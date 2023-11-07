use ::reqwest::Certificate;
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use clap::Parser;
use dogstatsd::{ServiceCheckOptions, ServiceStatus};
use futures::StreamExt;
use opentelemetry::sdk::trace::Sampler;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, warn};

use juicebox_networking::rpc::LoadBalancerService;
use juicebox_networking::{http, reqwest};
use juicebox_realm_auth::creation::create_token;
use juicebox_realm_auth::{AuthKey, AuthKeyVersion, Claims, Scope};
use juicebox_sdk::{
    AuthToken, Configuration, DeleteError, Pin, PinHashingMode, Policy, RealmId, RecoverError,
    RegisterError, TokioSleeper, UserInfo, UserSecret, JUICEBOX_VERSION_HEADER, VERSION,
};
use observability::metrics_tag as tag;
use observability::{logging, metrics};
use secret_manager::{tenant_secret_name, BulkLoad, SecretManager, SecretsFile};
use service_core::clap_parsers::parse_duration;

type Client = juicebox_sdk::Client<TokioSleeper, HttpReporter, HashMap<RealmId, AuthToken>>;

/// Runs a number of register/recover/delete requests and reports
/// success/failure via a Datadog health check.
#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Number of clients to run at a time.
    #[arg(long, value_name = "N", default_value_t = 1)]
    concurrency: usize,

    /// The SDK client configuration information, as a JSON string.
    #[arg(long, value_name = "JSON")]
    configuration: String,

    /// Number of each operation to do.
    #[arg(long, value_name = "N", default_value_t = 5)]
    count: u64,

    /// Name of JSON file containing per-tenant keys for authentication.
    #[arg(long, value_name = "FILE")]
    secrets_file: PathBuf,

    /// Name of tenant to generate auth tokens for. Must start with "test-".
    #[arg(long, value_name = "NAME", default_value = "test-juiceboxmonitor")]
    tenant: String,

    /// Prefix of the user name to generate auth tokens for.
    #[arg(long, default_value = "Mario")]
    user: String,

    /// DER file containing self-signed certificate for connecting to the load
    /// balancers over TLS. May be given more than once.
    #[arg(long = "tls-certificate", value_name = "PATH")]
    tls_certificates: Vec<PathBuf>,

    /// Name of the environment to include in the service check report to Datadog.
    #[arg(long, default_value = "dev")]
    env: String,

    /// Amount of time to allow for the entire service check operation to run before declaring a failure. in milliseconds.
    #[arg(long, default_value="10000", value_parser=parse_duration)]
    timeout: Duration,

    /// Timeout setting for http requests. in milliseconds
    #[arg(long, default_value="5000", value_parser=parse_duration)]
    http_timeout: Duration,

    /// Continuously run the service check in a loop
    #[arg(long, default_value_t = false)]
    forever: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    logging::configure_with_options(logging::Options {
        process_name: String::from("service_checker"),
        additional_tags: HashMap::from([(String::from("env"), args.env.clone())]),
        trace_sampler: Sampler::AlwaysOn,
        ..logging::Options::default()
    });

    info!(?args.tenant, ?args.user, "Starting service checker");
    let checker = match Checker::new(&args).await {
        Ok(c) => c,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut res;
    loop {
        res = match timeout(args.timeout, checker.run(&args)).await {
            Ok(res) => res,
            Err(_) => Err(anyhow!(
                "timed out waiting for register/recover to complete"
            )),
        };
        report_service_check(&res, &args.env);
        if !args.forever {
            break;
        }
    }

    info!(pid = std::process::id(), "exiting");
    logging::flush();

    match res {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

struct Checker {
    configuration: Configuration,
    auth_key: AuthKey,
    auth_key_version: AuthKeyVersion,
    certs: Vec<Certificate>,
}

impl Checker {
    async fn new(args: &Args) -> anyhow::Result<Self> {
        let mut configuration = Configuration::from_json(&args.configuration)
            .context("failed to parse configuration")?;
        if configuration.pin_hashing_mode != PinHashingMode::FastInsecure {
            warn!(
                was = ?configuration.pin_hashing_mode,
                "overriding configuration's pin hashing mode to FastInsecure"
            );
            configuration.pin_hashing_mode = PinHashingMode::FastInsecure;
        }

        let (auth_key, auth_key_version) = get_auth_key(&args.tenant, &args.secrets_file)
            .await
            .with_context(|| format!("failed to get auth key for tenant {:?}", args.tenant))?;

        let certs: Vec<Certificate> = args
            .tls_certificates
            .iter()
            .map(|path| {
                let file = fs::read(path)
                    .with_context(|| format!("failed to read TLS certificate at {path:?}"))?;
                Certificate::from_der(&file)
                    .with_context(|| format!("failed to decode TLS certificate at {path:?}"))
            })
            .collect::<anyhow::Result<_>>()?;

        Ok(Checker {
            configuration,
            auth_key,
            auth_key_version,
            certs,
        })
    }

    #[instrument(level = "trace", skip(self))]
    async fn run(&self, args: &Args) -> anyhow::Result<()> {
        let http_client = HttpReporter::new(reqwest::Client::<LoadBalancerService>::new(
            reqwest::ClientOptions {
                additional_root_certs: self.certs.clone(),
                timeout: args.http_timeout,
                default_headers: HashMap::from([(JUICEBOX_VERSION_HEADER, VERSION)]),
            },
        ));

        let client_builder = Arc::new(ClientBuilder {
            shared_http_client: http_client,
            configuration: self.configuration.clone(),
            tenant: args.tenant.clone(),
            auth_key: self.auth_key.clone(),
            auth_key_version: self.auth_key_version,
            user_prefix: args.user.clone(),
        });

        let mut stream =
            futures::stream::iter((1..=args.count).map(|i| run_op(i, client_builder.clone())))
                .buffer_unordered(args.concurrency);

        let mut last_error: Option<OpError> = None;
        while let Some(result) = stream.next().await {
            match result {
                Ok(_) => {}
                Err(err) => {
                    warn!(%err, "error during register/recover operation");
                    last_error = Some(err);
                }
            }
        }
        match last_error {
            Some(err) => Err(err.into()),
            None => Ok(()),
        }
    }
}

#[instrument(level = "trace", skip(client_builder))]
async fn run_op(user_num: u64, client_builder: Arc<ClientBuilder>) -> Result<(), OpError> {
    let start = Instant::now();
    let client = client_builder.build(user_num);
    let pin = Pin::from(format!("thepin{user_num}").into_bytes());
    let info = UserInfo::from(format!("user_info{user_num}").into_bytes());
    let secret = UserSecret::from(format!("its secret{user_num}").into_bytes());

    client
        .register(&pin, &secret, &info, Policy { num_guesses: 2 })
        .await?;

    let s = client.recover(&pin, &info).await?;
    if !s.expose_secret().eq(secret.expose_secret()) {
        return Err(OpError::RecoveredIncorrectSecret);
    }
    client.delete().await?;
    debug!(
        pid = std::process::id(),
        ?user_num,
        elapsed = ?start.elapsed(),
        "completed register/recover/delete for user"
    );
    Ok(())
}

#[derive(Debug, Error)]
enum OpError {
    #[error("register failed: {0:?}")]
    Register(#[from] RegisterError),
    #[error("recover failed: {0:?}")]
    Recover(#[from] RecoverError),
    #[error("recover returned a different secret to the one registered")]
    RecoveredIncorrectSecret,
    #[error("delete failed: {0:?}")]
    Delete(#[from] DeleteError),
}

struct ClientBuilder {
    shared_http_client: HttpReporter,
    configuration: Configuration,
    tenant: String,
    auth_key_version: AuthKeyVersion,
    auth_key: AuthKey,
    user_prefix: String,
}

impl ClientBuilder {
    fn build(&self, user_num: u64) -> Client {
        self.build_with_auth_key(user_num, &self.auth_key, self.auth_key_version)
    }

    fn build_with_auth_key(
        &self,
        user_num: u64,
        auth_key: &AuthKey,
        auth_key_version: AuthKeyVersion,
    ) -> Client {
        let auth_tokens: HashMap<RealmId, AuthToken> = self
            .configuration
            .realms
            .iter()
            .map(|realm| {
                (
                    realm.id,
                    create_token(
                        &Claims {
                            issuer: self.tenant.clone(),
                            subject: format!("{}{}", self.user_prefix, user_num),
                            audience: realm.id,
                            scope: Some(Scope::User),
                        },
                        auth_key,
                        auth_key_version,
                    ),
                )
            })
            .collect();

        juicebox_sdk::ClientBuilder::new()
            .configuration(self.configuration.clone())
            .auth_token_manager(auth_tokens)
            .tokio_sleeper()
            .http(self.shared_http_client.clone())
            .build()
    }
}

async fn get_auth_key(
    tenant: &str,
    secrets_file: &PathBuf,
) -> anyhow::Result<(AuthKey, AuthKeyVersion)> {
    if !tenant.starts_with("test-") {
        return Err(anyhow!("tenant must start with 'test-'"));
    }

    info!(path = ?secrets_file, "loading secrets from JSON file");
    let secret_manager = SecretsFile::new(secrets_file.clone())
        .load_all()
        .await
        .context("failed to load secrets from JSON file")?;

    let (version, secret) = secret_manager
        .get_secrets(&tenant_secret_name(tenant))
        .await
        .context("could not get secrets for tenant")?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("could not find any secret versions for tenant"))?;
    Ok((secret.into(), version.into()))
}

fn report_service_check(r: &anyhow::Result<()>, env: &str) {
    let c = metrics::Client::new("service_checker");
    const STAT: &str = "healthcheck.register_recover";

    match r {
        Ok(()) => c.service_check(STAT, ServiceStatus::OK, [tag!(env)], None),
        Err(err) => {
            // this is dumb, thanks dogstatsd
            let msg: &'static str = Box::leak(format!("{:?}", err).into_boxed_str());
            c.service_check(
                STAT,
                ServiceStatus::Critical,
                [tag!(env)],
                Some(ServiceCheckOptions {
                    message: Some(msg),
                    ..ServiceCheckOptions::default()
                }),
            )
        }
    }
}

struct HttpReporter {
    client: reqwest::Client<LoadBalancerService>,
    // count of requests made by this specific instance
    count: AtomicUsize,
}

impl HttpReporter {
    fn new(client: reqwest::Client<LoadBalancerService>) -> Self {
        Self {
            client,
            count: AtomicUsize::new(0),
        }
    }
}
impl Clone for HttpReporter {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            count: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl http::Client for HttpReporter {
    async fn send(&self, mut request: http::Request) -> Option<http::Response> {
        let start = Instant::now();
        let count = self.count.fetch_add(1, Ordering::Relaxed);
        // Ask Cloudfront to return a server-timing response header with details
        // about this request.
        // see https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/understanding-response-headers-policies.html#server-timing-header
        request
            .headers
            .insert(String::from("pragma"), String::from("server-timing"));
        let result = self.client.send(request).await;
        let elapsed = start.elapsed();
        let mut cdn: Option<CdnInfo> = None;
        if let Some(r) = &result {
            if r.status_code != 200 {
                warn!(
                    prev_request_count=%count,
                    status_code = %r.status_code,
                    body = std::str::from_utf8(&r.body).unwrap_or("response body not UTF8"),
                    "http request returned unexpected status code"
                )
            }
            if let Some(timings) = r.headers.get("server-timing") {
                cdn = parse_cloudfront_server_timings(timings);
            } else if let Some(ray) = r.headers.get("cf-ray") {
                cdn = Some(CdnInfo::CloudFlare { ray: ray.clone() })
            }
        }
        if elapsed > Duration::from_secs(1) {
            warn!(?elapsed, prev_request_count=%count, ?cdn, "slow http request")
        }
        result
    }
}

fn parse_cloudfront_server_timings(v: &str) -> Option<CdnInfo> {
    // e.g. cdn-upstream-layer;desc="EDGE",cdn-upstream-dns;dur=0,cdn-upstream-connect;dur=60,cdn-upstream-fbl;dur=120,
    // cdn-cache-miss,cdn-pop;desc="SFO53-P5",cdn-rid;desc="s9h8qRzwLylq5TYQCeWUjop5TMZUXb3UDezTW-nPb0DCFv5nWb9enQ==",
    // cdn-downstream-fbl;dur=120
    fn value_of<'a>(v: &'a str, field: &str) -> Option<&'a str> {
        if let Some((fname, fval)) = v.split_once('=') {
            if fname == field {
                return Some(fval.trim_matches('"'));
            }
        }
        None
    }
    fn duration_of(v: &str) -> Option<Duration> {
        match value_of(v, "dur") {
            None => None,
            Some(d) => d.parse().ok().map(Duration::from_millis),
        }
    }
    let mut r = CloudFrontServerTimings::default();
    for item in v.split(',') {
        if let Some((key, value)) = item.split_once(';') {
            match key {
                "cdn-pop" => r.pop = value_of(value, "desc").map(str::to_string),
                "cdn-rid" => r.rid = value_of(value, "desc").map(str::to_string),
                "cdn-upstream-dns" => r.upstream_dns = duration_of(value),
                "cdn-upstream-connect" => r.upstream_connect = duration_of(value),
                "cdn-upstream-fbl" => r.upstream_first_byte = duration_of(value),
                "cdn-downstream-fbl" => r.downstream_first_byte = duration_of(value),
                _ => {}
            }
        }
    }
    if r.pop.is_some()
        || r.rid.is_some()
        || r.upstream_dns.is_some()
        || r.upstream_connect.is_some()
        || r.upstream_first_byte.is_some()
        || r.downstream_first_byte.is_some()
    {
        Some(CdnInfo::CloudFront(r))
    } else {
        None
    }
}

#[derive(Debug, Eq, PartialEq)]
// dead_code analysis ignores the Default impl, which is how the ray field gets used.
#[allow(dead_code)]
enum CdnInfo {
    CloudFlare { ray: String },
    CloudFront(CloudFrontServerTimings),
}

#[derive(Default, Debug, Eq, PartialEq)]
struct CloudFrontServerTimings {
    // The name of the CloudFront point of presence that handled the request.
    pop: Option<String>,
    // The CloudFront unique identifier for the request. You can use this
    // request identifier (RID) when troubleshooting issues with AWS Support
    rid: Option<String>,
    // The time that was spent retrieving the DNS record for the origin. May be
    // 0 if cached.
    upstream_dns: Option<Duration>,
    // The time between when the origin DNS request completed and a TCP (and
    // TLS, if applicable) connection to the origin completed. May be 0 if
    // reusing an existing connection.
    upstream_connect: Option<Duration>,
    // The time between when the origin HTTP request is completed and when the
    // first byte is received in the response from the origin (first byte
    // latency).
    upstream_first_byte: Option<Duration>,
    // The time between when the edge location finished receiving the request
    // and when it sent the first byte of the response to the viewer.
    downstream_first_byte: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use expect_test::expect_file;

    #[test]
    fn test_usage() {
        expect_file!["../usage.txt"].assert_eq(
            &Args::command()
                .try_get_matches_from(["service_checker", "--help"])
                .unwrap_err()
                .to_string(),
        );
    }

    #[test]
    fn test_cloudfront_parser() {
        let res = parse_cloudfront_server_timings("cdn-upstream-layer;desc=\"EDGE\",cdn-upstream-dns;dur=0,cdn-upstream-connect;dur=60,cdn-upstream-fbl;dur=120,\
        cdn-cache-miss,cdn-pop;desc=\"SFO53-P5\",cdn-rid;desc=\"s9h8qRzwLylq5TYQCeWUjop5TMZUXb3UDezTW-nPb0DCFv5nWb9enQ==\",\
        cdn-downstream-fbl;dur=125");
        assert_eq!(
            Some(CdnInfo::CloudFront(CloudFrontServerTimings {
                pop: Some(String::from("SFO53-P5")),
                rid: Some(String::from(
                    "s9h8qRzwLylq5TYQCeWUjop5TMZUXb3UDezTW-nPb0DCFv5nWb9enQ=="
                )),
                upstream_dns: Some(Duration::from_millis(0)),
                upstream_connect: Some(Duration::from_millis(60)),
                upstream_first_byte: Some(Duration::from_millis(120)),
                downstream_first_byte: Some(Duration::from_millis(125)),
            })),
            res
        );
    }
}
