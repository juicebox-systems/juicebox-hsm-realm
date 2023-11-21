use anyhow::{anyhow, Context};
use async_trait::async_trait;
use clap::Parser;
use dogstatsd::{ServiceCheckOptions, ServiceStatus};
use futures::future::join_all;
use futures::StreamExt;
use opentelemetry::sdk::trace::Sampler;
use reqwest::tls::TlsInfo;
use reqwest::Certificate;
use service_core::http::ReqwestClientMetrics;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, warn};
use x509_cert::der::{Decode, SliceReader};

use juicebox_networking::{http, reqwest as jb_reqwest};
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
    let mc = metrics::Client::new_with_tags("service_checker", [tag!("env":"{}",args.env)]);

    let mut res;
    loop {
        res = match timeout(args.timeout, checker.run(mc.clone(), &args)).await {
            Ok(res) => res,
            Err(_) => Err(anyhow!("timed out waiting for service check to complete")),
        };
        report_service_check(&mc, &res);
        if let Err(err) = &res {
            error!(?err, "service check error");
        }
        if !args.forever {
            break;
        }
    }

    info!(pid = std::process::id(), "exiting");
    logging::flush();

    match res {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:?}");
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

    #[instrument(level = "trace", skip(self, mc))]
    async fn run(&self, mc: metrics::Client, args: &Args) -> anyhow::Result<()> {
        let http_client = HttpReporter::new(
            ReqwestClientMetrics::new(
                mc.clone(),
                jb_reqwest::ClientOptions {
                    additional_root_certs: self.certs.clone(),
                    timeout: args.http_timeout,
                    default_headers: HashMap::from([(JUICEBOX_VERSION_HEADER, VERSION)]),
                },
            ),
            mc.clone(),
        );

        let client_builder = Arc::new(ClientBuilder {
            shared_http_client: http_client.clone(),
            configuration: self.configuration.clone(),
            tenant: args.tenant.clone(),
            auth_key: self.auth_key.clone(),
            auth_key_version: self.auth_key_version,
            user_prefix: args.user.clone(),
        });

        let mut stream =
            futures::stream::iter((1..=args.count).map(|i| run_op(i, client_builder.clone())))
                .buffer_unordered(args.concurrency);

        let mut first_op_error: Option<OpError> = None;
        while let Some(result) = stream.next().await {
            match result {
                Ok(_) => {}
                Err(err) => {
                    warn!(%err, "error during register/recover operation");
                    first_op_error.get_or_insert(err);
                }
            }
        }

        // Check all the certificates without short-circuiting.
        let tls_cert_checks = join_all(self.configuration.realms.iter().map(|realm| {
            check_tls_cert_expiration(
                realm.address.as_str(),
                http_client.client.client.clone(),
                mc.clone(),
                args,
            )
        }))
        .await
        .into_iter()
        .collect::<anyhow::Result<()>>();

        match first_op_error {
            None => Ok(()),
            Some(err) => Err(err.into()),
        }
        .and(tls_cert_checks)
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

fn report_service_check(mc: &metrics::Client, r: &anyhow::Result<()>) {
    const STAT: &str = "healthcheck.register_recover";

    match r {
        Ok(()) => mc.service_check(STAT, ServiceStatus::OK, metrics::NO_TAGS, None),
        Err(err) => {
            // this is dumb, thanks dogstatsd
            let msg: &'static str = Box::leak(format!("{:?}", err).into_boxed_str());
            mc.service_check(
                STAT,
                ServiceStatus::Critical,
                metrics::NO_TAGS,
                Some(ServiceCheckOptions {
                    message: Some(msg),
                    ..ServiceCheckOptions::default()
                }),
            )
        }
    }
}

struct HttpReporter {
    client: ReqwestClientMetrics,
    // count of requests made by this specific instance
    count: AtomicUsize,
    metrics: metrics::Client,
}

impl HttpReporter {
    fn new(client: ReqwestClientMetrics, mc: metrics::Client) -> Self {
        Self {
            client,
            count: AtomicUsize::new(0),
            metrics: mc,
        }
    }
}

impl Clone for HttpReporter {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            count: AtomicUsize::new(0),
            metrics: self.metrics.clone(),
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
        let tag_url = tag!("url":"{}",request.url);
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
            let tag_status = tag!("status_code":"{}",r.status_code);
            if let Some(exec) = r.headers.get("x-exec-time") {
                if let Ok(nanos) = exec.parse() {
                    let nanos = Duration::from_nanos(nanos);
                    self.metrics.timing(
                        "service_checker.http_send.network_latency",
                        elapsed - nanos,
                        [&tag_url, &tag_status],
                    );
                    self.metrics.timing(
                        "service_checker.http_send.server_exec_time",
                        nanos,
                        [&tag_url, &tag_status],
                    );
                }
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
    if r != CloudFrontServerTimings::default() {
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

async fn check_tls_cert_expiration(
    url: &str,
    http_client: jb_reqwest::Client,
    metrics: metrics::Client,
    args: &Args,
) -> anyhow::Result<()> {
    let request = http_client.to_reqwest(http::Request {
        method: http::Method::Get,
        url: url.to_owned(),
        headers: HashMap::default(),
        body: None,
        timeout: Some(args.http_timeout),
    });

    let response = request
        .send()
        .await
        .with_context(|| format!("failed to issue HTTP request to get {url:?} TLS certificate"))?;

    let tls_info = response.extensions().get::<TlsInfo>().with_context(|| {
        format!("HTTP request to check {url:?} TLS certificate did not return TLS info")
    })?;
    let der = tls_info.peer_certificate().ok_or_else(|| {
        anyhow!("HTTP request to check {url:?} TLS certificate did not return certificate")
    })?;
    let cert = SliceReader::new(der)
        .and_then(|mut reader| x509_cert::Certificate::decode(&mut reader))
        .with_context(|| format!("failed to decode {url:?} TLS certificate"))?;

    let not_after = cert.tbs_certificate.validity.not_after;
    let remaining_duration = (UNIX_EPOCH + not_after.to_unix_duration())
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO);
    let remaining_days = remaining_duration.as_secs_f64() / 60.0 / 60.0 / 24.0;
    let remaining = format!("{:.1} days", remaining_days);

    if remaining_days > 30.0 {
        info!(url, remaining, %not_after, "server TLS certificate expiration OK");
    } else if remaining_days > 20.0 {
        warn!(url, remaining, %not_after, "server TLS certificate expires soon");
    } else {
        error!(url, remaining, %not_after, "server TLS certificate expires soon");
    }

    metrics.gauge(
        "service_checker.tls_cert.remaining_days",
        remaining_days,
        [tag!(url)],
    );

    if remaining_days > 15.0 {
        Ok(())
    } else {
        Err(anyhow!(
            "server TLS certificate for {url:?} expires in {remaining} (not_after={not_after})"
        ))
    }
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
