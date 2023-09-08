use ::reqwest::Certificate;
use anyhow::{anyhow, Context};
use clap::Parser;
use dogstatsd::{ServiceCheckOptions, ServiceStatus};
use futures::StreamExt;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn, Level};

use juicebox_networking::reqwest;
use juicebox_networking::rpc::LoadBalancerService;
use juicebox_realm_auth::{creation::create_token, AuthKey, AuthKeyVersion, Claims};
use juicebox_sdk::{
    AuthToken, Configuration, Pin, PinHashingMode, Policy, RealmId, RecoverError, RegisterError,
    TokioSleeper, UserInfo, UserSecret, JUICEBOX_VERSION_HEADER, VERSION,
};
use observability::metrics_tag as tag;
use observability::{logging, metrics};
use secret_manager::{tenant_secret_name, BulkLoad, SecretManager, SecretsFile};
use service_core::clap_parsers::parse_duration;

type Client = juicebox_sdk::Client<
    TokioSleeper,
    reqwest::Client<LoadBalancerService>,
    HashMap<RealmId, AuthToken>,
>;

/// Runs a number of register/recover requests and reports success/failure via a
/// Datadog health check.
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
    #[arg(long, value_name = "NAME", default_value = "test-acme")]
    tenant: String,

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
}

#[tokio::main]
async fn main() -> ExitCode {
    logging::configure_with_options(logging::Options {
        process_name: String::from("service_checker"),
        default_log_level: Level::INFO,
    });

    let args = Args::parse();
    let res = match timeout(args.timeout, run(&args)).await {
        Ok(res) => res,
        Err(_) => Err(anyhow!(
            "timed out waiting for register/recover to complete"
        )),
    };
    report_service_check(&res, &args.env);

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

async fn run(args: &Args) -> anyhow::Result<()> {
    let mut configuration: Configuration =
        serde_json::from_str(&args.configuration).context("failed to parse configuration")?;
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

    let http_client = reqwest::Client::new(reqwest::ClientOptions {
        additional_root_certs: certs.clone(),
        timeout: args.http_timeout,
        default_headers: HashMap::from([(JUICEBOX_VERSION_HEADER, VERSION)]),
    });

    let client_builder = Arc::new(ClientBuilder {
        shared_http_client: http_client,
        configuration,
        tenant: args.tenant.clone(),
        auth_key,
        auth_key_version,
        user_prefix: String::from("Mario"),
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

async fn run_op(user_num: u64, client_builder: Arc<ClientBuilder>) -> Result<(), OpError> {
    trace!(?user_num, "starting register/recover");
    let client = client_builder.build(user_num);
    let pin = Pin::from(b"thepin".to_vec());
    let info = UserInfo::from(b"user_info".to_vec());
    let secret = UserSecret::from(b"its secret".to_vec());

    client
        .register(&pin, &secret, &info, Policy { num_guesses: 2 })
        .await?;

    let s = client.recover(&pin, &info).await?;
    if s.expose_secret().eq(secret.expose_secret()) {
        debug!(?user_num, "recovered correct secret for user");
        Ok(())
    } else {
        Err(OpError::RecoveredIncorrectSecret)
    }
}

#[derive(Debug, Error)]
enum OpError {
    #[error("register failed: {0:?}")]
    Register(RegisterError),
    #[error("recover failed: {0:?}")]
    Recover(RecoverError),
    #[error("recover returned a different secret to the one registered")]
    RecoveredIncorrectSecret,
}

impl From<RegisterError> for OpError {
    fn from(value: RegisterError) -> Self {
        OpError::Register(value)
    }
}

impl From<RecoverError> for OpError {
    fn from(value: RecoverError) -> Self {
        OpError::Recover(value)
    }
}

struct ClientBuilder {
    shared_http_client: reqwest::Client<LoadBalancerService>,
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
