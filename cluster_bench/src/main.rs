use anyhow::{anyhow, Context};
use clap::Parser;
use futures::StreamExt;
use hdrhistogram::Histogram;
use loam_sdk::{Policy, TokioSleeper};
use loam_sdk_networking::rpc::LoadBalancerService;
use reqwest::Certificate;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn, Level};

use loam_mvp::client_auth::{
    creation::create_token, new_google_secret_manager, tenant_secret_name, AuthKey, Claims,
};
use loam_mvp::google_auth;
use loam_mvp::http_client;
use loam_mvp::logging;
use loam_mvp::secret_manager::{BulkLoad, SecretManager, SecretVersion, SecretsFile};
use loam_sdk::{Configuration, Pin, PinHashingMode, UserSecret};

type Client = loam_sdk::Client<TokioSleeper, http_client::Client<LoadBalancerService>>;

/// Run many concurrent clients in a single process to benchmark the
/// performance of a Juicebox cluster.
#[derive(Parser)]
struct Args {
    /// Number of clients to run at a time.
    #[arg(long, value_name = "N", default_value_t = 3)]
    concurrency: usize,

    /// The SDK client configuration information, as a JSON string.
    #[arg(long, value_name = "JSON")]
    configuration: String,

    /// Number of each operation to do.
    #[arg(long, value_name = "N", default_value_t = 100)]
    count: usize,

    /// Name of a Google Cloud project.
    ///
    /// Used for accessing Secret Manager if `--secrets-file` is not given.
    #[arg(long, value_name = "NAME", required_unless_present("secrets_file"))]
    gcp_project: Option<String>,

    /// Name of JSON file containing per-tenant keys for authentication.
    ///
    /// The default is to fetch keys from Google Secret Manager (see
    /// `--gcp-project`).
    #[arg(long, value_name = "FILE", required_unless_present("gcp_project"))]
    secrets_file: Option<PathBuf>,

    /// Name of tenant to generate auth tokens for. Must start with "test-".
    #[arg(long, value_name = "NAME", default_value = "test-acme")]
    tenant: String,

    /// DER file containing self-signed certificate for connecting to the load
    /// balancers over TLS. May be given more than once.
    #[arg(long = "tls-certificate", value_name = "PATH")]
    tls_certificates: Vec<PathBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
    logging::configure_with_options(logging::Options {
        process_name: String::from("cluster_bench"),
        default_log_level: Level::INFO,
    });

    let args = Args::parse();
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:?}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
    let mut configuration: Configuration =
        serde_json::from_str(&args.configuration).context("failed to parse configuration")?;
    if configuration.pin_hashing_mode != PinHashingMode::FastInsecure {
        warn!(
            was = ?configuration.pin_hashing_mode,
            "overriding configuration's pin hashing mode to FastInsecure"
        );
        configuration.pin_hashing_mode = PinHashingMode::FastInsecure;
    }

    let (auth_key, auth_key_version) =
        get_auth_key(&args.tenant, &args.secrets_file, &args.gcp_project)
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

    let client_builder = Arc::new(ClientBuilder {
        certs,
        configuration,
        tenant: args.tenant,
        auth_key,
        auth_key_version,
    });

    info!("running test register");
    client_builder
        .build(String::from("mario0"))
        .register(
            &Pin::from(b"pin0".to_vec()),
            &UserSecret::from(b"secret0".to_vec()),
            Policy { num_guesses: 2 },
        )
        .await
        .unwrap();

    benchmark(
        Operation::Register,
        args.concurrency,
        args.count,
        &client_builder,
    )
    .await;

    benchmark(
        Operation::Recover,
        args.concurrency,
        args.count,
        &client_builder,
    )
    .await;

    benchmark(
        Operation::Delete,
        args.concurrency,
        args.count,
        &client_builder,
    )
    .await;

    logging::flush();
    info!(pid = std::process::id(), "exiting");

    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Operation {
    Register,
    Recover,
    Delete,
}

async fn benchmark(
    op: Operation,
    concurrency: usize,
    count: usize,
    client_builder: &Arc<ClientBuilder>,
) {
    info!(?op, concurrency, count, "benchmarking concurrent clients");
    let start = Instant::now();

    let mut stream =
        futures::stream::iter((0..count).map(|i| run_op(op, i, client_builder.clone())))
            .buffer_unordered(concurrency);

    let mut durations_ns: Histogram<u64> = Histogram::new(1).unwrap();
    let mut errors: usize = 0;
    while let Some(result) = stream.next().await {
        match result {
            Ok(duration) => {
                durations_ns
                    .record(duration.as_nanos().try_into().unwrap())
                    .unwrap();
            }
            Err(()) => {
                errors += 1;
            }
        }
    }

    let elapsed_s = start.elapsed().as_secs_f64();

    info!(
        ?op,
        count,
        concurrency,
        elapsed = format!("{:0.3} s", elapsed_s),
        throughput = format!("{:0.3} op/s", count as f64 / elapsed_s),
        min = format!("{:0.3} ms", durations_ns.min() as f64 / 1e6),
        mean = format!("{:0.3} ms", durations_ns.mean() / 1e6),
        p50 = format!(
            "{:0.3} ms",
            durations_ns.value_at_quantile(0.50) as f64 / 1e6
        ),
        p95 = format!(
            "{:0.3} ms",
            durations_ns.value_at_quantile(0.95) as f64 / 1e6
        ),
        p99 = format!(
            "{:0.3} ms",
            durations_ns.value_at_quantile(0.99) as f64 / 1e6
        ),
        max = format!("{:0.3} ms", durations_ns.max() as f64 / 1e6),
        "completed benchmark"
    );
    if errors > 0 {
        error!(errors, "client(s) reported errors");
    }
}

async fn run_op(
    op: Operation,
    i: usize,
    client_builder: Arc<ClientBuilder>,
) -> Result<Duration, ()> {
    let start = Instant::now();
    // Each operation creates a fresh client so that it cannot reuse TCP, HTTP,
    // TLS, or Noise connections, which would be cheating.
    let client = client_builder.build(format!("mario{i}"));
    match op {
        Operation::Register => match client
            .register(
                &Pin::from(format!("pin{i}").into_bytes()),
                &UserSecret::from(format!("secret{i}").into_bytes()),
                Policy { num_guesses: 2 },
            )
            .await
        {
            Ok(_) => Ok(start.elapsed()),
            Err(err) => {
                debug!(?op, ?err, i, "client got error");
                Err(())
            }
        },

        Operation::Recover => match client
            .recover(&Pin::from(format!("pin{i}").into_bytes()))
            .await
        {
            Ok(_) => Ok(start.elapsed()),
            Err(err) => {
                debug!(?op, ?err, i, "client got error");
                Err(())
            }
        },

        Operation::Delete => match client.delete().await {
            Ok(_) => Ok(start.elapsed()),
            Err(err) => {
                debug!(?op, ?err, i, "client got error");
                Err(())
            }
        },
    }
}

struct ClientBuilder {
    certs: Vec<Certificate>,
    configuration: Configuration,
    tenant: String,
    auth_key_version: SecretVersion,
    auth_key: AuthKey,
}

impl ClientBuilder {
    fn build(&self, user_id: String) -> Client {
        let auth_token = create_token(
            &Claims {
                issuer: self.tenant.clone(),
                subject: user_id,
            },
            &self.auth_key,
            self.auth_key_version,
        );

        Client::with_tokio(
            self.configuration.clone(),
            vec![],
            auth_token,
            http_client::Client::new(http_client::ClientOptions {
                additional_root_certs: self.certs.clone(),
            }),
        )
    }
}

async fn get_auth_key(
    tenant: &str,
    secrets_file: &Option<PathBuf>,
    gcp_project: &Option<String>,
) -> anyhow::Result<(AuthKey, SecretVersion)> {
    if !tenant.starts_with("test-") {
        return Err(anyhow!("tenant must start with 'test-'"));
    }

    let secret_manager: Box<dyn SecretManager> = match &secrets_file {
        Some(secrets_file) => {
            info!(path = ?secrets_file, "loading secrets from JSON file");
            Box::new(
                SecretsFile::new(secrets_file.clone())
                    .load_all()
                    .await
                    .context("failed to load secrets from JSON file")?,
            )
        }

        None => {
            info!("connecting to Google Cloud Secret Manager");
            let auth_manager = google_auth::from_adc()
                .await
                .context("failed to initialize Google Cloud auth")?;
            Box::new(
                new_google_secret_manager(
                    gcp_project.as_ref().expect("need --gcp-project"),
                    auth_manager,
                    Duration::MAX,
                )
                .await
                .context("failed to load secrets from Google Secret Manager")?,
            )
        }
    };

    let (version, secret) = secret_manager
        .get_secrets(&tenant_secret_name(tenant))
        .await
        .context("could not get secrets for tenant")?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("could not find any secret versions for tenant"))?;
    Ok((AuthKey::from(secret), version))
}
