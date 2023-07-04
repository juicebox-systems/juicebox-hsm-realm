use ::reqwest::Certificate;
use anyhow::{anyhow, Context};
use clap::{Parser, ValueEnum};
use dogstatsd::{ServiceCheckOptions, ServiceStatus};
use futures::StreamExt;
use hdrhistogram::Histogram;
use std::collections::HashMap;
use std::fs;
use std::ops::Range;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn, Level};

use juicebox_hsm::logging;
use juicebox_hsm::metrics_tag as tag;
use juicebox_hsm::secret_manager::{
    new_google_secret_manager, tenant_secret_name, BulkLoad, SecretManager, SecretsFile,
};
use juicebox_hsm::{google_auth, metrics};
use juicebox_sdk::{
    AuthToken, Configuration, Pin, PinHashingMode, Policy, RealmId, RecoverError, TokioSleeper,
    UserInfo, UserSecret,
};
use juicebox_sdk_networking::reqwest;
use juicebox_sdk_networking::rpc::LoadBalancerService;
use juicebox_sdk_realm_auth::{creation::create_token, AuthKey, AuthKeyVersion, Claims};

type Client = juicebox_sdk::Client<
    TokioSleeper,
    reqwest::Client<LoadBalancerService>,
    HashMap<RealmId, AuthToken>,
>;

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
    count: u64,

    /// Name of a Google Cloud project.
    ///
    /// Used for accessing Secret Manager if `--secrets-file` is not given.
    #[arg(long, value_name = "NAME", required_unless_present("secrets_file"))]
    gcp_project: Option<String>,

    /// Share an HTTP(S) connection pool across all concurrent clients.
    #[arg(long = "conn-pool")]
    share_http_connections: bool,

    /// List of operations to benchmark. Pass multiple times or use a
    /// comma-separated list.
    #[arg(
        long,
        value_enum,
        value_delimiter(','),
        value_name = "OP",
        default_value = "register,recover,delete"
    )]
    plan: Vec<Operation>,

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

    /// The string that all generated usernames begin with.
    ///
    /// A number is concatenated to the end of this to form the username.
    #[arg(long, value_name = "NAME", default_value = "mario")]
    user_prefix: String,

    /// The starting number after the prefix in the generated usernames.
    ///
    /// The numbers will go from `start` up to `start + count`.
    #[arg(long, value_name = "N", default_value_t = 0)]
    user_start: u64,

    /// Emit a service check event to datadog on completion.
    #[arg(long, default_value_t = false)]
    service_check: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    logging::configure_with_options(logging::Options {
        process_name: String::from("cluster_bench"),
        default_log_level: Level::INFO,
    });

    let args = Args::parse();
    let service_check = args.service_check;

    let res = run(args).await;
    if service_check {
        report_service_check(&res);
    }
    match res {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:?}");
            ExitCode::FAILURE
        }
    }
}

// returns the number of benchmark operation errors encountered
async fn run(args: Args) -> anyhow::Result<usize> {
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

    let shared_http_client = if args.share_http_connections {
        Some(reqwest::Client::new(reqwest::ClientOptions {
            additional_root_certs: certs.clone(),
        }))
    } else {
        None
    };

    let client_builder = Arc::new(ClientBuilder {
        shared_http_client,
        certs,
        configuration,
        tenant: args.tenant,
        auth_key,
        auth_key_version,
        user_prefix: args.user_prefix,
    });

    info!("running test register");
    client_builder
        .build(args.user_start)
        .register(
            &Pin::from(b"pin0".to_vec()),
            &UserSecret::from(b"secret0".to_vec()),
            &UserInfo::from(b"info0".to_vec()),
            Policy { num_guesses: 2 },
        )
        .await
        .unwrap();

    let mut total_errors = 0;
    for op in args.plan {
        total_errors += benchmark(
            op,
            args.concurrency,
            Range {
                start: args.user_start,
                end: args
                    .user_start
                    .checked_add(args.count)
                    .expect("user ID overflow"),
            },
            &client_builder,
        )
        .await;
    }

    logging::flush();
    info!(pid = std::process::id(), "exiting");

    Ok(total_errors)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Operation {
    Register,
    /// Must follow register to succeed.
    Recover,
    Delete,
    /// Recover with an invalid auth token. Hits the load balancer only.
    AuthError,
}

// returns the number of errors encountered
async fn benchmark(
    op: Operation,
    concurrency: usize,
    ids: Range<u64>,
    client_builder: &Arc<ClientBuilder>,
) -> usize {
    info!(?op, concurrency, ?ids, "benchmarking concurrent clients");
    let start = Instant::now();

    let mut stream =
        futures::stream::iter(ids.clone().map(|i| run_op(op, i, client_builder.clone())))
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

    let count = ids.end.saturating_sub(ids.start);
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
    errors
}

async fn run_op(op: Operation, i: u64, client_builder: Arc<ClientBuilder>) -> Result<Duration, ()> {
    let start = Instant::now();

    // Each operation creates a fresh client so that it cannot reuse Noise
    // connections, which would be cheating. If `args.share_http_connections`
    // is set, the clients will share TCP, HTTP, and TLS connections, which is
    // also cheating with respect to network behavior and load balancer load.
    let client = if op == Operation::AuthError {
        client_builder.build_with_auth_key(
            i,
            &AuthKey::from(b"invalid".to_vec()),
            AuthKeyVersion(1),
        )
    } else {
        client_builder.build(i)
    };

    match op {
        Operation::Register => match client
            .register(
                &Pin::from(format!("pin{i}").into_bytes()),
                &UserSecret::from(format!("secret{i}").into_bytes()),
                &UserInfo::from(format!("info{i}").into_bytes()),
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
            .recover(
                &Pin::from(format!("pin{i}").into_bytes()),
                &UserInfo::from(format!("info{i}").into_bytes()),
            )
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

        Operation::AuthError => match client
            .recover(
                &Pin::from(b"bogus".to_vec()),
                &UserInfo::from(b"bogus".to_vec()),
            )
            .await
        {
            Err(RecoverError::InvalidAuth) => Ok(start.elapsed()),
            Ok(_) => {
                debug!(?op, i, "client got unexpected success");
                Err(())
            }
            Err(err) => {
                debug!(?op, ?err, i, "client got error");
                Err(())
            }
        },
    }
}

struct ClientBuilder {
    shared_http_client: Option<reqwest::Client<LoadBalancerService>>,
    certs: Vec<Certificate>,
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
            .http(match &self.shared_http_client {
                Some(client) => client.clone(),
                None => reqwest::Client::new(reqwest::ClientOptions {
                    additional_root_certs: self.certs.clone(),
                }),
            })
            .tokio_sleeper()
            .build()
    }
}

async fn get_auth_key(
    tenant: &str,
    secrets_file: &Option<PathBuf>,
    gcp_project: &Option<String>,
) -> anyhow::Result<(AuthKey, AuthKeyVersion)> {
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
    Ok((secret.into(), version.into()))
}

fn report_service_check(r: &anyhow::Result<usize>) {
    let c = metrics::Client::new("cluster_bench");
    const STAT: &str = "healthcheck.register_recover";
    match r {
        Ok(0) => c.service_check(STAT, ServiceStatus::OK, metrics::NO_TAGS, None),
        Ok(err_count) => c.service_check(STAT, ServiceStatus::Critical, [tag!(err_count)], None),
        Err(err) => {
            // this is dumb, thanks dogstatsd
            let msg: &'static str = Box::leak(format!("{:?}", err).into_boxed_str());
            c.service_check(
                STAT,
                ServiceStatus::Warning,
                metrics::NO_TAGS,
                Some(ServiceCheckOptions {
                    message: Some(msg),
                    ..ServiceCheckOptions::default()
                }),
            )
        }
    };
}
