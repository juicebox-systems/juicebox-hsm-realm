use ::reqwest::Certificate;
use anyhow::{anyhow, Context};
use chrono::{DateTime, Local};
use clap::{Parser, ValueEnum};
use futures::StreamExt;
use hdrhistogram::Histogram;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::ops::Range;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tracing::{debug, error, info, warn};

use async_util::ScopedTask;
use google::{auth, GrpcConnectionOptions};
use juicebox_networking::reqwest;
use juicebox_realm_auth::creation::create_token;
use juicebox_realm_auth::{AuthKey, AuthKeyVersion, Claims, Scope};
use juicebox_sdk::{
    AuthToken, Configuration, Pin, PinHashingMode, Policy, RealmId, RecoverError, TokioSleeper,
    UserInfo, UserSecret, JUICEBOX_VERSION_HEADER, VERSION,
};
use observability::{logging, metrics};
use secret_manager::{
    new_google_secret_manager, tenant_secret_name, BulkLoad, SecretManager, SecretsFile,
};
use service_core::clap_parsers::parse_duration;

type Client = juicebox_sdk::Client<TokioSleeper, reqwest::Client, HashMap<RealmId, AuthToken>>;

const TIMEOUT: Duration = Duration::from_secs(5);

/// Run many concurrent clients in a single process to benchmark the
/// performance of a Juicebox cluster.
#[derive(Parser)]
#[command(version = build_info::clap!())]
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

    /// How often to report progress for longer running operations.
    #[arg(long, value_parser=parse_duration, default_value="10m")]
    reporting_interval: Duration,

    /// If set will write the results of the benchmark run to the specified file
    /// in json format. If the file already exists it'll be overwritten.
    #[arg(long, value_name = "OUT_FILE")]
    results_file: Option<PathBuf>,

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
}

#[tokio::main]
async fn main() -> ExitCode {
    logging::configure_with_options(logging::Options {
        process_name: String::from("cluster_bench"),
        build_info: Some(build_info::get!()),
        ..logging::Options::default()
    });

    let args = Args::parse();
    match run(args).await {
        Ok(_) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:?}");
            ExitCode::FAILURE
        }
    }
}

// returns the number of benchmark operation errors encountered
async fn run(args: Args) -> anyhow::Result<usize> {
    let mut configuration =
        Configuration::from_json(&args.configuration).context("failed to parse configuration")?;
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
            timeout: TIMEOUT,
            default_headers: HashMap::from([(JUICEBOX_VERSION_HEADER, VERSION)]),
        }))
    } else {
        None
    };

    let client_builder = Arc::new(ClientBuilder {
        shared_http_client,
        certs,
        configuration: configuration.clone(),
        tenant: args.tenant,
        auth_key,
        auth_key_version,
        user_prefix: args.user_prefix,
    });

    info!("running test register");
    let started_time = SystemTime::now();

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
    let mut results = Vec::new();
    for op in args.plan {
        let result = benchmark(
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
            args.reporting_interval,
        )
        .await;
        total_errors += result.errors;
        results.push(result);
    }

    logging::flush();
    if let Some(results_file) = args.results_file {
        let datetime: DateTime<Local> = started_time.into();
        let result = BenchmarkResult {
            configuration,
            started: format!("{}", datetime.format("%+")),
            elapsed_secs: started_time.elapsed().unwrap_or_default().as_secs_f64(),
            errors: total_errors,
            operations: results,
        };
        match File::create(results_file) {
            Ok(f) => {
                if let Err(e) = serde_json::to_writer_pretty(f, &result) {
                    eprintln!("failed to serialize results to json: {e:?}");
                }
            }
            Err(e) => {
                eprintln!("failed to create results file: {e:?}");
            }
        }
    }
    info!(pid = std::process::id(), "exiting");

    Ok(total_errors)
}

#[derive(Serialize)]
struct BenchmarkResult {
    configuration: Configuration,
    started: String,
    elapsed_secs: f64,
    errors: usize,
    operations: Vec<OperationResult>,
}

#[derive(Debug, Serialize)]
struct OperationResult {
    op: Operation,
    count: usize,
    concurrency: usize,
    errors: usize,
    elapsed_secs: f64,
    throughput: f64, //ops per sec
    min_ms: f64,
    mean_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
}

impl OperationResult {
    fn new(
        op: Operation,
        count: usize,
        concurrency: usize,
        errors: usize,
        elapsed: Duration,
        durations_ns: &Histogram<u64>,
    ) -> Self {
        OperationResult {
            op,
            count,
            concurrency,
            errors,
            elapsed_secs: elapsed.as_secs_f64(),
            throughput: count as f64 / elapsed.as_secs_f64(),
            min_ms: durations_ns.min() as f64 / 1e6,
            mean_ms: durations_ns.mean() / 1e6,
            p50_ms: durations_ns.value_at_quantile(0.50) as f64 / 1e6,
            p95_ms: durations_ns.value_at_quantile(0.95) as f64 / 1e6,
            p99_ms: durations_ns.value_at_quantile(0.99) as f64 / 1e6,
            max_ms: durations_ns.max() as f64 / 1e6,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
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
    report_interval: Duration,
) -> OperationResult {
    info!(?op, concurrency, ?ids, "benchmarking concurrent clients");
    let start = Instant::now();

    let report = |count: usize, durations_ns: &Histogram<u64>| {
        let r = OperationResult::new(op, count, concurrency, 0, start.elapsed(), durations_ns);
        info!(
            ?op,
            count,
            concurrency,
            elapsed = format!("{:0.3} s", r.elapsed_secs),
            throughput = format!("{:0.3} op/s", count as f64 / r.elapsed_secs),
            min = format!("{:0.3} ms", r.min_ms),
            mean = format!("{:0.3} ms", r.mean_ms),
            p50 = format!("{:0.3} ms", r.p50_ms),
            p95 = format!("{:0.3} ms", r.p95_ms),
            p99 = format!("{:0.3} ms", r.p99_ms),
            max = format!("{:0.3} ms", r.max_ms),
        );
    };

    let mut stream = futures::stream::iter(
        ids.clone()
            .map(|i| ScopedTask::spawn(run_op(op, i, client_builder.clone()))),
    )
    .buffer_unordered(concurrency);

    let mut last_reported = start;
    let mut durations_ns: Histogram<u64> = Histogram::new(1).unwrap();
    let mut errors: usize = 0;
    let mut count: usize = 0;
    while let Some(result) = stream.next().await {
        count += 1;
        match result {
            Ok(Ok(duration)) => {
                durations_ns
                    .record(duration.as_nanos().try_into().unwrap())
                    .unwrap();
            }
            Ok(Err(_)) | Err(_) => {
                errors += 1;
            }
        }
        if last_reported.elapsed() > report_interval {
            report(count, &durations_ns);
            last_reported = Instant::now();
        }
    }

    let res = OperationResult::new(
        op,
        count,
        concurrency,
        errors,
        start.elapsed(),
        &durations_ns,
    );
    info!("benchmark complete");
    report(count, &durations_ns);
    if errors > 0 {
        error!(errors, "client(s) reported errors");
    }
    res
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
    shared_http_client: Option<reqwest::Client>,
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
                            scope: Some(Scope::User),
                        },
                        auth_key,
                        auth_key_version,
                    ),
                )
            })
            .collect();

        let mut cb = juicebox_sdk::ClientBuilder::new()
            .configuration(self.configuration.clone())
            .auth_token_manager(auth_tokens)
            .tokio_sleeper();
        cb = match &self.shared_http_client {
            Some(client) => cb.http(client.clone()),
            None => cb.reqwest_with_options(reqwest::ClientOptions {
                additional_root_certs: self.certs.clone(),
                timeout: TIMEOUT,
                ..reqwest::ClientOptions::default()
            }),
        };
        cb.build()
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
            let auth_manager = auth::from_adc()
                .await
                .context("failed to initialize Google Cloud auth")?;
            Box::new(
                new_google_secret_manager(
                    gcp_project.as_ref().expect("need --gcp-project"),
                    auth_manager,
                    Duration::MAX,
                    GrpcConnectionOptions::default(),
                    metrics::Client::NONE,
                )
                .await
                .context("failed to load secrets from Google Secret Manager")?,
            )
        }
    };

    let (version, secret) = secret_manager
        .get_latest_secret_version(&tenant_secret_name(tenant))
        .await
        .context("could not get secrets for tenant")?
        .ok_or_else(|| anyhow!("could not find any secret versions for tenant"))?;
    Ok((secret.try_into()?, version.into()))
}
