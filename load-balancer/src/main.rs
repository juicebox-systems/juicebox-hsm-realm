use clap::Parser;
use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tracing::{info, warn};

use loam_mvp::client_auth::new_google_secret_manager;
use loam_mvp::google_auth;
use loam_mvp::logging;
use loam_mvp::realm::store::bigtable::BigTableArgs;
use loam_mvp::secret_manager::{Periodic, SecretManager, SecretsFile};

mod cert;
mod load_balancer;

use cert::CertificateResolver;
use load_balancer::LoadBalancer;

#[derive(Parser)]
#[command(about = "An HTTP load balancer for one or more realms")]
struct Args {
    #[command(flatten)]
    bigtable: BigTableArgs,

    /// The IP/port to listen on.
    #[arg(
        short,
        long,
        default_value_t = SocketAddr::from(([127,0,0,1], 8081)),
        value_parser=parse_listen,
    )]
    listen: SocketAddr,

    /// Name of the load balancer in logging [default: lb{listen}]
    #[arg(short, long)]
    name: Option<String>,

    /// Name of JSON file containing per-tenant keys for authentication. The
    /// default is to fetch these from Google Secret Manager.
    #[arg(long)]
    secrets_file: Option<PathBuf>,

    /// Name of the file containing the private key for terminating TLS.
    #[arg(long)]
    tls_key: PathBuf,

    /// Name of the file containing the certificate(s) for terminating TLS.
    #[arg(long)]
    tls_cert: PathBuf,
}

#[tokio::main]
async fn main() {
    logging::configure("loam-load-balancer");

    let args = Args::parse();
    let name = args.name.unwrap_or_else(|| format!("lb{}", args.listen));

    let certs = Arc::new(
        CertificateResolver::new(args.tls_key, args.tls_cert).expect("Failed to load TLS key/cert"),
    );
    let cert_resolver = certs.clone();

    let mut signals =
        Signals::new([SIGHUP, SIGINT, SIGTERM, SIGQUIT]).expect("Failed to init signal handler");

    // This uses a real thread rather than a tokio task to resolve some weirdness in
    // logging::flush where the underlying opentelemetry call just hangs forever.
    thread::Builder::new()
        .name("signal_handler".into())
        .spawn(move || {
            for signal in &mut signals {
                match signal {
                    SIGHUP => {
                        info!("Reloading TLS certificate/key from disk");
                        match certs.reload() {
                            Err(err) => warn!(?err, "Failed to reload TLS certificate/key"),
                            Ok(_) => info!("Successfully reloaded TLS certificate/key from disk"),
                        }
                    }
                    SIGTERM | SIGINT | SIGQUIT => {
                        info!(pid = std::process::id(), "received termination signal");
                        logging::flush();
                        info!(pid = std::process::id(), "exiting");
                        std::process::exit(0);
                    }
                    _ => unreachable!(),
                }
            }
        })
        .unwrap();

    let auth_manager = if args.bigtable.needs_auth() || args.secrets_file.is_none() {
        Some(
            google_auth::from_adc()
                .await
                .expect("failed to initialize Google Cloud auth"),
        )
    } else {
        None
    };

    let store_admin = args
        .bigtable
        .connect_admin(auth_manager.clone())
        .await
        .expect("Unable to connect to Bigtable admin");

    store_admin
        .initialize_discovery()
        .await
        .expect("Failed to initialize service discovery table");

    let store = args
        .bigtable
        .connect_data(auth_manager.clone())
        .await
        .expect("Unable to connect to Bigtable");

    let secret_manager: Box<dyn SecretManager> = match args.secrets_file {
        Some(secrets_file) => {
            info!(path = ?secrets_file, "loading secrets from JSON file");
            Box::new(
                Periodic::new(SecretsFile::new(secrets_file), Duration::from_secs(5))
                    .await
                    .expect("failed to load secrets from JSON file"),
            )
        }

        None => {
            info!("connecting to Google Cloud Secret Manager");
            Box::new(
                new_google_secret_manager(
                    &args.bigtable.project,
                    auth_manager.unwrap(),
                    Duration::from_secs(5),
                )
                .await
                .expect("failed to load Google SecretManager secrets"),
            )
        }
    };

    let lb = LoadBalancer::new(name, store, secret_manager);
    let (url, join_handle) = lb.listen(args.listen, cert_resolver).await.expect("TODO");
    info!(url = %url, "Load balancer started");
    join_handle.await.unwrap();

    logging::flush();
    info!(pid = std::process::id(), "exiting");
}

fn parse_listen(s: &str) -> Result<SocketAddr, String> {
    s.parse()
        .map_err(|e| format!("couldn't parse listen argument: {e}"))
}
