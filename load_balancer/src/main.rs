use clap::Parser;
use futures::future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{info, warn};

use google::auth;
use observability::{logging, metrics};
use secret_manager::{new_google_secret_manager, Periodic, SecretManager, SecretsFile};
use server::{ConnectionOptions, ManagerOptions};
use service_core::clap_parsers::{parse_duration, parse_listen};
use service_core::panic;
use service_core::term::install_termination_handler;

mod cert;
mod load_balancer;
mod server;

use cert::CertificateResolver;
use load_balancer::LoadBalancer;

#[derive(Debug, Parser)]
#[command(version, about = "An HTTP load balancer for one or more realms")]
struct Args {
    #[command(flatten)]
    bigtable: store::Args,

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

    /// Max length of time to wait for a graceful shutdown to complete. (milliseconds)
    #[arg(long, default_value="60000", value_parser=parse_duration)]
    shutdown_timeout: Duration,

    /// Number of health checks to report as shutting down before starting to drain connections.
    #[arg(long, default_value_t = 5, name = "COUNT")]
    shutdown_min_health_checks: usize,

    /// Connections that have been idle longer than this timeout will be closed. (milliseconds)
    #[arg(long, default_value="10000", value_parser=parse_duration, name="TIMEOUT")]
    idle_timeout: Duration,

    /// Name of the file containing the private key for terminating TLS.
    #[arg(long)]
    tls_key: PathBuf,

    /// Name of the PEM file containing the certificate(s) for terminating TLS.
    #[arg(long)]
    tls_cert: PathBuf,
}

#[tokio::main]
async fn main() {
    logging::configure("juicebox-load-balancer");
    panic::set_abort_on_panic();

    let args = Args::parse();
    info!(
        ?args,
        version = env!("CARGO_PKG_VERSION"),
        "starting load balancer"
    );
    let name = args.name.unwrap_or_else(|| format!("lb{}", args.listen));
    let metrics = metrics::Client::new("load_balancer");

    let certs = Arc::new(
        CertificateResolver::new(args.tls_key, args.tls_cert).expect("Failed to load TLS key/cert"),
    );
    let cert_resolver = certs.clone();

    let mut shutdown_tasks = install_termination_handler(args.shutdown_timeout);
    tokio::spawn(async move {
        let mut hup = signal(SignalKind::hangup()).unwrap();
        loop {
            hup.recv().await;
            info!("Reloading TLS certificate/key from disk");
            match certs.reload() {
                Err(err) => warn!(?err, "Failed to reload TLS certificate/key"),
                Ok(_) => info!("Successfully reloaded TLS certificate/key from disk"),
            }
        }
    });

    let auth_manager = if args.bigtable.needs_auth() || args.secrets_file.is_none() {
        Some(
            auth::from_adc()
                .await
                .expect("failed to initialize Google Cloud auth"),
        )
    } else {
        None
    };

    let store = args
        .bigtable
        .connect_data(
            auth_manager.clone(),
            store::Options {
                metrics: metrics.clone(),
                ..store::Options::default()
            },
        )
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

    let svc_cfg = ManagerOptions {
        min_health_checks_before_shutdown: args.shutdown_min_health_checks,
        conn: ConnectionOptions {
            idle_timeout: args.idle_timeout,
        },
    };
    let lb = LoadBalancer::new(name, store, secret_manager, metrics.clone(), svc_cfg);
    let lb_clone = lb.clone();
    shutdown_tasks.add(Box::pin(async move { lb_clone.shutdown().await }));

    let (url, join_handle) = lb
        .listen(args.listen, cert_resolver)
        .await
        .expect("failed to listen for connections");
    info!(url = %url, "Load balancer started");
    join_handle.await.unwrap();
    future::pending::<()>().await;
    unreachable!("the pending future is never ready");
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use expect_test::expect_file;

    #[test]
    fn test_usage() {
        expect_file!["usage.txt"].assert_eq(
            &Args::command()
                .try_get_matches_from(["load_balancer", "--help"])
                .unwrap_err()
                .to_string(),
        );
    }
}
