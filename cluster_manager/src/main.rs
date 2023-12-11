use clap::Parser;
use std::{net::SocketAddr, time::Duration};
use tracing::info;

use google::auth;
use manager::Manager;
use observability::{logging, metrics};
use service_core::clap_parsers::{parse_duration, parse_listen};
use service_core::panic;
use service_core::term::install_termination_handler;

mod manager;

/// Management controller for Juicebox HSM realm clusters.
#[derive(Debug, Parser)]
#[command(version = build_info::clap!())]
struct Args {
    #[command(flatten)]
    bigtable: store::BigtableArgs,

    /// The IP/port to listen on.
    #[arg(
        short,
        long,
        default_value_t = SocketAddr::from(([127,0,0,1], 8079)),
        value_parser=parse_listen,
    )]
    listen: SocketAddr,

    /// Interval for checking the cluster state.
    #[arg(short, long, default_value="2000ms", value_parser=parse_duration)]
    interval: Duration,

    /// Interval for rebalancing the cluster.
    #[arg(long, default_value="60s", value_parser=parse_duration)]
    rebalance_interval: Duration,
}

#[tokio::main]
async fn main() {
    logging::configure("cluster-manager");
    panic::set_abort_on_panic();
    install_termination_handler(Duration::from_secs(1));

    let args = Args::parse();
    info!(
        ?args,
        version = env!("CARGO_PKG_VERSION"),
        "starting Cluster Manager"
    );
    let metrics = metrics::Client::new("cluster_manager");

    let auth_manager = if args.bigtable.needs_auth() {
        Some(
            auth::from_adc()
                .await
                .expect("failed to initialize Google Cloud auth"),
        )
    } else {
        None
    };

    let store_admin = args
        .bigtable
        .connect_admin(auth_manager.clone(), metrics.clone())
        .await
        .expect("Unable to connect to Bigtable admin");

    info!("initializing service discovery table");
    store_admin
        .initialize_discovery()
        .await
        .expect("Failed to initialize service discovery table");

    store_admin
        .initialize_leases()
        .await
        .expect("Failed to initialize lease table");

    let store = args
        .bigtable
        .connect_data(
            auth_manager,
            store::Options {
                metrics: metrics.clone(),
                ..store::Options::default()
            },
        )
        .await
        .expect("Unable to connect to Bigtable data");

    let manager = Manager::new(
        args.listen.to_string(),
        store,
        args.interval,
        args.rebalance_interval,
        metrics,
    );
    let (url, handle) = manager
        .listen(args.listen)
        .await
        .expect("Failed to start server");

    info!(url=%url, "Cluster Manager started");
    let _ = handle.await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use expect_test::expect_file;

    #[test]
    fn test_usage() {
        expect_file!["cluster_manager_usage.txt"].assert_eq(
            &Args::command()
                .try_get_matches_from(["cluster_manager", "--help"])
                .unwrap_err()
                .to_string(),
        );
    }
}
