use clap::Parser;
use std::{net::SocketAddr, time::Duration};
use tracing::info;

use loam_mvp::{
    clap_parsers::{parse_duration, parse_listen},
    google_auth, logging,
    realm::{cluster::Manager, store::bigtable::BigTableArgs},
};

#[derive(Debug, Parser)]
#[command(about = "Management controller for Juicebox Clusters")]
struct Args {
    #[command(flatten)]
    bigtable: BigTableArgs,

    /// The IP/port to listen on.
    #[arg(
        short,
        long,
        default_value_t = SocketAddr::from(([127,0,0,1], 8079)),
        value_parser=parse_listen,
    )]
    listen: SocketAddr,

    /// Interval for checking the cluster state in milliseconds.
    #[arg(short, long, default_value="2000", value_parser=parse_duration)]
    interval: Duration,
}

#[tokio::main]
async fn main() {
    logging::configure("cluster-manager");

    ctrlc::set_handler(move || {
        info!(pid = std::process::id(), "received termination signal");
        logging::flush();
        info!(pid = std::process::id(), "exiting");
        std::process::exit(0);
    })
    .expect("error setting signal handler");

    let args = Args::parse();
    info!(?args, "Parsed command-line args");

    let auth_manager = if args.bigtable.needs_auth() {
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

    info!("initializing service discovery table");
    store_admin
        .initialize_discovery()
        .await
        .expect("Failed to initialize service discovery table");

    let store = args
        .bigtable
        .connect_data(auth_manager)
        .await
        .expect("Unable to connect to Bigtable data");

    let manager = Manager::new(store, args.interval);
    let (url, handle) = manager
        .listen(args.listen)
        .await
        .expect("Failed to start server");

    info!(url=%url, "Cluster Manager started");
    let _ = handle.await;
}
