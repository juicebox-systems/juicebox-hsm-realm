use clap::Parser;
use loam_mvp::{
    clap_parsers::parse_duration,
    google_auth,
    http_client::{Client, ClientOptions},
    logging,
    realm::{
        agent::types::AgentService,
        cluster,
        store::bigtable::{BigTableArgs, StoreClient},
    },
};
use std::time::Duration;
use tokio::time;
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(about = "Management controller for Loam Clusters")]
struct Args {
    #[command(flatten)]
    bigtable: BigTableArgs,

    /// Interval for checking the cluster state in milliseconds.
    #[arg(short, long, default_value="2000", value_parser=parse_duration)]
    interval: Duration,
}

#[tokio::main]
async fn main() {
    logging::configure("cluster-manager");

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
    store_admin.initialize_discovery().await.expect("TODO");

    let manager = Manager {
        store: args
            .bigtable
            .connect_data(auth_manager)
            .await
            .expect("Unable to connect to Bigtable data"),
        agent_client: Client::<AgentService>::new(ClientOptions::default()),
    };

    loop {
        manager.manage().await;
        time::sleep(args.interval).await;
    }
}

struct Manager {
    agent_client: Client<AgentService>,
    store: StoreClient,
}

impl Manager {
    async fn manage(&self) {
        if let Err(err) = cluster::ensure_groups_have_leader(&self.agent_client, &self.store).await
        {
            warn!(?err, "GRPC error while checking cluster state")
        }
    }
}
