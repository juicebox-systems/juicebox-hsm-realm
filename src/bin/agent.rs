use clap::Parser;
use http::Uri;
use std::net::SocketAddr;
use tracing::info;
use url::Url;

use loam_mvp::logging;
use loam_mvp::realm::agent::Agent;
use loam_mvp::realm::hsm::http::client::HsmHttpClient;
use loam_mvp::realm::store::bigtable;

#[derive(Parser)]
#[command(about = "A host agent to pair with an HSM")]
struct Args {
    /// Address of Bigtable storage system (both data and admin).
    #[arg(long, default_value = "http://localhost:9000")]
    bigtable: Uri,

    /// Address of HSM (HTTP).
    #[arg(long, default_value = "http://localhost:8080")]
    hsm: Url,

    /// The IP/port to listen on.
    #[arg(
        short,
        long,
        default_value_t = SocketAddr::from(([127,0,0,1], 8082)),
        value_parser=parse_listen,
    )]
    listen: SocketAddr,

    /// Name of the agent in logging [default: agent{listen}]
    #[arg(short, long)]
    name: Option<String>,
}

#[tokio::main]
async fn main() {
    logging::configure();
    let args = Args::parse();
    let name = args.name.unwrap_or_else(|| format!("lb{}", args.listen));

    info!(bigtable = %args.bigtable, "Connecting to Bigtable");
    let instance = bigtable::Instance {
        project: String::from("prj"),
        instance: String::from("inst"),
    };
    let store = bigtable::StoreClient::new(args.bigtable.clone(), instance.clone())
        .await
        .unwrap_or_else(|e| panic!("Unable to connect to Bigtable at `{}`: {e}", args.bigtable));
    let store_admin = bigtable::StoreAdminClient::new(args.bigtable.clone(), instance.clone())
        .await
        .unwrap_or_else(|e| {
            panic!(
                "Unable to connect to Bigtable admin at `{}`: {e}",
                args.bigtable
            )
        });

    let hsm = HsmHttpClient::new_client(args.hsm);
    let lb = Agent::new(name, hsm, store, store_admin);
    let (url, join_handle) = lb.listen(args.listen).await.expect("TODO");
    info!(url = %url, "Load balancer started");
    join_handle.await.unwrap();
}

fn parse_listen(s: &str) -> Result<SocketAddr, String> {
    s.parse()
        .map_err(|e| format!("couldn't parse listen argument: {e}"))
}
