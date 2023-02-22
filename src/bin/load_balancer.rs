use clap::Parser;
use http::Uri;
use std::net::SocketAddr;
use tracing::info;

use loam_mvp::logging;
use loam_mvp::realm::load_balancer::LoadBalancer;
use loam_mvp::realm::store::bigtable;

#[derive(Parser)]
#[command(about = "An HTTP load balancer for one or more realms")]
struct Args {
    /// Address of Bigtable storage system.
    #[arg(long, default_value = "http://localhost:9000")]
    bigtable: Uri,

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

    let lb = LoadBalancer::new(name, store);
    let (url, join_handle) = lb.listen(args.listen).await.expect("TODO");
    info!(url = %url, "Load balancer started");
    join_handle.await.unwrap();
}

fn parse_listen(s: &str) -> Result<SocketAddr, String> {
    s.parse()
        .map_err(|e| format!("couldn't parse listen argument: {e}"))
}
