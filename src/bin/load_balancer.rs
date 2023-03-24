use clap::Parser;
use std::net::SocketAddr;
use tracing::info;

use loam_mvp::logging;
use loam_mvp::realm::load_balancer::LoadBalancer;
use loam_mvp::realm::store::bigtable::BigTableArgs;

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
}

#[tokio::main]
async fn main() {
    logging::configure("loam-load-balancer");

    ctrlc::set_handler(move || {
        info!(pid = std::process::id(), "received termination signal");
        logging::flush();
        info!(pid = std::process::id(), "exiting");
        std::process::exit(0);
    })
    .expect("error setting signal handler");

    let args = Args::parse();
    let name = args.name.unwrap_or_else(|| format!("lb{}", args.listen));

    let store = args.bigtable.connect_data().await;

    let lb = LoadBalancer::new(name, store);
    let (url, join_handle) = lb.listen(args.listen).await.expect("TODO");
    info!(url = %url, "Load balancer started");
    join_handle.await.unwrap();

    logging::flush();
    info!(pid = std::process::id(), "exiting");
}

fn parse_listen(s: &str) -> Result<SocketAddr, String> {
    s.parse()
        .map_err(|e| format!("couldn't parse listen argument: {e}"))
}
