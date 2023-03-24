use clap::Parser;
use std::net::SocketAddr;
use tracing::info;
use url::Url;

use loam_mvp::logging;
use loam_mvp::realm::agent::Agent;
use loam_mvp::realm::hsm::http::client::HsmHttpClient;
use loam_mvp::realm::store::bigtable::BigTableArgs;

#[derive(Parser)]
#[command(about = "A host agent to pair with an HSM")]
struct Args {
    #[command(flatten)]
    bigtable: BigTableArgs,

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
    logging::configure("loam-agent");

    ctrlc::set_handler(move || {
        info!(pid = std::process::id(), "received termination signal");
        logging::flush();
        info!(pid = std::process::id(), "exiting");
        std::process::exit(0);
    })
    .expect("error setting signal handler");

    let args = Args::parse();
    let name = args.name.unwrap_or_else(|| format!("agent{}", args.listen));

    let store = args.bigtable.connect_data().await;
    let store_admin = args.bigtable.connect_admin().await;

    let hsm = HsmHttpClient::new_client(args.hsm);
    let agent = Agent::new(name, hsm, store, store_admin);
    let (url, join_handle) = agent.listen(args.listen).await.expect("TODO");
    info!(url = %url, "Agent started");
    join_handle.await.unwrap();
}

fn parse_listen(s: &str) -> Result<SocketAddr, String> {
    s.parse()
        .map_err(|e| format!("couldn't parse listen argument: {e}"))
}
