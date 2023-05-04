use clap::Parser;
use loam_mvp::clap_parsers::parse_listen;
use loam_mvp::future_task::FutureTasks;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::runtime::Handle;
use tracing::info;
use url::Url;

use loam_mvp::clap_parsers::parse_duration;
use loam_mvp::google_auth;
use loam_mvp::logging;
use loam_mvp::realm::agent::Agent;
use loam_mvp::realm::hsm::client::HsmClient;
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

    /// HSM Metrics reporting interval in milliseconds [default: no reporting]
    #[arg(short, long, value_parser=parse_duration)]
    metrics: Option<Duration>,
}

#[tokio::main]
async fn main() {
    logging::configure("loam-agent");

    let mut shutdown_tasks = FutureTasks::new();
    let mut shutdown_tasks_clone = shutdown_tasks.clone();
    let rt = Handle::try_current().unwrap();

    ctrlc::set_handler(move || {
        info!(pid = std::process::id(), "received termination signal");
        logging::flush();
        rt.block_on(async { shutdown_tasks_clone.join_all().await });
        logging::flush();
        info!(pid = std::process::id(), "exiting");
        std::process::exit(0);
    })
    .expect("error setting signal handler");

    let args = Args::parse();
    let name = args.name.unwrap_or_else(|| format!("agent{}", args.listen));

    let auth_manager = if args.bigtable.needs_auth() {
        Some(
            google_auth::from_adc()
                .await
                .expect("failed to initialize Google Cloud auth"),
        )
    } else {
        None
    };

    let store = args
        .bigtable
        .connect_data(auth_manager.clone())
        .await
        .expect("Unable to connect to Bigtable");

    let store_admin = args
        .bigtable
        .connect_admin(auth_manager)
        .await
        .expect("Unable to connect to Bigtable admin");

    let hsm_t = HsmHttpClient::new(args.hsm);
    let hsm = HsmClient::new(hsm_t, name.clone(), args.metrics);
    let agent = Agent::new(name, hsm, store, store_admin);
    let agent_clone = agent.clone();
    shutdown_tasks.add(Box::pin(async move {
        agent_clone.shutdown(Duration::from_secs(10)).await
    }));

    let (url, join_handle) = agent
        .listen(args.listen)
        .await
        .expect("Failed to start web server");

    info!(%url, "Agent started");

    join_handle.await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use expect_test::expect_file;

    #[test]
    fn test_usage() {
        expect_file!["agent_usage.txt"].assert_eq(
            &Args::command()
                .try_get_matches_from(["agent", "--help"])
                .unwrap_err()
                .to_string(),
        );
    }
}
