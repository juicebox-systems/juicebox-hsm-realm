use clap::Parser;
use futures::future;
use loam_mvp::clap_parsers::parse_listen;
use loam_mvp::future_task::FutureTasks;
use rand::{rngs::OsRng, RngCore};
use std::fmt::Write;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::runtime::Handle;
use tracing::info;

use hsmcore::hsm::MacKey;
use loam_mvp::clap_parsers::parse_duration;
use loam_mvp::google_auth;
use loam_mvp::logging;
use loam_mvp::realm::agent::Agent;
use loam_mvp::realm::hsm::client::HsmClient;
use loam_mvp::realm::hsm::http::client::HsmHttpClient;
use loam_mvp::realm::hsm::http::host::HttpHsm;
use loam_mvp::realm::store::bigtable::BigTableArgs;

/// A host agent that embeds an insecure software HSM.
#[derive(Parser)]
struct Args {
    #[command(flatten)]
    bigtable: BigTableArgs,

    /// Derive realm key from this input (insecure).
    #[arg(short, long, value_parser=derive_mac_key)]
    key: MacKey,

    /// The IP/port to listen on.
    #[arg(
        short,
        long,
        default_value_t = SocketAddr::from(([127,0,0,1], 8082)),
        value_parser=parse_listen,
    )]
    listen: SocketAddr,

    /// HSM Metrics reporting interval in milliseconds [default: no reporting]
    #[arg(short, long, value_parser=parse_duration)]
    metrics: Option<Duration>,

    /// Name of the agent in logging [default: agent{listen}]
    #[arg(short, long)]
    name: Option<String>,

    /// Directory to store the persistent state file in [default: a random temp dir]
    #[arg(short, long)]
    state_dir: Option<PathBuf>,
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

    let dir = args.state_dir.unwrap_or_else(random_tmp_dir);
    if !dir.exists() {
        fs::create_dir_all(&dir).unwrap_or_else(|e| {
            panic!("failed to create directory {dir:?} for persistent state: {e:?}")
        });
    } else if dir.is_file() {
        panic!("--state-dir should be a directory, but {dir:?} is a file");
    }

    let hsm = HttpHsm::new(dir.clone(), name.clone(), args.key)
        .expect("HttpHsm failed to initialize from prior state");
    let (hsm_url, hsm_handle) = hsm.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    info!(url = %hsm_url, dir=%dir.display(), "HSM started");

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

    let hsm = HsmClient::new(HsmHttpClient::new(hsm_url), name.clone(), args.metrics);
    let agent = Agent::new(name, hsm, store, store_admin);
    let agent_clone = agent.clone();
    shutdown_tasks.add(Box::pin(async move {
        agent_clone.shutdown(Duration::from_secs(10)).await
    }));

    let (url, agent_handle) = agent
        .listen(args.listen)
        .await
        .expect("Failed to start web server");

    info!(%url, "Agent started");

    future::try_join(hsm_handle, agent_handle).await.unwrap();
}

fn derive_mac_key(s: &str) -> Result<MacKey, String> {
    Ok(MacKey::derive_from(s.as_bytes()))
}

fn random_tmp_dir() -> PathBuf {
    let tmp = std::env::temp_dir();
    let mut n = [0u8; 10];
    OsRng.fill_bytes(&mut n);
    let mut dn = String::from("agent_hsm_");
    for b in n {
        write!(dn, "{b:02x}").unwrap()
    }
    tmp.join(dn)
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
