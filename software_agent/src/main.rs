use anyhow::anyhow;
use blake2::Blake2s256;
use clap::Parser;
use futures::future;
use hkdf::Hkdf;
use hmac::SimpleHmac;
use hsmcore::hsm::RealmKeys;
use hsmcore::hsm::RecordEncryptionKey;
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

use agent_core::Agent;
use hsmcore::hsm::MacKey;
use loam_mvp::clap_parsers::parse_duration;
use loam_mvp::google_auth;
use loam_mvp::logging;
use loam_mvp::metrics;
use loam_mvp::realm::hsm::client::HsmClient;
use loam_mvp::realm::store::bigtable::{AgentBigTableArgs, BigTableArgs};

mod http_hsm;

use http_hsm::client::HsmHttpClient;
use http_hsm::host::HttpHsm;

/// A host agent that embeds an insecure software HSM.
#[derive(Parser)]
struct Args {
    #[command(flatten)]
    bigtable: BigTableArgs,

    #[command(flatten)]
    agent_bigtable: AgentBigTableArgs,

    /// Derive realm keys from this input (insecure).
    #[arg(short, long)]
    key: String,

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

    let mut args = Args::parse();
    args.bigtable.agent_args = Some(args.agent_bigtable);

    let name = args.name.unwrap_or_else(|| format!("agent{}", args.listen));
    let metrics = metrics::Client::new("software_agent");

    let dir = args.state_dir.unwrap_or_else(random_tmp_dir);
    if !dir.exists() {
        fs::create_dir_all(&dir).unwrap_or_else(|e| {
            panic!("failed to create directory {dir:?} for persistent state: {e:?}")
        });
    } else if dir.is_file() {
        panic!("--state-dir should be a directory, but {dir:?} is a file");
    }

    let keys = insecure_derive_realm_keys(&args.key).unwrap();
    let hsm = HttpHsm::new(dir.clone(), name.clone(), keys)
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
        .connect_data(auth_manager.clone(), metrics.clone())
        .await
        .expect("Unable to connect to Bigtable");

    let store_admin = args
        .bigtable
        .connect_admin(auth_manager)
        .await
        .expect("Unable to connect to Bigtable admin");

    let hsm = HsmClient::new(
        HsmHttpClient::new(hsm_url),
        name.clone(),
        args.metrics,
        metrics.clone(),
    );
    let agent = Agent::new(name, hsm, store, store_admin, metrics);
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

fn insecure_derive_realm_keys(s: &str) -> anyhow::Result<RealmKeys> {
    if s.is_empty() {
        return Err(anyhow!("the key can't be empty"));
    }
    let salts = [
        // from /dev/urandom
        hex::decode("12DC3D4454D4FFFDBCD5F3484DC23D6BD4CB1323DB3D5BFB53DE88589FD48D34")?,
        hex::decode("591ABF589B93E8F75EEA54F2BE94360C5BCA05903AA85C7DE6847F4E48A50EED")?,
        hex::decode("B9782DBCA82235A2871226DD05807C955592FD5FC29280A536DFD2E02D2A9BFE")?,
    ];
    let mac = MacKey::from(derive_from(s.as_bytes(), &salts[0]));
    let record = RecordEncryptionKey::from(derive_from(s.as_bytes(), &salts[1]));
    let noise_priv = x25519_dalek::StaticSecret::from(derive_from(s.as_bytes(), &salts[2]));
    let noise_pub = x25519_dalek::PublicKey::from(&noise_priv);
    Ok(RealmKeys {
        communication: (noise_priv, noise_pub),
        record,
        mac,
    })
}

fn derive_from<const N: usize>(b: &[u8], salt: &[u8]) -> [u8; N] {
    let kdf = Hkdf::<Blake2s256, SimpleHmac<Blake2s256>>::new(Some(salt), b);
    let mut out = [0u8; N];
    kdf.expand(&[], &mut out).unwrap();
    out
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
        expect_file!["../usage.txt"].assert_eq(
            &Args::command()
                .try_get_matches_from(["agent", "--help"])
                .unwrap_err()
                .to_string(),
        );
    }
}
