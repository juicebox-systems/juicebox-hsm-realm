use clap::Parser;
use loam_mvp::future_task::FutureTasks;
use rand::{rngs::OsRng, RngCore};
use std::fmt::Write;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;
use tokio::time::sleep;
use tracing::{debug, info};

use hsmcore::hsm::RealmKey;
use loam_mvp::clap_parsers::parse_listen;
use loam_mvp::logging;
use loam_mvp::realm::hsm::http::host::HttpHsm;

#[derive(Parser)]
#[command(about = "A software not-HSM accessible via HTTP")]
struct Args {
    /// The IP/port to listen on.
    #[arg(
        short,
        long,
        default_value_t = SocketAddr::from(([127,0,0,1], 8080)),
        value_parser=parse_listen,
    )]
    listen: SocketAddr,

    /// Name of the hsm in logging [default: hsm{listen}]
    #[arg(short, long)]
    name: Option<String>,

    /// Derive realm key from this input.
    #[arg(short, long, value_parser=parse_realm_key)]
    key: RealmKey,

    /// Directory to store the persistent state file in [default: a random temp dir]
    #[arg(short, long)]
    state_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    logging::configure("loam-http-hsm");

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
    let name = args.name.unwrap_or_else(|| format!("hsm{}", args.listen));

    let dir = args.state_dir.unwrap_or_else(random_tmp_dir);
    if !dir.exists() {
        fs::create_dir_all(&dir).unwrap_or_else(|e| {
            panic!(
                "failed to create directory '{}' for persistent state: {e:?}",
                dir.display()
            )
        });
    } else if dir.is_file() {
        println!(
            "the --dir argument should be a directory, but '{}' is a file.",
            dir.display()
        );
        return;
    }
    let hsm = HttpHsm::new(dir.clone(), name.clone(), args.key)
        .expect("HttpHsm failed to initialize from prior state");
    let hsm_clone = hsm.clone();
    shutdown_tasks.add(Box::pin(async move {
        let start = Instant::now();
        // give some time for the agent to shutdown before we do.
        // this is just for hsm_bench & demo_runner
        sleep(Duration::from_millis(50)).await;
        while hsm_clone.is_leader() {
            debug!(hsm = name, "is leader, waiting for shutdown");
            if start.elapsed() > Duration::from_secs(5) {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    }));
    let (url, join_handle) = hsm.listen(args.listen).await.unwrap();
    info!(url = %url, dir=%dir.display(), "HSM started");
    join_handle.await.unwrap();
}

fn parse_realm_key(s: &str) -> Result<RealmKey, String> {
    Ok(RealmKey::derive_from(s.as_bytes()))
}

fn random_tmp_dir() -> PathBuf {
    let tmp = std::env::temp_dir();
    let mut n = [0u8; 10];
    OsRng.fill_bytes(&mut n);
    let mut dn = String::from("http_hsm_");
    for b in n {
        write!(dn, "{b:02x}").unwrap()
    }
    tmp.join(dn)
}
