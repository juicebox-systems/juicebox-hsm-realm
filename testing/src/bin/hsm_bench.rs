use clap::Parser;
use std::env::current_dir;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

use juicebox_process_group::ProcessGroup;
use observability::logging;
use service_core::term::install_termination_handler;
use testing::exec::cluster_gen::{create_cluster, ClusterConfig, RealmConfig};
use testing::exec::hsm_gen::Entrust;

/// An end-to-end benchmark to stress an HSM.
#[derive(Debug, Parser)]
#[command(version = build_info::clap!())]
struct Args {
    #[command(flatten)]
    bigtable: store::BigtableArgs,

    /// Number of secret registrations to do at a time.
    #[arg(long, value_name = "N", default_value_t = 3)]
    concurrency: usize,

    /// Total number of secret registrations.
    #[arg(long, value_name = "N", default_value_t = 100)]
    count: usize,

    /// Use a local pub/sub emulator. If not set will use pub/sub from the same
    /// project as the bigtable-project argument.
    #[arg(long, default_value_t = false)]
    pubsub_emulator: bool,

    /// Use an entrust HSM/Agent as the only HSM.
    ///
    /// You must provide signed machine and userdata files at
    /// "target/powerpc-unknown-linux-gnu/{mode}/entrust_hsm.sar" and
    /// "target/powerpc-unknown-linux-gnu/{mode}/userdata.sar".
    #[arg(long, default_value_t = false)]
    entrust: bool,

    /// Name of JSON file containing per-tenant keys for authentication. The
    /// default is to fetch these from Google Secret Manager.
    #[arg(long)]
    secrets_file: Option<PathBuf>,

    /// A directory to read/write HSM state to. This allows for testing with a
    /// realm that was created by a previous run. You need to keep the bigtable
    /// state between runs for this to be useful.
    #[arg(long)]
    state: Option<PathBuf>,

    /// Keep the cluster alive until Ctrl-C is input
    #[arg(short, long, default_value_t = false)]
    keep_alive: bool,
}

#[tokio::main]
async fn main() {
    logging::configure("juicebox-hsm-bench", build_info::get!());

    let mut process_group = ProcessGroup::new();
    install_termination_handler(Duration::from_secs(1));

    let args = Args::parse();
    info!(?args, "Parsed command-line args");

    let config = ClusterConfig {
        load_balancers: 1,
        cluster_managers: 2,
        realms: vec![RealmConfig {
            hsms: if args.entrust {
                // Entrust HSMs cannot participate in the same realm as
                // software HSMs since they (currently) have no way to share
                // the same secret keys.
                1
            } else {
                5
            },
            groups: 1,
            state_dir: args.state.clone(),
        }],
        bigtable: args.bigtable.clone(),
        local_pubsub: args.pubsub_emulator,
        secrets_file: args.secrets_file.clone(),
        entrust: Entrust(args.entrust),
        path_to_target: current_dir().unwrap(),
    };

    let cluster = create_cluster(config, &mut process_group, 4000)
        .await
        .unwrap();

    let path = "target/configuration.json";
    fs::write(
        path,
        serde_json::to_string(&cluster.configuration()).unwrap(),
    )
    .unwrap_or_else(|e| panic!("failed to write to {path:?}: {e}"));
    info!("wrote configuration to {path:?}");

    info!("starting cluster_bench");
    let mut cluster_bench = Command::new(
        current_dir()
            .unwrap()
            .join("target")
            .join(if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            })
            .join("cluster_bench"),
    );
    cluster_bench
        .arg("--configuration")
        .arg(serde_json::to_string(&cluster.configuration()).unwrap())
        .arg("--concurrency")
        .arg(args.concurrency.to_string())
        .arg("--count")
        .arg(args.count.to_string())
        .arg("--tls-certificate")
        .arg("target/localhost.cert.der")
        .arg("--reporting-interval")
        .arg("1m")
        .arg("--conn-pool")
        .arg("10");
    if let Some(f) = args.secrets_file {
        cluster_bench.arg("--secrets-file").arg(f);
    } else {
        cluster_bench
            .arg("--gcp-project")
            .arg(args.bigtable.project);
    }
    if let Err(err) = cluster_bench.status() {
        warn!(?err, "error running cluster_bench");
    }

    if args.keep_alive {
        info!("sleeping forever due to --keep-alive");
        sleep(Duration::MAX).await;
    }
    info!("main: done");
    if args.state.is_some() || args.entrust {
        info!("letting agents drain their delete queue");
        sleep(Duration::from_secs(6)).await;
    }
    process_group.kill();
    logging::flush();
    info!("main: exiting");
}
