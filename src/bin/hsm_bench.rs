use clap::Parser;
use futures::StreamExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use loam_mvp::exec::cluster_gen::{create_cluster, ClusterConfig, RealmConfig};
use loam_mvp::exec::hsm_gen::{Entrust, MetricsParticipants};
use loam_mvp::http_client::{self};
use loam_mvp::logging;
use loam_mvp::process_group::ProcessGroup;
use loam_mvp::realm::store::bigtable::BigTableArgs;
use loam_sdk::{Client, Pin, UserSecret};
use loam_sdk_core::types::Policy;
use loam_sdk_networking::rpc::LoadBalancerService;

/// An end-to-end benchmark to stress an HSM.
#[derive(Debug, Parser)]
struct Args {
    #[command(flatten)]
    bigtable: BigTableArgs,

    /// Number of secret registrations to do at a time.
    #[arg(long, value_name = "N", default_value_t = 3)]
    concurrency: usize,

    /// Total number of secret registrations.
    #[arg(long, value_name = "N", default_value_t = 100)]
    count: usize,

    /// Use an entrust HSM/Agent for one of the HSMs and make it the leader.
    #[arg(long, default_value_t = false)]
    entrust: bool,

    /// Report metrics from HSMs. Options are Leader, All, None.
    #[arg(long, value_parser=MetricsParticipants::parse, default_value_t=MetricsParticipants::None)]
    metrics: MetricsParticipants,

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
    logging::configure("loam-hsm-bench");

    let mut process_group = ProcessGroup::new();

    ctrlc::set_handler(move || {
        info!(pid = std::process::id(), "received termination signal");
        logging::flush();
        info!(pid = std::process::id(), "exiting");
        std::process::exit(0);
    })
    .expect("error setting signal handler");

    let args = Args::parse();
    info!(?args, "Parsed command-line args");

    let config = ClusterConfig {
        load_balancers: 1,
        realms: vec![RealmConfig {
            hsms: 5,
            groups: 1,
            metrics: args.metrics,
            state_dir: args.state.clone(),
        }],
        bigtable: args.bigtable,
        secrets_file: args.secrets_file,
        entrust: Entrust(args.entrust),
    };

    let cluster = create_cluster(config, &mut process_group, 4000)
        .await
        .unwrap();

    info!(clients = args.concurrency, "creating clients");
    let clients: Vec<Arc<Mutex<Client<_, http_client::Client<LoadBalancerService>>>>> = (0..args
        .concurrency)
        .map(|i| Arc::new(Mutex::new(cluster.client_for_user(format!("mario{i}")))))
        .collect();

    info!("main: Running test register");
    clients[0]
        .lock()
        .await
        .register(
            &Pin::from(b"pin-test".to_vec()),
            &UserSecret::from(b"secret-test".to_vec()),
            Policy { num_guesses: 2 },
        )
        .await
        .unwrap();

    info!(
        concurrency = args.concurrency,
        count = args.count,
        "main: Running concurrent registers"
    );
    let start = Instant::now();

    let mut stream = futures::stream::iter((0..args.count).map(|i| {
        let client = clients[i % args.concurrency].clone();
        async move {
            client
                .lock()
                .await
                .register(
                    &Pin::from(format!("pin{i}").into_bytes()),
                    &UserSecret::from(format!("secret{i}").into_bytes()),
                    Policy { num_guesses: 2 },
                )
                .await
        }
    }))
    .buffer_unordered(args.concurrency);

    let mut completed = 0;
    let mut errors = 0;
    while let Some(result) = stream.next().await {
        match result {
            Ok(_) => {
                debug!(completed, "ok");
                completed += 1;
            }
            Err(err) => {
                warn!(?err, "client got error");
                errors += 1;
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    info!(
        registrations = args.count,
        seconds = elapsed,
        registrations_per_s = (args.count as f64) / elapsed,
        concurrency = args.concurrency,
        "completed benchmark"
    );
    if errors > 0 {
        warn!(errors, "There were errors reported by the client");
    }
    if args.keep_alive {
        sleep(Duration::MAX).await;
    }
    info!("main: done");
    if args.state.is_some() {
        info!("letting agents drain their delete queue");
        sleep(Duration::from_secs(6)).await;
    }
    process_group.kill();
    logging::flush();
    info!("main: exiting");
}
