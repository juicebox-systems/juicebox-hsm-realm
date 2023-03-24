use clap::Parser;
use futures::StreamExt;
use hsmcore::types::{AuthToken, Policy};
use reqwest::Url;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::{debug, info};

use loam_mvp::client::{Client, Configuration, Pin, Realm, UserSecret};
use loam_mvp::logging;
use loam_mvp::realm::cluster;
use loam_mvp::realm::store::bigtable::BigTableArgs;

mod common;
use common::hsm_gen::{Entrust, HsmGenerator, Metrics};
use common::process_group::ProcessGroup;

#[derive(Debug, Parser)]
#[command(about = "An end-to-end benchmark to stress an HSM")]
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

    /// Report metrics from HSMs. Options are Leader, All
    #[arg(long, value_parser=Metrics::parse)]
    metrics: Option<Metrics>,
}

#[tokio::main]
async fn main() {
    logging::configure("loam-hsm-bench");

    let mut process_group = ProcessGroup::new();

    let mut process_group_alias = process_group.clone();
    ctrlc::set_handler(move || {
        info!(pid = std::process::id(), "received termination signal");
        logging::flush();
        process_group_alias.kill();
        info!(pid = std::process::id(), "exiting");
        std::process::exit(0);
    })
    .expect("error setting signal handler");

    let args = Args::parse();
    info!(?args, "Parsed command-line args");

    let store_admin = args.bigtable.connect_admin().await;
    info!("initializing service discovery table");
    store_admin.initialize_discovery().await.expect("TODO");

    info!("creating load balancer");
    let load_balancer: Url = {
        let address = SocketAddr::from(([127, 0, 0, 1], 3000));
        let mut cmd = Command::new(format!(
            "target/{}/load_balancer",
            if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
        ));
        cmd.arg("--listen").arg(address.to_string());
        args.bigtable.add_to_cmd(&mut cmd);
        process_group.spawn(&mut cmd);
        Url::parse(&format!("http://{address}")).unwrap()
    };

    let mut hsm_generator = HsmGenerator::new(Entrust(args.entrust), 4000);

    let num_hsms = 5;
    info!(count = num_hsms, "creating HSMs and agents");
    let group = hsm_generator
        .create_hsms(num_hsms, args.metrics, &mut process_group, &args.bigtable)
        .await;
    let (realm_id, group_id) = cluster::new_realm(&group).await.unwrap();
    info!(?realm_id, ?group_id, "initialized cluster");

    info!(clients = args.concurrency, "creating clients");
    let clients = (0..args.concurrency)
        .map(|i| {
            Arc::new(Mutex::new(Client::new(
                Configuration {
                    realms: vec![Realm {
                        address: load_balancer.clone(),
                        public_key: b"qwer".to_vec(),
                        id: realm_id,
                    }],
                    register_threshold: 1,
                    recover_threshold: 1,
                },
                AuthToken {
                    tenant: String::from("test"),
                    user: format!("mario{i}"),
                    signature: b"it's-a-me!".to_vec(),
                },
            )))
        })
        .collect::<Vec<_>>();

    info!("main: Running test register");
    clients[0]
        .lock()
        .await
        .register(
            &Pin(b"pin-test".to_vec()),
            &UserSecret(b"secret-test".to_vec()),
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
                    &Pin(format!("pin{i}").into_bytes()),
                    &UserSecret(format!("secret{i}").into_bytes()),
                    Policy { num_guesses: 2 },
                )
                .await
        }
    }))
    .buffer_unordered(args.concurrency);

    let mut completed = 0;
    while let Some(result) = stream.next().await {
        result.unwrap();
        completed += 1;
        debug!(completed, "ok");
    }

    let elapsed = start.elapsed().as_secs_f64();
    info!(
        recoveries = args.count,
        seconds = elapsed,
        recoveries_per_s = (args.count as f64) / elapsed,
        concurrency = args.concurrency,
        "completed benchmark"
    );

    info!("main: done");
    process_group.kill();
    logging::flush();
    info!("main: exiting");
}
