use clap::Parser;
use futures::future::{join_all, try_join_all};
use http::Uri;
use loam_sdk_core::types::AuthToken;
use reqwest::Url;

use std::env::current_dir;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use tracing::info;

use hsmcore::hsm::types::{OwnedRange, RecordId};
use loam_mvp::logging;
use loam_mvp::process_group::ProcessGroup;
use loam_mvp::realm::cluster;
use loam_mvp::realm::store::bigtable::{BigTableArgs, BigTableRunner};
use loam_sdk::{Configuration, Realm};

mod common;
use common::certs::create_localhost_key_and_cert;
use common::hsm_gen::{Entrust, HsmGenerator, MetricsParticipants};

#[derive(Parser)]
#[command(
    about = "A tool to launch all the loam services and execute a demo binary configured to access them"
)]
struct Args {
    /// Path to the demo binary to execute
    #[arg(long)]
    demo: PathBuf,
}

#[tokio::main]
async fn main() {
    logging::configure("loam-demo-runner");

    let args = Args::parse();

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

    let bt_args = BigTableArgs {
        inst: String::from("inst"),
        project: String::from("prj"),
        url: Some(Uri::from_static("http://localhost:9000")),
    };

    info!("starting bigtable emulator");

    let (store_admin, store) = BigTableRunner::run(&mut process_group, &bt_args).await;

    info!("initializing service discovery table");
    store_admin.initialize_discovery().await.expect("TODO");

    let certificates = create_localhost_key_and_cert(current_dir().unwrap().join("target"))
        .expect("Failed to create TLS key/cert for load balancer");

    let num_load_balancers = 2;
    info!(count = num_load_balancers, "creating load balancers");
    let load_balancers: Vec<Url> = (1..=num_load_balancers)
        .map(|i| {
            let address = SocketAddr::from(([127, 0, 0, 1], 3000 + i));
            let mut cmd = Command::new(format!(
                "target/{}/load_balancer",
                if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                }
            ));
            cmd.arg("--tls-cert")
                .arg(certificates.cert_file_pem.clone())
                .arg("--tls-key")
                .arg(certificates.key_file_pem.clone())
                .arg("--listen")
                .arg(address.to_string());
            bt_args.add_to_cmd(&mut cmd);
            process_group.spawn(&mut cmd);
            Url::parse(&format!("https://localhost:{}", address.port())).unwrap()
        })
        .collect();

    let mut hsm_generator = HsmGenerator::new(Entrust(false), 4000);

    let num_hsms = 5;
    info!(count = num_hsms, "creating initial HSMs and agents");
    let group1 = hsm_generator
        .create_hsms(
            num_hsms,
            MetricsParticipants::None,
            &mut process_group,
            &bt_args,
        )
        .await;
    let (realm_id, group_id1) = cluster::new_realm(&group1).await.unwrap();
    info!(?realm_id, group_id = ?group_id1, "initialized cluster");
    let realm1_public_key = hsm_generator.public_communication_key();

    info!("creating additional groups");
    let group2 = hsm_generator
        .create_hsms(5, MetricsParticipants::None, &mut process_group, &bt_args)
        .await;
    let group3 = hsm_generator
        .create_hsms(4, MetricsParticipants::None, &mut process_group, &bt_args)
        .await;

    let mut groups = try_join_all([
        cluster::new_group(realm_id, &group2),
        cluster::new_group(realm_id, &group3),
        cluster::new_group(realm_id, &group1),
    ])
    .await
    .unwrap();
    info!(?realm_id, new_groups = ?groups, "created groups");

    groups.insert(0, group_id1);
    info!(
        source = ?groups[0],
        destination = ?groups[1],
        "transferring ownership of entire uid-space"
    );
    cluster::transfer(realm_id, groups[0], groups[1], OwnedRange::full(), &store)
        .await
        .unwrap();

    info!("growing the cluster to 4 partitions");
    cluster::transfer(
        realm_id,
        groups[1],
        groups[2],
        OwnedRange {
            start: RecordId::min_id(),
            end: RecordId([0x80; 32]),
        },
        &store,
    )
    .await
    .unwrap();

    cluster::transfer(
        realm_id,
        groups[1],
        groups[0],
        OwnedRange {
            start: RecordId([0x80; 32]).next().unwrap(),
            end: RecordId([0xA0; 32]),
        },
        &store,
    )
    .await
    .unwrap();

    cluster::transfer(
        realm_id,
        groups[2],
        groups[3],
        OwnedRange {
            start: RecordId([0x40; 32]),
            end: RecordId([0x80; 32]),
        },
        &store,
    )
    .await
    .unwrap();

    // moving part of a partition to another group.
    cluster::transfer(
        realm_id,
        groups[2],
        groups[3],
        OwnedRange {
            start: RecordId([0x30; 32]),
            end: RecordId([0x40; 32]).prev().unwrap(),
        },
        &store,
    )
    .await
    .unwrap();

    info!("creating additional realms");
    let mut realms = join_all([5000, 6000, 7000].map(|start_port| {
        let mut hsm_generator = HsmGenerator::new(Entrust(false), start_port);
        let mut process_group = process_group.clone();
        let bigtable = bt_args.clone();
        async move {
            let agents = hsm_generator
                .create_hsms(
                    num_hsms,
                    MetricsParticipants::None,
                    &mut process_group,
                    &bigtable,
                )
                .await;
            let realm_id = cluster::new_realm(&agents).await.unwrap().0;
            let public_key = hsm_generator.public_communication_key();
            (realm_id, public_key)
        }
    }))
    .await;
    realms.push((realm_id, realm1_public_key));

    let mut lb = load_balancers.iter().cycle();
    let configuration = Configuration {
        realms: realms
            .into_iter()
            .map(|(id, public_key)| Realm {
                address: lb.next().unwrap().clone(),
                id,
                public_key,
            })
            .collect(),
        register_threshold: 3,
        recover_threshold: 3,
    };

    let auth_token = AuthToken {
        tenant: String::from("test"),
        user: String::from("mario"),
        signature: b"it's-a-me!".to_vec(),
    };

    info!(pid = std::process::id(), "runner: executing demo");

    Command::new(args.demo)
        .arg("--tls-certificate")
        .arg(certificates.cert_file_der.clone())
        .arg("--configuration")
        .arg(serde_json::to_string(&configuration).unwrap())
        .arg("--auth-token")
        .arg(serde_json::to_string(&auth_token).unwrap())
        .status()
        .expect("Couldn't run demo executable");

    info!(pid = std::process::id(), "runner: done");
    process_group.kill();
    logging::flush();
    info!(pid = std::process::id(), "runner: exiting");
}
