use futures::future::{join_all, try_join_all};
use hsmcore::types::{AuthToken, Policy};
use http::Uri;
use reqwest::Url;
use std::net::SocketAddr;
use std::process::Command;
use tracing::info;

use hsmcore::hsm::types::{OwnedRange, RecordId};
use loam_mvp::client::{Client, Configuration, Pin, Realm, RecoverError, UserSecret};
use loam_mvp::logging;
use loam_mvp::realm::cluster;
use loam_mvp::realm::store::bigtable;

mod common;
use common::hsm_gen::{Entrust, HsmGenerator};
use common::process_group::ProcessGroup;

#[tokio::main]
async fn main() {
    logging::configure("loam-demo");

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

    let bigtable = Uri::from_static("http://localhost:9000");
    info!(url = %bigtable, "connecting to Bigtable");
    let instance = bigtable::Instance {
        project: String::from("prj"),
        instance: String::from("inst"),
    };
    let store = bigtable::StoreClient::new(bigtable.clone(), instance.clone())
        .await
        .unwrap_or_else(|e| panic!("Unable to connect to Bigtable at `{bigtable}`: {e}"));
    let store_admin = bigtable::StoreAdminClient::new(bigtable.clone(), instance.clone())
        .await
        .unwrap_or_else(|e| panic!("Unable to connect to Bigtable admin at `{bigtable}`: {e}"));

    info!("initializing service discovery table");
    store_admin.initialize_discovery().await.expect("TODO");

    let num_load_balancers = 2;
    info!(count = num_load_balancers, "creating load balancers");
    let load_balancers: Vec<Url> = (1..=num_load_balancers)
        .map(|i| {
            let address = SocketAddr::from(([127, 0, 0, 1], 3000 + i));
            process_group.spawn(
                Command::new(format!(
                    "target/{}/load_balancer",
                    if cfg!(debug_assertions) {
                        "debug"
                    } else {
                        "release"
                    }
                ))
                .arg("--listen")
                .arg(address.to_string())
                .arg("--bigtable")
                .arg(bigtable.to_string()),
            );
            Url::parse(&format!("http://{address}")).unwrap()
        })
        .collect();

    let mut hsm_generator = HsmGenerator::new(Entrust(false), 4000);

    let num_hsms = 5;
    info!(count = num_hsms, "creating initial HSMs and agents");
    let group1 = hsm_generator
        .create_hsms(num_hsms, &mut process_group, &bigtable)
        .await;
    let (realm_id, group_id1) = cluster::new_realm(&group1).await.unwrap();
    info!(?realm_id, group_id = ?group_id1, "initialized cluster");

    info!("creating additional groups");
    let group2 = hsm_generator
        .create_hsms(5, &mut process_group, &bigtable)
        .await;
    let group3 = hsm_generator
        .create_hsms(4, &mut process_group, &bigtable)
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
    let mut realm_ids = join_all([5000, 6000, 7000].map(|start_port| {
        let mut hsm_generator = HsmGenerator::new(Entrust(false), start_port);
        let mut process_group = process_group.clone();
        let bigtable = bigtable.clone();
        async move {
            let agents = hsm_generator
                .create_hsms(num_hsms, &mut process_group, &bigtable)
                .await;
            cluster::new_realm(&agents).await.unwrap().0
        }
    }))
    .await;
    realm_ids.push(realm_id);

    let mut lb = load_balancers.iter().cycle();
    let client = Client::new(
        Configuration {
            realms: vec![
                Realm {
                    address: lb.next().unwrap().clone(),
                    public_key: b"qwer".to_vec(),
                    id: realm_ids[0],
                },
                Realm {
                    address: lb.next().unwrap().clone(),
                    public_key: b"asdf".to_vec(),
                    id: realm_ids[1],
                },
                Realm {
                    address: lb.next().unwrap().clone(),
                    public_key: b"zxcv".to_vec(),
                    id: realm_ids[2],
                },
                Realm {
                    address: lb.next().unwrap().clone(),
                    public_key: b"uiop".to_vec(),
                    id: realm_ids[3],
                },
            ],
            register_threshold: 3,
            recover_threshold: 3,
        },
        AuthToken {
            tenant: String::from("test"),
            user: String::from("mario"),
            signature: b"it's-a-me!".to_vec(),
        },
    );

    println!("main: Starting register (allowing 2 guesses)");
    client
        .register(
            &Pin(b"1234".to_vec()),
            &UserSecret(b"teyla21".to_vec()),
            Policy { num_guesses: 2 },
        )
        .await
        .expect("register failed");
    println!("main: register succeeded");
    println!();

    println!("main: Starting recover with wrong PIN (guess 1)");
    match client.recover(&Pin(b"1212".to_vec())).await {
        Err(RecoverError::Unsuccessful(_)) => { /* ok */ }
        result => panic!("Unexpected result from recover: {result:?}"),
    };
    println!();

    println!("main: Starting recover with correct PIN (guess 2)");
    let secret = client
        .recover(&Pin(b"1234".to_vec()))
        .await
        .expect("recover failed");
    println!(
        "main: Recovered secret {:?}",
        String::from_utf8_lossy(&secret.0)
    );
    println!();

    println!("main: Starting recover with wrong PIN (guess 1)");
    match client.recover(&Pin(b"1212".to_vec())).await {
        Err(RecoverError::Unsuccessful(_)) => { /* ok */ }
        result => panic!("Unexpected result from recover: {result:?}"),
    };
    println!();

    println!("main: Starting recover with wrong PIN (guess 2)");
    match client.recover(&Pin(b"1212".to_vec())).await {
        Err(RecoverError::Unsuccessful(_)) => { /* ok */ }
        result => panic!("Unexpected result from recover: {result:?}"),
    };
    println!();

    println!("main: Starting recover with correct PIN (guess 3)");
    match client.recover(&Pin(b"1234".to_vec())).await {
        Err(RecoverError::Unsuccessful(_)) => { /* ok */ }
        result => panic!("Unexpected result from recover: {result:?}"),
    };
    println!();

    println!("main: Starting register");
    client
        .register(
            &Pin(b"4321".to_vec()),
            &UserSecret(b"presso42".to_vec()),
            Policy { num_guesses: 2 },
        )
        .await
        .expect("register failed");
    println!("main: register succeeded");
    println!();

    println!("main: Starting recover with correct PIN (guess 1)");
    let secret = client
        .recover(&Pin(b"4321".to_vec()))
        .await
        .expect("recover failed");
    println!(
        "main: Recovered secret {:?}",
        String::from_utf8_lossy(&secret.0)
    );

    println!("main: Deleting secret");
    match client.delete_all().await {
        Ok(()) => {
            println!("main: delete succeeded");
        }
        Err(e) => {
            println!("main: warning: delete failed: {e:?}");
        }
    }
    println!();

    info!(pid = std::process::id(), "main: done");
    process_group.kill();
    logging::flush();
    info!(pid = std::process::id(), "main: exiting");
}
