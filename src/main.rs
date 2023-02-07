use actix::prelude::*;
use bitvec::prelude::*;
use futures::future::{join_all, try_join_all};
use reqwest::Url;
use std::iter;
use std::net::SocketAddr;
use std::ops::RangeFrom;
use std::str::FromStr;
use tracing::{info, Level};
use tracing_subscriber::filter::FilterFn;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::FmtSubscriber;

mod client;
mod realm;
mod types;

use client::{Client, Configuration, Pin, Realm, RecoverError, UserSecret};
use realm::agent::Agent;
use realm::hsm::types::{OwnedPrefix, RealmId};
use realm::hsm::{Hsm, RealmKey};
use realm::load_balancer::LoadBalancer;
use realm::store::Store;
use types::{AuthToken, Policy};

/// Creates HSMs and their agents.
///
/// This module exists to encapsulate the secret shared between the HSMs.
mod hsm_gen {
    use super::*;

    pub struct HsmGenerator {
        secret: RealmKey,
        port: RangeFrom<u16>,
    }

    impl HsmGenerator {
        pub fn new(start_port: u16) -> Self {
            Self {
                secret: RealmKey::random(),
                port: start_port..,
            }
        }

        pub async fn create_hsms(&mut self, count: usize, store: &Addr<Store>) -> Vec<Url> {
            let listens = iter::repeat_with(|| {
                let port = self.port.next().unwrap();
                let hsm = Hsm::new(format!("hsm{port}"), self.secret.clone()).start();
                let agent = Agent::new(format!("agent{port}"), hsm, store.clone());
                let address = SocketAddr::from(([127, 0, 0, 1], port));
                async move {
                    let result = agent.listen(address).await;
                    result.map(|(url, _)| url)
                }
            })
            .take(count);
            try_join_all(listens).await.expect("TODO")
        }
    }
}
use hsm_gen::HsmGenerator;

#[actix_rt::main]
async fn main() {
    let log_level = std::env::var("LOGLEVEL")
        .map(|s| match Level::from_str(&s) {
            Ok(level) => level,
            Err(e) => panic!("failed to parse LOGLEVEL: {e}"),
        })
        .unwrap_or(Level::DEBUG);
    // Quiet down `hyper`.
    let filter = FilterFn::new(|metadata| {
        if let Some(module) = metadata.module_path() {
            if module.starts_with("hyper::") {
                return false;
            }
        }
        true
    });
    let subscriber = FmtSubscriber::builder()
        .with_file(true)
        .with_line_number(true)
        .with_max_level(log_level)
        .with_span_events(FmtSpan::ACTIVE)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber.with(filter)).unwrap();
    info!(
        max_level = %log_level,
        "set up tracing. you can set verbosity with env var LOGLEVEL."
    );

    info!("creating in-memory store");
    let store = Store::new().start();

    let num_load_balancers = 2;
    info!(count = num_load_balancers, "creating load balancers");
    let load_balancers: Vec<Url> = join_all((1..=num_load_balancers).map(|i| {
        let address = SocketAddr::from(([127, 0, 0, 1], 3000 + i));
        let lb = LoadBalancer::new(format!("lb{i}"), store.clone());
        async move {
            let (url, _) = lb.listen(address).await.expect("TODO");
            url
        }
    }))
    .await;

    let mut hsm_generator = HsmGenerator::new(4000);

    let num_hsms = 5;
    info!(count = num_hsms, "creating initial HSMs and agents");
    let group1: Vec<Url> = hsm_generator.create_hsms(num_hsms, &store).await;
    let (realm_id, group_id1) = realm::cluster::new_realm(&group1).await.unwrap();
    info!(?realm_id, group_id = ?group_id1, "initialized cluster");

    info!("creating additional groups");
    let group2: Vec<Url> = hsm_generator.create_hsms(5, &store).await;
    let group3: Vec<Url> = hsm_generator.create_hsms(4, &store).await;

    let mut groups = try_join_all([
        realm::cluster::new_group(realm_id, &group2),
        realm::cluster::new_group(realm_id, &group3),
        realm::cluster::new_group(realm_id, &group1),
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
    realm::cluster::transfer(realm_id, groups[0], groups[1], OwnedPrefix::full(), &store)
        .await
        .unwrap();

    info!("growing the cluster to 4 partitions");
    realm::cluster::transfer(
        realm_id,
        groups[1],
        groups[2],
        OwnedPrefix(bitvec![u8, Msb0; 1]),
        &store,
    )
    .await
    .unwrap();

    realm::cluster::transfer(
        realm_id,
        groups[1],
        groups[0],
        OwnedPrefix(bitvec![u8, Msb0; 0,0]),
        &store,
    )
    .await
    .unwrap();

    realm::cluster::transfer(
        realm_id,
        groups[2],
        groups[3],
        OwnedPrefix(bitvec![u8, Msb0; 1, 1]),
        &store,
    )
    .await
    .unwrap();

    info!("creating additional realms");
    let mut realm_ids: Vec<RealmId> = join_all([5000, 6000, 7000].map(|start_port| {
        let mut hsm_generator = HsmGenerator::new(start_port);
        let store = store.clone();
        async move {
            let agents = hsm_generator.create_hsms(num_hsms, &store).await;
            realm::cluster::new_realm(&agents).await.unwrap().0
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
            user: String::from("mario"),
            signature: String::from("it's-a-me!"),
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

    println!("main: exiting");
    System::current().stop();
}
