use actix::prelude::*;
use bitvec::prelude::*;
use futures::future::{join_all, try_join_all};
use std::iter;
use std::ops::RangeFrom;
use std::str::FromStr;
use tracing::{info, trace, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::FmtSubscriber;

mod client;
mod realm;
mod server;
mod types;

use client::{Client, Configuration, Pin, Realm, RecoverError, UserSecret};
use server::Server;
use types::{AuthToken, Policy};

use realm::hsm::types::{OwnedPrefix, RecordId, SecretsRequest, SecretsResponse};
use realm::hsm::{Hsm, RealmKey};
use realm::load_balancer::types::{ClientRequest, ClientResponse};
use realm::load_balancer::LoadBalancer;
use realm::store::Store;
use realm::{
    agent::{
        types::{TenantId, UserId},
        Agent,
    },
    merkle::KeyVec,
};

/// Creates HSMs and their agents.
///
/// This module exists to encapsulate the secret shared between the HSMs.
mod hsm_gen {
    use super::*;

    pub struct HsmGenerator {
        secret: RealmKey,
        counter: RangeFrom<usize>,
    }

    impl HsmGenerator {
        pub fn new() -> Self {
            Self {
                secret: RealmKey::random(),
                counter: 1..,
            }
        }

        pub fn create_hsm(&mut self, store: Addr<Store>) -> Addr<Agent> {
            let i = self.counter.next().unwrap();
            let hsm = Hsm::new(format!("hsm{i:02}"), self.secret.clone()).start();
            Agent::new(format!("agent{i:02}"), hsm, store).start()
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
    let subscriber = FmtSubscriber::builder()
        .with_file(true)
        .with_line_number(true)
        .with_max_level(log_level)
        .with_span_events(FmtSpan::ACTIVE)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    info!(
        max_level = %log_level,
        "set up tracing. you can set verbosity with env var LOGLEVEL."
    );

    info!("creating in-memory store");
    let store = Store::new().start();

    let num_load_balancers = 2;
    info!(count = num_load_balancers, "creating load balancers");
    let load_balancers: Vec<Addr<LoadBalancer>> = (1..=num_load_balancers)
        .map(|i| LoadBalancer::new(format!("lb{i}"), store.clone()).start())
        .collect();

    let mut hsm_generator = HsmGenerator::new();

    let num_hsms = 5;
    info!(count = num_hsms, "creating initial HSMs and agents");
    let group1: Vec<Addr<Agent>> = iter::repeat_with(|| hsm_generator.create_hsm(store.clone()))
        .take(num_hsms)
        .collect();
    let (realm_id, group_id1) = realm::cluster::new_realm(&group1).await.unwrap();
    info!(?realm_id, group_id = ?group_id1, "initialized cluster");

    info!("creating additional groups");
    let group2: Vec<Addr<Agent>> = iter::repeat_with(|| hsm_generator.create_hsm(store.clone()))
        .take(5)
        .collect();
    let group3: Vec<Addr<Agent>> = iter::repeat_with(|| hsm_generator.create_hsm(store.clone()))
        .take(4)
        .collect();
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
        OwnedPrefix(key_vec(&[1])),
        &store,
    )
    .await
    .unwrap();

    realm::cluster::transfer(
        realm_id,
        groups[1],
        groups[0],
        OwnedPrefix(key_vec(&[0, 0])),
        &store,
    )
    .await
    .unwrap();

    realm::cluster::transfer(
        realm_id,
        groups[2],
        groups[3],
        OwnedPrefix(key_vec(&[1, 1])),
        &store,
    )
    .await
    .unwrap();

    info!("incrementing a bunch");
    let tenant_id = TenantId(bitvec::bitvec![0, 1]);
    let rids: [RecordId; 4] = [
        (tenant_id.clone(), UserId(bitvec::bitvec![0, 0])).into(),
        (tenant_id.clone(), UserId(bitvec::bitvec![0, 1])).into(),
        (tenant_id.clone(), UserId(bitvec::bitvec![1, 0])).into(),
        (tenant_id, UserId(bitvec::bitvec![1, 1])).into(),
    ];
    join_all(
        iter::zip(rids.iter().cycle(), load_balancers.iter().cycle())
            .take(99 * rids.len())
            .map(|(rid, load_balancer)| async move {
                let result = load_balancer
                    .send(ClientRequest {
                        realm: realm_id,
                        rid: rid.clone(),
                        request: SecretsRequest::Increment,
                    })
                    .await
                    .unwrap();
                match result {
                    ClientResponse::Ok(SecretsResponse::Increment(new_value)) => {
                        trace!(?rid, new_value, "incremented")
                    }
                    ClientResponse::Unavailable => todo!(),
                }
            }),
    )
    .await;

    info!("reading counts after many parallel requests");
    join_all(rids.iter().map(|rid| {
        let load_balancer = load_balancers[0].clone();
        async move {
            let result = load_balancer
                .send(ClientRequest {
                    realm: realm_id,
                    rid: rid.clone(),
                    request: SecretsRequest::Increment,
                })
                .await
                .unwrap();
            match result {
                ClientResponse::Ok(SecretsResponse::Increment(new_value)) => {
                    info!(?rid, new_value, "incremented")
                }
                ClientResponse::Unavailable => todo!(),
            }
        }
    }))
    .await;

    println!("main: Starting 4 servers");
    let server1_addr = Server::new(String::from("server1")).start();
    let server2_addr = Server::new(String::from("server2")).start();
    let server3_addr = Server::new(String::from("server3")).start();
    let server4_addr = Server::new(String::from("dead-server4")).start();
    println!();

    let client = Client::new(
        Configuration {
            realms: vec![
                Realm {
                    address: server1_addr,
                    public_key: b"qwer".to_vec(),
                },
                Realm {
                    address: server2_addr,
                    public_key: b"asdf".to_vec(),
                },
                Realm {
                    address: server3_addr,
                    public_key: b"zxcv".to_vec(),
                },
                Realm {
                    address: server4_addr,
                    public_key: b"uiop".to_vec(),
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
            &Pin(b"1234".to_vec()),
            &UserSecret(b"teyla21".to_vec()),
            Policy { num_guesses: 2 },
        )
        .await
        .expect("register failed");
    println!("main: register succeeded");
    println!();

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

fn key_vec(bits: &[u8]) -> KeyVec {
    let mut v = KeyVec::with_capacity(bits.len());
    for b in bits {
        match b {
            0 => v.push(false),
            1 => v.push(true),
            _ => panic!("invalid bit value"),
        }
    }
    v
}
