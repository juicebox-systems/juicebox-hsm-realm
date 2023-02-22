use futures::future::{join_all, try_join_all};
use hsmcore::types::{AuthToken, Policy};
use http::Uri;
use reqwest::Url;
use std::net::SocketAddr;
use std::ops::RangeFrom;
use std::process::{Child, ExitStatus};
use std::{io, iter};
use tracing::{info, warn};

use hsmcore::hsm::types::{OwnedRange, RecordId};
use loam_mvp::client::{Client, Configuration, Pin, Realm, RecoverError, UserSecret};
use loam_mvp::logging;
use loam_mvp::realm;
use loam_mvp::realm::agent::Agent;
use loam_mvp::realm::hsm::http::client::HsmHttpClient;
use loam_mvp::realm::load_balancer::LoadBalancer;
use loam_mvp::realm::store::bigtable;

/// Creates HSMs and their agents.
///
/// This module exists to encapsulate the secret shared between the HSMs.
mod hsm_gen {
    use std::{fmt::Write, process::Command, time::Duration};

    use hsmcore::hsm::types::StatusRequest;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use reqwest::Url;

    use super::*;

    pub struct HsmGenerator {
        secret: String,
        port: RangeFrom<u16>,
    }

    impl HsmGenerator {
        pub fn new(start_port: u16) -> Self {
            let mut v = vec![0; 32];
            OsRng.fill_bytes(&mut v);
            let mut buf = String::new();
            for byte in v {
                write!(buf, "{byte:02x}").unwrap();
            }
            Self {
                secret: buf,
                port: start_port..,
            }
        }

        pub async fn create_hsms(
            &mut self,
            count: usize,
            store: &bigtable::StoreClient,
            store_admin: &bigtable::StoreAdminClient,
        ) -> (Vec<Url>, Vec<ProcessKiller>) {
            let listens = iter::repeat_with(|| {
                let hsm_port = self.port.next().unwrap();
                let agent_port = self.port.next().unwrap();
                let hsm_child = Command::new("target/debug/http_hsm")
                    .args([
                        "--listen",
                        &SocketAddr::from(([127, 0, 0, 1], hsm_port)).to_string(),
                        "--key",
                        &self.secret,
                    ])
                    .spawn()
                    .expect("TODO!");
                let hsm_url = Url::parse(&format!("http://127.0.0.1:{hsm_port}")).unwrap();
                async move {
                    let hsm = HsmHttpClient::new_client(hsm_url);
                    // wait for the HSM to be up.
                    for _tries in 0..10 {
                        if hsm.send(StatusRequest {}).await.is_ok() {
                            break;
                        } else {
                            tokio::time::sleep(Duration::from_millis(2)).await;
                            continue;
                        }
                    }
                    let agent = Agent::new(
                        format!("agent{agent_port}"),
                        hsm,
                        store.clone(),
                        store_admin.clone(),
                    );
                    let address = SocketAddr::from(([127, 0, 0, 1], agent_port));
                    let result = agent.listen(address).await;
                    result.map(|(url, _)| (url, ProcessKiller(hsm_child)))
                }
            })
            .take(count);
            try_join_all(listens)
                .await
                .expect("TODO")
                .into_iter()
                .unzip()
        }
    }
}
use hsm_gen::HsmGenerator;

#[tokio::main]
async fn main() {
    logging::configure();

    info!("connecting to Bigtable");
    let instance = bigtable::Instance {
        project: String::from("prj"),
        instance: String::from("inst"),
    };
    let store =
        bigtable::StoreClient::new(Uri::from_static("http://localhost:9000"), instance.clone())
            .await
            .expect("TODO");
    let store_admin = bigtable::StoreAdminClient::new(
        Uri::from_static("http://localhost:9000"),
        instance.clone(),
    )
    .await
    .expect("TODO");

    info!("initializing service discovery table");
    store_admin.initialize_discovery().await.expect("TODO");

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
    let (group1, mut child_processes) = hsm_generator
        .create_hsms(num_hsms, &store, &store_admin)
        .await;
    let (realm_id, group_id1) = realm::cluster::new_realm(&group1).await.unwrap();
    info!(?realm_id, group_id = ?group_id1, "initialized cluster");

    info!("creating additional groups");
    let (group2, group2_children) = hsm_generator.create_hsms(5, &store, &store_admin).await;
    let (group3, group3_children) = hsm_generator.create_hsms(4, &store, &store_admin).await;
    child_processes.extend(group2_children);
    child_processes.extend(group3_children);

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
    realm::cluster::transfer(realm_id, groups[0], groups[1], OwnedRange::full(), &store)
        .await
        .unwrap();

    info!("growing the cluster to 4 partitions");
    realm::cluster::transfer(
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

    realm::cluster::transfer(
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

    realm::cluster::transfer(
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
    realm::cluster::transfer(
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
    let (mut realm_ids, realm_processes): (Vec<_>, Vec<_>) =
        join_all([5000, 6000, 7000].map(|start_port| {
            let mut hsm_generator = HsmGenerator::new(start_port);
            let store = store.clone();
            let store_admin = store_admin.clone();
            async move {
                let agents = hsm_generator
                    .create_hsms(num_hsms, &store, &store_admin)
                    .await;
                (
                    realm::cluster::new_realm(&agents.0).await.unwrap().0,
                    agents.1,
                )
            }
        }))
        .await
        .into_iter()
        .unzip();
    child_processes.extend(realm_processes.into_iter().flatten());
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
    println!(
        "waiting for {} child processes to exit",
        child_processes.len()
    );
    for mut cp in child_processes.into_iter() {
        if let Err(e) = cp.kill() {
            warn!(?e, "failed to kill child process");
        }
    }

    println!("main: exiting");
}

pub struct ProcessKiller(Child);

impl ProcessKiller {
    fn kill(&mut self) -> io::Result<ExitStatus> {
        self.0.kill()?;
        self.0.wait()
    }
}
impl Drop for ProcessKiller {
    fn drop(&mut self) {
        // Err is deliberately ignored.
        if self.kill().is_err() {};
    }
}
