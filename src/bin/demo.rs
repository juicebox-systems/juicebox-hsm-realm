use futures::future::{join_all, try_join_all};
use hsmcore::types::{AuthToken, Policy};
use http::Uri;
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::Url;
use std::fmt::Write;
use std::io;
use std::iter;
use std::net::SocketAddr;
use std::ops::RangeFrom;
use std::process::{Child, Command, ExitStatus};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

use hsmcore::hsm::types::{OwnedRange, RecordId};
use loam_mvp::client::{Client, Configuration, Pin, Realm, RecoverError, UserSecret};
use loam_mvp::http_client;
use loam_mvp::logging;
use loam_mvp::realm::agent::types::{AgentService, StatusRequest};
use loam_mvp::realm::cluster;
use loam_mvp::realm::store::bigtable;

type AgentClient = http_client::Client<AgentService>;

/// Creates HSMs and their agents.
///
/// This module exists to encapsulate the secret shared between the HSMs.
mod hsm_gen {
    use super::*;

    pub struct HsmGenerator {
        secret: String,
        port: RangeFrom<u16>,
    }

    impl HsmGenerator {
        pub(super) fn new(start_port: u16) -> Self {
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

        pub(super) async fn create_hsms(
            &mut self,
            count: usize,
            process_group: &mut ProcessGroup,
            bigtable: &Uri,
        ) -> Vec<Url> {
            let waits = iter::repeat_with(|| {
                let hsm_port = self.port.next().unwrap();
                let agent_port = self.port.next().unwrap();
                let hsm_address = SocketAddr::from(([127, 0, 0, 1], hsm_port));
                let hsm_url = Url::parse(&format!("http://{hsm_address}")).unwrap();
                process_group.spawn(
                    Command::new("target/debug/http_hsm")
                        .arg("--listen")
                        .arg(hsm_address.to_string())
                        .arg("--key")
                        .arg(&self.secret),
                );
                let agent_address = SocketAddr::from(([127, 0, 0, 1], agent_port)).to_string();
                let agent_url = Url::parse(&format!("http://{agent_address}")).unwrap();
                process_group.spawn(
                    Command::new("target/debug/agent")
                        .arg("--listen")
                        .arg(agent_address)
                        .arg("--bigtable")
                        .arg(bigtable.to_string())
                        .arg("--hsm")
                        .arg(hsm_url.to_string()),
                );

                // Wait for the agent to be up, which in turn waits for the HSM
                // to be up.
                //
                // TODO: we shouldn't wait here. Other code needs to handle
                // failures, since servers can go down at any later point.
                let agents = AgentClient::new();
                async move {
                    for attempt in 1.. {
                        if let Ok(response) = agents.send(&agent_url, StatusRequest {}).await {
                            if response.hsm.is_some() {
                                break;
                            }
                        }
                        if attempt >= 1000 {
                            panic!("Failed to connect to agent/HSM at {agent_url}");
                        }
                        sleep(Duration::from_millis(1)).await;
                    }
                    agent_url
                }
            })
            .take(count);
            join_all(waits).await
        }
    }
}
use hsm_gen::HsmGenerator;

#[tokio::main]
async fn main() {
    logging::configure();

    let mut process_group = ProcessGroup::new();

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
                Command::new("target/debug/load_balancer")
                    .arg("--listen")
                    .arg(address.to_string())
                    .arg("--bigtable")
                    .arg(bigtable.to_string()),
            );
            Url::parse(&format!("http://{address}")).unwrap()
        })
        .collect();

    let mut hsm_generator = HsmGenerator::new(4000);

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
        let mut hsm_generator = HsmGenerator::new(start_port);
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

    process_group.kill();
    println!("main: exiting");
}

#[derive(Clone)]
struct ProcessGroup(Arc<Mutex<Vec<ProcessKiller>>>);

impl ProcessGroup {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }

    fn spawn(&mut self, command: &mut Command) {
        match command.spawn() {
            Ok(child) => self.0.lock().unwrap().push(ProcessKiller(child)),
            Err(e) => panic!("failed to spawn command: {e}"),
        }
    }

    fn kill(&mut self) {
        let children = self.0.lock().unwrap().split_off(0);
        info!("waiting for {} child processes to exit", children.len());
        for mut child in children {
            if let Err(e) = child.kill() {
                warn!(?e, "failed to kill child process");
            }
        }
    }
}

struct ProcessKiller(Child);

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
