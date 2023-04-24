use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU16, Ordering},
        mpsc::{channel, Sender},
    },
};

use loam_mvp::{
    exec::{
        cluster_gen::{create_cluster, ClusterConfig, RealmConfig},
        hsm_gen::{Entrust, MetricsParticipants},
    },
    http_client::{self, ClientOptions},
    process_group::ProcessGroup,
    realm::{
        cluster::{self, types::StepdownAsLeaderRequest},
        store::bigtable::BigTableArgs,
    },
};
use loam_sdk::{Pin, Policy, UserSecret};
use loam_sdk_networking::rpc::{self};

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: AtomicU16 = AtomicU16::new(8333);

fn emulator() -> BigTableArgs {
    let u = format!("http://localhost:{}", PORT.fetch_add(1, Ordering::SeqCst))
        .parse()
        .unwrap();
    BigTableArgs {
        project: String::from("prj"),
        instance: String::from("inst"),
        url: Some(u),
    }
}

enum WorkerReq {
    Report,
    Shutdown,
}

struct TestWorkerGuard(Sender<WorkerReq>);
impl Drop for TestWorkerGuard {
    fn drop(&mut self) {
        // This can error if the worker was already shutdown
        let _ = self.0.send(WorkerReq::Shutdown);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn leader_handover() {
    let bt_args = emulator();
    let mut processes = ProcessGroup::new();

    let cluster_args = ClusterConfig {
        load_balancers: 1,
        realms: vec![RealmConfig {
            hsms: 3,
            groups: 1,
            metrics: MetricsParticipants::None,
            state_dir: None,
        }],
        bigtable: bt_args,
        secrets_file: Some(PathBuf::from("secrets-demo.json")),
        entrust: Entrust(false),
    };

    let cluster = create_cluster(cluster_args, &mut processes, 3000)
        .await
        .unwrap();

    let client = cluster.client_for_user(String::from("presso"));

    let (tx, rx) = channel();
    let (res_tx, res_rx) = channel();
    let _guard = TestWorkerGuard(tx.clone());

    tokio::spawn(async move {
        let mut success_count = 0;
        let mut failures = Vec::new();
        loop {
            match client
                .register(
                    &Pin(vec![1, 2, 3, 4]),
                    &UserSecret(b"bob".to_vec()),
                    Policy { num_guesses: 3 },
                )
                .await
            {
                Ok(_) => success_count += 1,
                Err(e) => failures.push(format!("{e:?}")),
            }

            match client.recover(&Pin(vec![1, 2, 3, 4])).await {
                Ok(secret) if secret.0 == b"bob".to_vec() => success_count += 1,
                Ok(secret) => {
                    failures.push(format!("expected {:?} got {:?}", b"bob".to_vec(), secret.0))
                }
                Err(e) => failures.push(format!("{e:?}")),
            }

            match rx.try_recv() {
                Ok(WorkerReq::Report) => {
                    res_tx.send((success_count, failures.split_off(0))).unwrap();
                }
                Ok(WorkerReq::Shutdown) => {
                    res_tx.send((success_count, failures.split_off(0))).unwrap();
                    return;
                }
                Err(_) => {}
            }
        }
    });

    // Wait til our background register/recover workers had made some requests.
    let mut success_count;
    let mut errors: Vec<String>;
    loop {
        tx.send(WorkerReq::Report).unwrap();
        (success_count, errors) = res_rx.recv().unwrap();
        assert_eq!(Vec::<String>::new(), errors, "client reported errors");
        if success_count > 3 {
            break;
        }
    }

    let agents = http_client::Client::new(ClientOptions::default());
    for _ in 1..10 {
        // Find out the current leader HSM and ask the cluster manager it have it stepdown.
        let leaders1 = cluster::find_leaders(&cluster.store, &agents)
            .await
            .unwrap();

        assert_eq!(1, leaders1.len());
        let (hsm_id1, _) = leaders1.values().next().unwrap();

        rpc::send(
            &agents,
            &cluster.cluster_manager,
            StepdownAsLeaderRequest::Hsm(*hsm_id1),
        )
        .await
        .unwrap();

        // See who the new leader is and make sure its a different HSM.
        let leaders2 = cluster::find_leaders(&cluster.store, &agents)
            .await
            .unwrap();

        assert_eq!(1, leaders2.len());
        let (hsm_id2, _) = leaders2.values().next().unwrap();
        assert_ne!(hsm_id1, hsm_id2);

        // make sure the background worker made some progress.
        let count_before_leader_change = success_count;
        loop {
            tx.send(WorkerReq::Report).unwrap();
            (success_count, errors) = res_rx.recv().unwrap();
            assert_eq!(Vec::<String>::new(), errors, "client reported errors");
            if success_count > 5 + count_before_leader_change {
                break;
            }
        }

        // Now ask for a stepdown based on the realm/group Id.
        let (realm, group) = leaders2.keys().next().unwrap();
        rpc::send(
            &agents,
            &cluster.cluster_manager,
            StepdownAsLeaderRequest::Group {
                realm: *realm,
                group: *group,
            },
        )
        .await
        .unwrap();

        // check that the leadership moved.
        let leaders3 = cluster::find_leaders(&cluster.store, &agents)
            .await
            .unwrap();

        assert_eq!(1, leaders3.len());
        let (hsm_id3, _) = leaders3.values().next().unwrap();
        assert_ne!(hsm_id2, hsm_id3);

        // check in on our background register/recover progress.
        let count_before_leader_change = success_count;
        loop {
            tx.send(WorkerReq::Report).unwrap();
            (success_count, errors) = res_rx.recv().unwrap();
            assert_eq!(Vec::<String>::new(), errors, "client reported errors");
            if success_count > 3 + count_before_leader_change {
                break;
            }
        }
    }

    // all done.
    tx.send(WorkerReq::Shutdown).unwrap();
    (_, errors) = res_rx.recv().unwrap();
    assert_eq!(Vec::<String>::new(), errors, "client reported errors");

    processes.kill();
}
