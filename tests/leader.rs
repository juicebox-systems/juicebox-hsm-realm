use once_cell::sync::Lazy;
use std::{path::PathBuf, sync::mpsc::channel};
use tokio::task::JoinSet;

use juicebox_hsm::{
    exec::{
        cluster_gen::{create_cluster, ClusterConfig, RealmConfig},
        hsm_gen::{Entrust, MetricsParticipants},
        PortIssuer,
    },
    process_group::ProcessGroup,
    realm::{
        cluster::{self, types::StepDownRequest},
        store::bigtable,
    },
};
use juicebox_sdk::Policy;
use juicebox_sdk_networking::reqwest::{self, ClientOptions};
use juicebox_sdk_networking::rpc;

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8333));

fn emulator() -> bigtable::Args {
    let u = format!("http://localhost:{}", PORT.next()).parse().unwrap();
    bigtable::Args {
        project: String::from("prj"),
        instance: String::from("inst"),
        url: Some(u),
    }
}

enum WorkerReq {
    Report,
    Shutdown,
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
    let mut tasks = JoinSet::new();

    tasks.spawn(async move {
        let mut success_count = 0;
        let mut failures = Vec::new();
        loop {
            match client
                .register(
                    &vec![1, 2, 3, 4].into(),
                    &b"bob".to_vec().into(),
                    &b"info".to_vec().into(),
                    Policy { num_guesses: 3 },
                )
                .await
            {
                Ok(_) => success_count += 1,
                Err(e) => failures.push(format!("{e:?}")),
            }

            match client
                .recover(&vec![1, 2, 3, 4].into(), &b"info".to_vec().into())
                .await
            {
                Ok(secret) if secret.expose_secret() == b"bob".to_vec() => success_count += 1,
                Ok(secret) => failures.push(format!(
                    "expected {:?} got {:?}",
                    b"bob".to_vec(),
                    secret.expose_secret()
                )),
                Err(e) => failures.push(format!("{e:?}")),
            }

            match rx.try_recv().unwrap() {
                WorkerReq::Report => {
                    res_tx.send((success_count, failures.split_off(0))).unwrap();
                }
                WorkerReq::Shutdown => {
                    res_tx.send((success_count, failures.split_off(0))).unwrap();
                    return;
                }
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

    let agents = reqwest::Client::new(ClientOptions::default());
    let cluster_realm = cluster.realms[0].realm;
    let cluster_group = cluster.realms[0].groups[1]; // first non-trivial group

    for _ in 1..10 {
        // Find out the current leader HSM and ask the cluster manager it have it stepdown.
        let leader1 = cluster::find_leaders(&cluster.store, &agents)
            .await
            .unwrap()
            .remove(&(cluster_realm, cluster_group));
        let Some((hsm_id1, _)) = leader1 else {
            panic!("leader1 was None");
        };

        rpc::send(
            &agents,
            &cluster.cluster_manager,
            StepDownRequest::Hsm(hsm_id1),
        )
        .await
        .unwrap();

        // See who the new leader is and make sure its a different HSM.
        let leader2 = cluster::find_leaders(&cluster.store, &agents)
            .await
            .unwrap()
            .remove(&(cluster_realm, cluster_group));
        let Some((hsm_id2, _)) = leader2 else {
            panic!("leader2 was None");
        };

        assert_ne!(hsm_id1, hsm_id2, "leader should have changed (1 to 2)");

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
        rpc::send(
            &agents,
            &cluster.cluster_manager,
            StepDownRequest::Group {
                realm: cluster_realm,
                group: cluster_group,
            },
        )
        .await
        .unwrap();

        // check that the leadership moved.
        let leader3 = cluster::find_leaders(&cluster.store, &agents)
            .await
            .unwrap()
            .remove(&(cluster_realm, cluster_group));
        let Some((hsm_id3, _)) = leader3 else {
            panic!("leader3 was None");
        };

        assert_ne!(hsm_id2, hsm_id3, "leader should have changed (2 to 3)");

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
