use once_cell::sync::Lazy;
use std::path::PathBuf;
use std::time::Duration;
use testing::background::{BackgroundClientRequests, WorkerReq};

use cluster_api::StepDownRequest;
use juicebox_networking::reqwest::{self, ClientOptions};
use juicebox_networking::rpc;
use juicebox_process_group::ProcessGroup;
use testing::exec::bigtable::emulator;
use testing::exec::cluster_gen::{create_cluster, ClusterConfig, RealmConfig};
use testing::exec::hsm_gen::Entrust;
use testing::exec::PortIssuer;

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8333));

#[tokio::test(flavor = "multi_thread")]
async fn leader_handover() {
    let bt_args = emulator(PORT.next());
    let mut processes = ProcessGroup::new();

    let cluster_args = ClusterConfig {
        load_balancers: 1,
        cluster_managers: 2,
        realms: vec![RealmConfig {
            hsms: 3,
            groups: 1,
            state_dir: None,
        }],
        bigtable: bt_args,
        local_pubsub: true,
        secrets_file: Some(PathBuf::from("../secrets-demo.json")),
        entrust: Entrust(false),
        path_to_target: PathBuf::from(".."),
    };

    let cluster = create_cluster(cluster_args, &mut processes, 3000)
        .await
        .unwrap();

    let client = cluster.client_for_user(String::from("presso"));
    let mut background_work = BackgroundClientRequests::spawn(client).await;

    // Wait til our background register/recover workers had made some requests.
    background_work
        .wait_for_progress(3, Duration::from_secs(5))
        .await;

    let agents = reqwest::Client::new(ClientOptions::default());
    let cluster_realm = cluster.realms[0].realm;
    let cluster_group = cluster.realms[0].groups[1]; // first non-trivial group
    let mut cluster_manager = cluster.cluster_managers.iter().cycle();

    for _ in 1..10 {
        // Find out the current leader HSM and ask the cluster manager it have it stepdown.
        let leader1 = cluster_core::find_leaders(&cluster.store, &agents)
            .await
            .unwrap()
            .remove(&(cluster_realm, cluster_group));
        let Some((hsm_id1, _)) = leader1 else {
            panic!("leader1 was None");
        };

        rpc::send(
            &agents,
            cluster_manager.next().unwrap(),
            StepDownRequest::Hsm(hsm_id1),
        )
        .await
        .unwrap();

        // See who the new leader is and make sure its a different HSM.
        let leader2 = cluster_core::find_leaders(&cluster.store, &agents)
            .await
            .unwrap()
            .remove(&(cluster_realm, cluster_group));
        let Some((hsm_id2, _)) = leader2 else {
            panic!("leader2 was None");
        };

        assert_ne!(hsm_id1, hsm_id2, "leader should have changed (1 to 2)");

        // make sure the background worker made some progress.
        background_work
            .wait_for_progress(5, Duration::from_secs(15))
            .await;

        // Now ask for a stepdown based on the realm/group Id.
        rpc::send(
            &agents,
            cluster_manager.next().unwrap(),
            StepDownRequest::Group {
                realm: cluster_realm,
                group: cluster_group,
            },
        )
        .await
        .unwrap();

        // check that the leadership moved.
        let leader3 = cluster_core::find_leaders(&cluster.store, &agents)
            .await
            .unwrap()
            .remove(&(cluster_realm, cluster_group));
        let Some((hsm_id3, _)) = leader3 else {
            panic!("leader3 was None");
        };

        assert_ne!(hsm_id2, hsm_id3, "leader should have changed (2 to 3)");

        // check in on our background register/recover progress.
        background_work
            .wait_for_progress(3, Duration::from_secs(15))
            .await;
    }

    // all done.
    let p = background_work.progress(WorkerReq::Shutdown).await;
    assert_eq!(Vec::<String>::new(), p.errors, "client reported errors");

    processes.kill();
}
