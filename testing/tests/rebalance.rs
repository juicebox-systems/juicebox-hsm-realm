use once_cell::sync::Lazy;
use std::path::PathBuf;
use std::time::Duration;
use testing::background::{BackgroundClientRequests, WorkerReq};

use cluster_api::{RebalanceRequest, RebalanceResponse};
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
async fn cluster_rebalance() {
    let bt_args = emulator(PORT.next());
    let mut processes = ProcessGroup::new();

    let cluster_args = ClusterConfig {
        load_balancers: 1,
        cluster_managers: 1,
        realms: vec![RealmConfig {
            hsms: 5,
            groups: 5,
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

    let cluster_client = reqwest::Client::new(ClientOptions::default());
    let mut cluster_manager = cluster.cluster_managers.iter().cycle();

    // All the groups were created on one HSM, and it is the leader for all of them.
    // There's a total of 6 groups, the initial realm creation group and the 5 additional
    // groups. We can rebalance these from [6,0,0,0,0] to [2,1,1,1,1] in 4 steps.
    for _ in 0..4 {
        // make sure the background worker made some progress.
        background_work
            .wait_for_progress(5, Duration::from_secs(15))
            .await;

        // Ask the cluster manager to rebalance the cluster. This will perform one leadership move.
        let rebalance = rpc::send(
            &cluster_client,
            cluster_manager.next().unwrap(),
            RebalanceRequest {},
        )
        .await;
        assert!(
            matches!(rebalance, Ok(RebalanceResponse::Rebalanced(_))),
            "{:?}",
            rebalance
        );
    }

    // At this point its as balanced as it can be
    let rebalance = rpc::send(
        &cluster_client,
        cluster_manager.next().unwrap(),
        RebalanceRequest {},
    )
    .await;
    assert_eq!(rebalance, Ok(RebalanceResponse::AlreadyBalanced));

    // all done.
    let p = background_work.progress(WorkerReq::Shutdown).await;
    assert_eq!(Vec::<String>::new(), p.errors, "client reported errors");

    processes.kill();
}
