use cluster_core::{JoinRealmError, NewRealmError};
use juicebox_sdk::RealmId;
use once_cell::sync::Lazy;
use std::path::PathBuf;
use testing::exec::bigtable::emulator;

use juicebox_sdk_networking::reqwest::{self, ClientOptions};
use juicebox_sdk_process_group::ProcessGroup;
use testing::exec::cluster_gen::{create_cluster, ClusterConfig, RealmConfig};
use testing::exec::hsm_gen::{Entrust, MetricsParticipants};
use testing::exec::PortIssuer;

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8666));

#[tokio::test]
async fn realm() {
    let bt_args = emulator(PORT.next());
    let mut processes = ProcessGroup::new();

    let cluster_args = ClusterConfig {
        load_balancers: 1,
        realms: vec![RealmConfig {
            hsms: 3,
            groups: 1,
            metrics: MetricsParticipants::All,
            state_dir: None,
        }],
        bigtable: bt_args,
        secrets_file: Some(PathBuf::from("../secrets-demo.json")),
        entrust: Entrust(false),
        path_to_target: PathBuf::from(".."),
    };

    let cluster = create_cluster(cluster_args, &mut processes, PORT.clone())
        .await
        .unwrap();

    // create_cluster put all the agents in a realm, so we shouldn't be able to
    // new_realm or join_realm them to something else.
    let agent_client = reqwest::Client::new(ClientOptions::default());
    for agent in &cluster.realms[0].agents {
        let r = cluster_core::new_realm(&agent_client, agent).await;
        assert_eq!(Err(NewRealmError::HaveRealm), r);
    }
    let agents = cluster.realms[0].agents.clone();
    let r =
        cluster_core::join_realm(&agent_client, RealmId([42; 16]), &agents[1..], &agents[0]).await;
    assert!(matches!(r, Err(JoinRealmError::InvalidRealm { agent: _ })));

    // can join the realm we're already in
    let r = cluster_core::join_realm(
        &agent_client,
        cluster.realms[0].realm,
        &agents[1..],
        &agents[0],
    )
    .await;
    assert!(r.is_ok());

    processes.kill();
}
