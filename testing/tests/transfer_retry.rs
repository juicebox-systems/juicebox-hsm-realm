use agent_api::{PrepareTransferResponse, TransferOutResponse};
use cluster_api::TransferRequest;
use juicebox_networking::rpc;
use observability::metrics;
use once_cell::sync::Lazy;
use std::path::PathBuf;

use cluster_core::new_group;
use hsm_api::{OwnedRange, RecordId};
use juicebox_networking::reqwest::{self, ClientOptions};
use juicebox_process_group::ProcessGroup;
use testing::exec::bigtable::emulator;
use testing::exec::cluster_gen::{create_cluster, ClusterConfig, RealmConfig};
use testing::exec::hsm_gen::Entrust;
use testing::exec::PortIssuer;

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8555));

#[tokio::test]
async fn transfer_retry() {
    let bt_args = emulator(PORT.next());
    let mut processes = ProcessGroup::new();

    let cluster_args = ClusterConfig {
        load_balancers: 1,
        cluster_managers: 1,
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

    let cluster = create_cluster(cluster_args, &mut processes, PORT.clone())
        .await
        .unwrap();

    let realm = cluster.realms[0].realm;
    let client = reqwest::Client::new(ClientOptions::default());

    let destination = new_group(&client, realm, &cluster.realms[0].agents)
        .await
        .unwrap();
    let source = *cluster.realms[0].groups.last().unwrap();
    println!("source: {source:?} dest: {destination:?}");
    let leaders = cluster_core::find_leaders(&cluster.store, &client)
        .await
        .unwrap();
    let src_leader = leaders.get(&(realm, source)).unwrap();
    let dest_leader = leaders.get(&(realm, destination)).unwrap();
    let range = OwnedRange {
        start: RecordId::min_id(),
        end: RecordId([42; 32]),
    };
    let (nonce, prepared_statement) = match rpc::send(
        &client,
        &dest_leader.1,
        agent_api::PrepareTransferRequest {
            realm,
            source,
            destination,
            range: range.clone(),
        },
    )
    .await
    .unwrap()
    {
        PrepareTransferResponse::Ok { nonce, statement } => (nonce, statement),
        other => panic!("prepare transfer failed {other:?}"),
    };

    match rpc::send(
        &client,
        &src_leader.1,
        agent_api::TransferOutRequest {
            realm,
            source,
            destination,
            range: range.clone(),
            nonce,
            statement: prepared_statement,
        },
    )
    .await
    .unwrap()
    {
        TransferOutResponse::Ok {
            transferring,
            statement,
        } => (transferring, statement),
        other => panic!("transfer out failed {other:?}"),
    };

    // At this point the transfer coordinator crashes. The transfer should be
    // recoverable by running through all the steps again, even though some of
    // them are already done.
    assert!(cluster_core::transfer(
        &cluster.store,
        metrics::Client::NONE,
        TransferRequest {
            realm,
            source,
            destination,
            range
        }
    )
    .await
    .is_ok());

    processes.kill();
}
