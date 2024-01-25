use agent_api::{
    CancelPreparedTransferRequest, CancelPreparedTransferResponse, PrepareTransferRequest,
    PrepareTransferResponse,
};
use futures::future::join_all;
use futures::FutureExt;
use juicebox_networking::rpc;
use once_cell::sync::Lazy;
use std::iter::zip;
use std::path::PathBuf;

use cluster_api::TransferRequest;
use cluster_core::new_group;
use hsm_api::{GroupId, OwnedRange, RecordId};
use hsm_core::merkle::testing::rec_id;
use juicebox_networking::reqwest::{self, Client, ClientOptions};
use juicebox_process_group::ProcessGroup;
use juicebox_sdk::{Pin, Policy, UserInfo, UserSecret};
use testing::exec::bigtable::emulator;
use testing::exec::cluster_gen::{create_cluster, ClusterConfig, ClusterResult, RealmConfig};
use testing::exec::hsm_gen::Entrust;
use testing::exec::PortIssuer;

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8555));

#[tokio::test]
async fn transfer() {
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
    let agent_client = reqwest::Client::new(ClientOptions::default());
    split_merge_empty_cluster(&agent_client, &cluster).await;

    // do some registers
    let clients: Vec<_> = (0..50)
        .map(|i| {
            (
                cluster.client_for_user(format!("presso_{i}")),
                UserSecret::from(vec![4, 3, 2, 1, i]),
            )
        })
        .collect();
    let pin = Pin::from(vec![1, 2, 3, 4]);
    let user_info = UserInfo::from(b"presso".to_vec());
    join_all(clients.iter().map(|(client, secret)| {
        client.register(&pin, secret, &user_info, Policy { num_guesses: 5 })
    }))
    .await;

    // create some more groups.
    let group_ids: Vec<GroupId> =
        join_all((1..5).map(|_| new_group(&agent_client, realm, &cluster.realms[0].agents)))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

    // repartition across the new groups.
    let partitions =
        [(0x00, 0x3F), (0x40, 0x7F), (0x80, 0xBF), (0xC0, 0xFF)].map(|p| make_range(p.0, p.1));
    for (group, partition) in zip(&group_ids, &partitions) {
        rpc::send(
            &agent_client,
            &cluster.cluster_managers[0],
            TransferRequest {
                realm,
                source: *cluster.realms[0].groups.last().unwrap(),
                destination: *group,
                range: partition.clone(),
            },
        )
        .await
        .unwrap()
        .unwrap();
    }

    // do some recovers
    for (r, expected) in join_all(clients.iter().map(|(client, expected)| {
        client
            .recover(&pin, &user_info)
            .map(|result| (result, expected.clone()))
    }))
    .await
    {
        assert_eq!(r.unwrap().expose_secret(), expected.expose_secret());
    }
    // and deletes
    for r in join_all(clients.iter().map(|(client, _)| client.delete())).await {
        assert!(r.is_ok());
    }
    // do some registers again
    join_all(clients.iter().map(|(client, secret)| {
        client.register(&pin, secret, &user_info, Policy { num_guesses: 1 })
    }))
    .await;

    // merge some partitions back into larger ones
    rpc::send(
        &agent_client,
        &cluster.cluster_managers[0],
        TransferRequest {
            realm,
            source: group_ids[0],
            destination: group_ids[1],
            range: partitions[0].clone(),
        },
    )
    .await
    .unwrap()
    .unwrap();

    rpc::send(
        &agent_client,
        &cluster.cluster_managers[0],
        TransferRequest {
            realm,
            source: group_ids[3],
            destination: group_ids[2],
            range: partitions[3].clone(),
        },
    )
    .await
    .unwrap()
    .unwrap();

    // do some recovers
    for (r, expected) in join_all(clients.iter().map(|(client, expected)| {
        client
            .recover(&pin, &user_info)
            .map(|result| (result, expected.clone()))
    }))
    .await
    {
        assert_eq!(r.unwrap().expose_secret(), expected.expose_secret());
    }

    // prepare & then cancel a transfer out.
    let leader = cluster_core::find_leaders(&cluster.store, &agent_client)
        .await
        .unwrap()
        .get(&(cluster.realms[0].realm, group_ids[0]))
        .unwrap()
        .1
        .clone();

    assert!(matches!(
        rpc::send(
            &agent_client,
            &leader,
            PrepareTransferRequest {
                realm,
                source: group_ids[1],
                destination: group_ids[0],
                range: partitions[0].clone(),
            },
        )
        .await
        .unwrap(),
        PrepareTransferResponse::Ok { .. }
    ));
    assert!(matches!(
        rpc::send(
            &agent_client,
            &leader,
            CancelPreparedTransferRequest {
                realm,
                source: group_ids[1],
                destination: group_ids[0],
                range: partitions[0].clone(),
            },
        )
        .await
        .unwrap(),
        CancelPreparedTransferResponse::Ok
    ));

    // do some recovers
    for (r, expected) in join_all(clients.iter().map(|(client, expected)| {
        client
            .recover(&pin, &user_info)
            .map(|result| (result, expected.clone()))
    }))
    .await
    {
        assert_eq!(r.unwrap().expose_secret(), expected.expose_secret());
    }

    processes.kill();
}

async fn split_merge_empty_cluster(agent_client: &Client, cluster: &ClusterResult) {
    // create another group
    let new_group_id = new_group(
        agent_client,
        cluster.realms[0].realm,
        &cluster.realms[0].agents,
    )
    .await
    .unwrap();
    let src_group = cluster.realms[0].groups.last().copied().unwrap();
    // move some to the new group.
    rpc::send(
        agent_client,
        &cluster.cluster_managers[0],
        TransferRequest {
            realm: cluster.realms[0].realm,
            source: src_group,
            destination: new_group_id,
            range: OwnedRange {
                start: RecordId::min_id(),
                end: rec_id(&[5]),
            },
        },
    )
    .await
    .unwrap()
    .unwrap();

    // move part of it back.
    rpc::send(
        agent_client,
        &cluster.cluster_managers[0],
        TransferRequest {
            realm: cluster.realms[0].realm,
            source: new_group_id,
            destination: src_group,
            range: OwnedRange {
                start: rec_id(&[1]),
                end: rec_id(&[5]),
            },
        },
    )
    .await
    .unwrap()
    .unwrap();

    // move the rest of it back
    rpc::send(
        agent_client,
        &cluster.cluster_managers[0],
        TransferRequest {
            realm: cluster.realms[0].realm,
            source: new_group_id,
            destination: src_group,
            range: OwnedRange {
                start: RecordId::min_id(),
                end: rec_id(&[1]).prev().unwrap(),
            },
        },
    )
    .await
    .unwrap()
    .unwrap();
}

fn make_range(start: u8, end: u8) -> OwnedRange {
    let mut start_id = RecordId::min_id();
    start_id.0[0] = start;
    let mut end_id = RecordId::max_id();
    end_id.0[0] = end;
    OwnedRange {
        start: start_id,
        end: end_id,
    }
}
