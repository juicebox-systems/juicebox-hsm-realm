use google::bigtable::v2::read_rows_request::RequestStatsView;
use google::bigtable::v2::ReadRowsRequest;
use google::GrpcConnectionOptions;
use once_cell::sync::Lazy;
use std::fs;
use std::panic;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;

use bigtable::read::{Cell, Reader};
use bigtable::{new_data_client, BigtableClient, Instance, NoWarmup};
use hsm_api::RecordId;
use juicebox_process_group::ProcessGroup;
use juicebox_sdk::{Pin, Policy, RealmId, UserInfo, UserSecret};
use observability::metrics;
use retry_loop::Retry;
use store::tenants::tenant_user_table;
use testing::exec::bigtable::emulator;
use testing::exec::cluster_gen::{create_cluster, ClusterConfig, RealmConfig};
use testing::exec::hsm_gen::Entrust;
use testing::exec::PortIssuer;

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8666));

#[tokio::test]
async fn user_accounting() {
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
        bigtable: bt_args.clone(),
        local_pubsub: true,
        secrets_file: Some(PathBuf::from("../secrets-demo.json")),
        entrust: Entrust(false),
        path_to_target: fs::canonicalize("..").unwrap(),
    };

    let cluster = create_cluster(cluster_args, &mut processes, PORT.clone())
        .await
        .unwrap();

    let client = cluster.client_for_user("bob");
    client
        .register(
            &Pin::from(vec![1, 2, 3, 4]),
            &UserSecret::from(b"secret".to_vec()),
            &UserInfo::from(vec![]),
            Policy { num_guesses: 42 },
        )
        .await
        .unwrap();

    // There should be one row in the -users table with a single cell indicating a secret was registered.
    let inst = Instance {
        project: bt_args.project,
        instance: bt_args.instance,
    };
    let bt_client = new_data_client(
        inst.clone(),
        bt_args.url.unwrap(),
        None,
        GrpcConnectionOptions::default(),
        metrics::Client::NONE,
        NoWarmup,
    )
    .await
    .unwrap();

    // The writing to the users table is done by a background task, so we might get to trying to read it before its been written.
    let mut users = Vec::new();
    for _tries in 0..10 {
        users = read_realm_users(&bt_client, &inst, &cluster.realms[0].realm).await;
        if users.is_empty() {
            sleep(Duration::from_millis(10)).await;
            continue;
        }
        break;
    }

    assert_eq!(1, users.len());
    assert_eq!(cluster.tenant, users[0].0);
    assert_eq!(1, users[0].2.len());
    let e = &users[0].2[0];
    assert_eq!(vec![1], e.value);
    assert_eq!(b"e".to_vec(), e.qualifier);
    assert_eq!("f".to_string(), e.family);
    let bob_id = users[0].1.clone();

    client.delete().await.unwrap();
    // If a client calls delete when they had no secret to start with, that shouldn't write anything
    let client = cluster.client_for_user("alice");
    client.delete().await.unwrap();

    // There should be one row in the -users table with 1 cell indicating that
    // bob's secret was deleted. (we only store the last event for a given day)
    for tries in 0..10 {
        let users = read_realm_users(&bt_client, &inst, &cluster.realms[0].realm).await;
        let r = panic::catch_unwind(|| {
            assert_eq!(1, users.len());
            assert_eq!(cluster.tenant, users[0].0);
            assert_eq!(1, users[0].2.len());
            let e = &users[0].2[0];
            assert_eq!(vec![0], e.value);
            assert_eq!(b"e".to_vec(), e.qualifier);
            assert_eq!("f".to_string(), e.family);
            assert_eq!(bob_id, users[0].1);
        });
        if let Err(err) = r {
            if tries >= 9 {
                panic::resume_unwind(err);
            } else {
                sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

async fn read_realm_users(
    bigtable: &BigtableClient,
    instance: &Instance,
    realm: &RealmId,
) -> Vec<(String, RecordId, Vec<Cell>)> {
    let read_req = ReadRowsRequest {
        table_name: tenant_user_table(instance, realm),
        app_profile_id: String::new(),
        rows: None,
        filter: None,
        rows_limit: 0,
        request_stats_view: RequestStatsView::RequestStatsNone.into(),
        reversed: false,
    };
    let mut bigtable = bigtable.clone();
    let rows = Reader::read_rows(&mut bigtable, Retry::disabled(), read_req)
        .await
        .unwrap();
    rows.into_iter()
        .map(|(key, cells)| {
            let p = key.0.len() - RecordId::NUM_BYTES * 2;
            (
                String::from_utf8(key.0[..p - 1].to_vec()).unwrap(),
                RecordId(hex::decode(&key.0[p..]).unwrap().try_into().unwrap()),
                cells,
            )
        })
        .collect()
}
