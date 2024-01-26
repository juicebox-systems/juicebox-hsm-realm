use once_cell::sync::Lazy;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

use cluster_api::{TransferError, TransferRequest};
use cluster_core::{
    get_hsm_statuses, new_group, perform_transfer, range_owners, wait_for_management_grant,
    ManagementLeaseKey, TransferChaos,
};
use hsm_api::{GroupId, LeaderStatus, OwnedRange, RecordId};
use juicebox_networking::reqwest::{self, ClientOptions};
use juicebox_process_group::ProcessGroup;
use juicebox_sdk::RealmId;
use retry_loop::{retry_logging_debug, RetryError};
use store::StoreClient;
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
        path_to_target: fs::canonicalize("..").unwrap(),
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

    let store = Arc::new(cluster.store);
    let r1 = OwnedRange {
        start: RecordId::min_id(),
        end: RecordId([12; 32]),
    };
    let r2 = OwnedRange {
        start: r1.end.next().unwrap(),
        end: RecordId([45; 32]),
    };
    let r3 = OwnedRange {
        start: r2.end.next().unwrap(),
        end: RecordId([99; 32]),
    };
    check_transfer_recovery(
        store.clone(),
        &client,
        &cluster.realms[0].agents,
        TransferChaos::StopAfterPrepare,
        realm,
        source,
        destination,
        r1,
    )
    .await;
    check_transfer_recovery(
        store.clone(),
        &client,
        &cluster.realms[0].agents,
        TransferChaos::StopAfterTransferOut,
        realm,
        source,
        destination,
        r2,
    )
    .await;
    check_transfer_recovery(
        store,
        &client,
        &cluster.realms[0].agents,
        TransferChaos::StopAfterTransferIn,
        realm,
        source,
        destination,
        r3,
    )
    .await;

    let status = get_hsm_statuses(
        &client,
        cluster.realms[0].agents.iter(),
        Some(Duration::from_secs(5)),
    )
    .await;

    assert!(range_owners(&status, realm, &OwnedRange::full()).is_some());

    processes.kill();
}

#[allow(clippy::too_many_arguments)]
async fn check_transfer_recovery(
    store: Arc<StoreClient>,
    client: &reqwest::Client,
    agents: &[Url],
    chaos: TransferChaos,
    realm: RealmId,
    source: GroupId,
    destination: GroupId,
    range: OwnedRange,
) {
    {
        let grant = wait_for_management_grant(
            store.clone(),
            String::from("test"),
            ManagementLeaseKey::Ownership(realm),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        assert!(matches!(
            perform_transfer(
                &store,
                client,
                &grant,
                Some(chaos),
                TransferRequest {
                    realm,
                    source,
                    destination,
                    range: range.clone(),
                },
            )
            .await,
            // Timeout is return when stopped short by the TransferChaos setting.
            Err(RetryError::Fatal {
                error: TransferError::Timeout
            })
        ));
    }

    // The above transfer stopped at some point before completion simulating a
    // coordinator crash. The cluster manager should spot this half completed
    // transfer and arrange for it to finish.

    let has_finished = |_| async {
        let s = cluster_core::get_hsm_statuses(client, agents.iter(), None).await;
        let leader_states: Vec<(GroupId, LeaderStatus)> = s
            .into_values()
            .filter_map(|(r, _)| r.realm)
            .flat_map(|rs| {
                rs.groups
                    .into_iter()
                    .filter_map(|gs| gs.leader.map(|l| (gs.id, l)))
            })
            .collect();

        let dest_has_range = leader_states.iter().any(|(group, ls)| {
            *group == destination
                && ls.transferring.is_none()
                && ls
                    .owned_range
                    .as_ref()
                    .is_some_and(|r| r.contains_range(&range))
        });

        let src_completed = leader_states
            .iter()
            .any(|(group, ls)| *group == source && ls.transferring.is_none());

        if dest_has_range && src_completed {
            Ok(())
        } else {
            Err(
                retry_loop::AttemptError::<NotMovedError, NotMovedError>::Retryable {
                    error: NotMovedError,
                    tags: vec![],
                },
            )
        }
    };
    assert!(
        retry_loop::Retry::new("check transfer completed")
            .with_timeout(Duration::from_secs(10))
            .with_exponential_backoff(Duration::from_millis(10), 1.05, Duration::from_millis(100))
            .retry(has_finished, retry_logging_debug!())
            .await
            .is_ok(),
        "timeout waiting for transfer to complete in after {chaos:?}"
    );
}

#[derive(Debug)]
struct NotMovedError;
