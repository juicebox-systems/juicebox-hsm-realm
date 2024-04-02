use futures::future::join_all;
use futures::FutureExt;
use juicebox_marshalling::to_be4;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use agent_api::StatusRequest;
use hsm_api::{
    GroupId, GroupStatus, HsmId, LeaderStatus, LogIndex, OwnedRange, RecordId, StatusResponse,
};
use jburl::Url;
use juicebox_networking::http;
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc::{self, RpcError, SendOptions};
use juicebox_realm_api::types::RealmId;
use retry_loop::{retry_logging_debug, AttemptError, RetryError};
use store::{Lease, LeaseKey, LeaseType, ServiceKind, StoreClient};

mod assimilate;
mod leader;
mod realm;
mod transfer;
pub mod workload;

pub use assimilate::{assimilate, AssimilateError};
pub use leader::{discover_hsm_ids, find_leaders, hsm_ids};
pub use realm::{join_realm, new_group, new_realm, JoinRealmError, NewGroupError, NewRealmError};
pub use transfer::{
    perform_transfer, plan_transfers, plan_transfers_range, TransferChaos, TransferError,
    TransferRequest, TransferStep,
};

const LEASE_DURATION: Duration = Duration::from_secs(3);

/// When drop'd will remove the lease from the store.
pub struct ManagementGrant {
    key: ManagementLeaseKey,
    inner: Option<ManagementGrantInner>,
}

struct ManagementGrantInner {
    store: StoreClient,
    lease: Lease,
    renewer: JoinHandle<()>,
}

impl ManagementGrant {
    /// Takes a lease out for some management operation that should block
    /// conflicting management operations.
    ///
    /// Returns None if the lease has already been taken by some other task.
    /// When the returned `ManagementGrant` is dropped, the lease will be
    /// terminated.
    ///
    /// The grant uses a lease managed by the bigtable store. The grant applies
    /// across all cluster managers using the same store, not just this
    /// instance.
    pub async fn obtain(
        store: StoreClient,
        owner: String,
        key: ManagementLeaseKey,
    ) -> Result<Option<Self>, RetryError<tonic::Status>> {
        Ok(store
            .obtain_lease(key.clone(), owner, LEASE_DURATION, SystemTime::now())
            .await?
            .map(|lease| {
                info!(?key, "obtained lease for active management");
                ManagementGrant::new(store, key, lease)
            }))
    }

    fn new(store: StoreClient, key: ManagementLeaseKey, lease: Lease) -> Self {
        let store2 = store.clone();
        let lease2 = lease.clone();
        // This task gets aborted when the ManagementGrant is dropped.
        let renewer = tokio::spawn(async move {
            let mut lease = lease2;
            loop {
                sleep(LEASE_DURATION / 3).await;
                let now = SystemTime::now();
                let expires = lease.until();
                lease = tokio::select! {
                    result = store2
                    .extend_lease(lease, LEASE_DURATION, now) => result.expect("failed to extend lease"),
                    _ = sleep(expires.duration_since(now).unwrap()) => panic!("didn't renew lease in time")
                }
            }
        });
        ManagementGrant {
            key,
            inner: Some(ManagementGrantInner {
                store,
                lease,
                renewer,
            }),
        }
    }
}

impl Drop for ManagementGrant {
    fn drop(&mut self) {
        let inner = self.inner.take().unwrap();
        info!(
            key = ?self.key,
            "management task completed. dropping lease"
        );
        inner.renewer.abort();
        tokio::spawn(async move {
            _ = inner.renewer.await;
            if let Err(err) = inner.store.terminate_lease(inner.lease).await {
                warn!(?err, "gRPC error while trying to terminate lease");
            }
        });
    }
}

#[derive(Debug)]
pub enum WaitForGrantError {
    Timeout,
    Rpc(RetryError<tonic::Status>),
}

// Waits for up to 'timeout' to try and obtain the specified management grant.
pub async fn wait_for_management_grant(
    store: StoreClient,
    owner: String,
    key: ManagementLeaseKey,
    timeout: Duration,
) -> Result<ManagementGrant, WaitForGrantError> {
    retry_loop::Retry::new("get/wait for management grant")
        .with_timeout(timeout)
        .with_exponential_backoff(Duration::from_millis(10), 2.0, Duration::from_millis(100))
        .retry(
            |_| async {
                match ManagementGrant::obtain(store.clone(), owner.clone(), key.clone()).await {
                    Ok(Some(grant)) => Ok(grant),
                    Ok(None) => Err(AttemptError::Retryable {
                        error: WaitForGrantError::Timeout,
                        tags: vec![],
                    }),
                    Err(err) => Err(AttemptError::Fatal {
                        // the store already retried errors getting the lease.
                        error: WaitForGrantError::Rpc(err),
                        tags: Vec::new(),
                    }),
                }
            },
            retry_logging_debug!(),
        )
        .await
        .map_err(|e| e.last().unwrap_or(WaitForGrantError::Timeout))
}

#[derive(Clone, Debug)]
pub enum ManagementLeaseKey {
    RealmGroup(RealmId, GroupId),
    Ownership(RealmId),
}

impl From<ManagementLeaseKey> for LeaseKey {
    fn from(value: ManagementLeaseKey) -> Self {
        let k = match value {
            ManagementLeaseKey::RealmGroup(r, g) => format!("{r:?}-{g:?}"),
            ManagementLeaseKey::Ownership(r) => format!("{r:?}-ownership"),
        };
        LeaseKey(LeaseType::ClusterManagement, k)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Tonic/gRPC error: {0}")]
    Grpc(#[from] RetryError<tonic::Status>),
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),
}

async fn wait_for_commit(
    leader: &Url,
    realm: RealmId,
    group_id: GroupId,
    agent_client: &Client,
) -> Result<(), RpcError> {
    debug!(?realm, group = ?group_id, "waiting for first log entry to commit");
    // TODO: replace ad hoc retry loop with retry_loop::Retry
    loop {
        let status = rpc::send(agent_client, leader, StatusRequest {}).await?;
        let Some(hsm) = status.hsm else { continue };
        let Some(realm_status) = hsm.realm else {
            continue;
        };
        if realm_status.id != realm {
            continue;
        }
        let group_status = realm_status
            .groups
            .iter()
            .find(|group_status| group_status.id == group_id);
        if let Some(GroupStatus {
            leader:
                Some(LeaderStatus {
                    committed: Some(committed),
                    ..
                }),
            ..
        }) = group_status
        {
            if *committed >= LogIndex::FIRST {
                info!(?realm, group = ?group_id, ?committed, "first log entry committed");
                return Ok(());
            }
        }

        sleep(Duration::from_millis(1)).await;
    }
}

pub type HsmStatuses = HashMap<HsmId, (hsm_api::StatusResponse, Url)>;

pub async fn discover_hsm_statuses(
    store: &StoreClient,
    client: &impl http::Client,
) -> Result<HsmStatuses, RetryError<tonic::Status>> {
    let addresses = store.get_addresses(Some(ServiceKind::Agent)).await?;
    Ok(get_hsm_statuses(
        client,
        addresses.iter().map(|(url, _)| url),
        Some(Duration::from_secs(5)),
    )
    .await)
}

pub async fn get_hsm_statuses(
    agents: &impl http::Client,
    agent_urls: impl Iterator<Item = &Url>,
    timeout: Option<Duration>,
) -> HsmStatuses {
    join_all(agent_urls.map(|url| {
        rpc::send_with_options(
            agents,
            url,
            StatusRequest {},
            SendOptions {
                timeout,
                ..SendOptions::default()
            },
        )
        .map(|r| (r, url.clone()))
    }))
    .await
    .into_iter()
    .filter_map(|(r, url)| r.ok().and_then(|s| s.hsm).map(|s| (s.id, (s, url))))
    .collect()
}

pub fn find_leader(status: &HsmStatuses, realm: RealmId, group: GroupId) -> Option<(HsmId, Url)> {
    for (hsm, (status, url)) in status {
        if let Some(rs) = &status.realm {
            if rs.id == realm {
                for gs in &rs.groups {
                    if gs.leader.is_some() && gs.id == group {
                        return Some((*hsm, url.clone()));
                    }
                }
            }
        }
    }
    None
}

// Extracts the range owners from the provided StatusRequest results and returns
// the set of owners that cover `range_to_check`. If `range_to_check` is not
// fully covered None is returned. This is used to help verify ownership of all
// or a subset of the recordId range during transfer recovery.
pub fn range_owners<'a>(
    hsm_status: impl Iterator<Item = &'a StatusResponse>,
    realm: RealmId,
    range_to_check: &OwnedRange,
) -> Option<Vec<(GroupId, OwnedRange)>> {
    let ranges: Vec<(GroupId, OwnedRange)> = hsm_status
        .filter_map(|s| s.realm.as_ref())
        .filter(|rs| rs.id == realm)
        .flat_map(|rs| rs.groups.iter())
        .filter_map(|gs| {
            gs.leader
                .as_ref()
                .and_then(|ls| ls.owned_range.as_ref().map(|r| (gs.id, r.clone())))
        })
        .collect();
    verify_range_owners(ranges, range_to_check)
}

// If the provided set of range owners fully cover the `range_to_check`, then
// the range owners that own part of `range_to_check` are returned. If
// `range_to_check` is not fully covered, then None is returned.
//
// This is broken out to simplify testing.
fn verify_range_owners(
    mut owners: Vec<(GroupId, OwnedRange)>,
    range_to_check: &OwnedRange,
) -> Option<Vec<(GroupId, OwnedRange)>> {
    owners.retain(|(_, r)| range_to_check.overlaps(r));
    owners.sort_by(|a, b| a.1.start.cmp(&b.1.start));

    if owners.first()?.1.start <= range_to_check.start
        && owners.last()?.1.end >= range_to_check.end
        && owners
            .windows(2)
            .all(|pair| pair[0].1.end.next() == Some(pair[1].1.start.clone()))
    {
        Some(owners)
    } else {
        None
    }
}

pub fn partition_evenly(n: usize) -> Vec<OwnedRange> {
    // It's difficult to divide a 256-bit space into even ranges using only
    // 64-bit integers. This divides a 32-bit space instead and gets close
    // enough for our purposes. Dividing 2^32 by n is better than dividing
    // (2^64-1) by n because it gets the exact results you'd expect when n is a
    // small power of two.
    if n > 1_000_000 {
        unimplemented!("no guarantees here");
    }
    let n = u64::try_from(n).unwrap();
    let partition_size = 2u64.pow(32) / n;

    (0..n)
        .map(|i| {
            let start = RecordId::min_id().with(&to_be4(partition_size * i));
            let mut end = RecordId::max_id();
            if i + 1 < n {
                end = end.with(&to_be4(partition_size * (i + 1) - 1));
            }
            OwnedRange { start, end }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use expect_test::expect;
    use hsm_api::{GroupId, OwnedRange, RecordId};
    use std::fmt::Write;

    #[test]
    fn test_partition_evenly_full_coverage() {
        for i in [1, 2, 3, 15, 32, 108] {
            let mut last: Option<RecordId> = None;
            for range in partition_evenly(i) {
                let next = match &last {
                    None => RecordId::min_id(),
                    Some(id) => id.next().unwrap(),
                };
                assert_eq!(range.start, next);
                assert!(range.end >= range.start);
                last = Some(range.end);
            }
            assert_eq!(last, Some(RecordId::max_id()));
        }
    }

    #[test]
    fn test_partition_evenly_snapshot() {
        let mut buf = String::new();
        for i in 1..10 {
            writeln!(buf, "partition_evenly({i}):").unwrap();
            for range in partition_evenly(i) {
                writeln!(buf, "  {}", &range).unwrap();
            }
        }

        expect![[r#"
            partition_evenly(1):
              [0x00...-0xff...]
            partition_evenly(2):
              [0x00...-0x7fff...]
              [0x8000...-0xff...]
            partition_evenly(3):
              [0x00...-0x55555554ff...]
              [0x5555555500...-0xaaaaaaa9ff...]
              [0xaaaaaaaa00...-0xff...]
            partition_evenly(4):
              [0x00...-0x3fff...]
              [0x4000...-0x7fff...]
              [0x8000...-0xbfff...]
              [0xc000...-0xff...]
            partition_evenly(5):
              [0x00...-0x33333332ff...]
              [0x3333333300...-0x66666665ff...]
              [0x6666666600...-0x99999998ff...]
              [0x9999999900...-0xcccccccbff...]
              [0xcccccccc00...-0xff...]
            partition_evenly(6):
              [0x00...-0x2aaaaaa9ff...]
              [0x2aaaaaaa00...-0x55555553ff...]
              [0x5555555400...-0x7ffffffdff...]
              [0x7ffffffe00...-0xaaaaaaa7ff...]
              [0xaaaaaaa800...-0xd5555551ff...]
              [0xd555555200...-0xff...]
            partition_evenly(7):
              [0x00...-0x24924923ff...]
              [0x2492492400...-0x49249247ff...]
              [0x4924924800...-0x6db6db6bff...]
              [0x6db6db6c00...-0x9249248fff...]
              [0x9249249000...-0xb6db6db3ff...]
              [0xb6db6db400...-0xdb6db6d7ff...]
              [0xdb6db6d800...-0xff...]
            partition_evenly(8):
              [0x00...-0x1fff...]
              [0x2000...-0x3fff...]
              [0x4000...-0x5fff...]
              [0x6000...-0x7fff...]
              [0x8000...-0x9fff...]
              [0xa000...-0xbfff...]
              [0xc000...-0xdfff...]
              [0xe000...-0xff...]
            partition_evenly(9):
              [0x00...-0x1c71c71bff...]
              [0x1c71c71c00...-0x38e38e37ff...]
              [0x38e38e3800...-0x55555553ff...]
              [0x5555555400...-0x71c71c6fff...]
              [0x71c71c7000...-0x8e38e38bff...]
              [0x8e38e38c00...-0xaaaaaaa7ff...]
              [0xaaaaaaa800...-0xc71c71c3ff...]
              [0xc71c71c400...-0xe38e38dfff...]
              [0xe38e38e000...-0xff...]
        "#]]
        .assert_eq(&buf);
    }

    #[test]
    fn lease_key() {
        let lk = ManagementLeaseKey::RealmGroup(RealmId([9; 16]), GroupId([3; 16]));
        let k: LeaseKey = lk.into();
        assert_eq!(LeaseType::ClusterManagement, k.0);
        assert_eq!(
            "09090909090909090909090909090909-03030303030303030303030303030303".to_string(),
            k.1
        );
    }

    #[test]
    fn test_verify_range_owners() {
        let gids: Vec<GroupId> = (0..3).map(|i| GroupId([i; 16])).collect();

        assert!(
            verify_range_owners(vec![(gids[0], OwnedRange::full())], &OwnedRange::full()).is_some()
        );
        assert!(
            verify_range_owners(vec![(gids[0], OwnedRange::full())], &mkrange(0, 15)).is_some()
        );
        assert!(
            verify_range_owners(vec![(gids[0], OwnedRange::full())], &mkrange(0xfe, 0xff))
                .is_some()
        );
        assert!(verify_range_owners(
            vec![(gids[0], mkrange(0, 15)), (gids[1], mkrange(16, 0xff))],
            &OwnedRange::full()
        )
        .is_some());
        // input not in order
        assert!(verify_range_owners(
            vec![
                (gids[0], mkrange(11, 15)),
                (gids[1], mkrange(0, 10)),
                (gids[2], mkrange(16, 0xff))
            ],
            &OwnedRange::full()
        )
        .is_some());
        // hole in range, but not in the range we're checking
        assert!(verify_range_owners(
            vec![
                (gids[0], mkrange(11, 15)),
                (gids[1], mkrange(0, 9)),
                (gids[2], mkrange(16, 0xff))
            ],
            &mkrange(12, 22)
        )
        .is_some());

        assert!(verify_range_owners(
            vec![(gids[0], mkrange(1, 15)), (gids[1], mkrange(16, 0xff))],
            &OwnedRange::full()
        )
        .is_none());
        assert!(verify_range_owners(
            vec![(gids[0], mkrange(0, 15)), (gids[1], mkrange(16, 0xfe))],
            &OwnedRange::full()
        )
        .is_none());
        assert!(verify_range_owners(
            vec![(gids[0], mkrange(0, 15)), (gids[1], mkrange(17, 0xff))],
            &OwnedRange::full()
        )
        .is_none());
        assert!(verify_range_owners(
            vec![
                (gids[0], mkrange(11, 15)),
                (gids[1], mkrange(0, 9)),
                (gids[2], mkrange(16, 0xff))
            ],
            &OwnedRange::full()
        )
        .is_none());
        assert!(verify_range_owners(
            vec![
                (gids[0], mkrange(11, 15)),
                (gids[1], mkrange(0, 9)),
                (gids[2], mkrange(16, 0xff))
            ],
            &mkrange(5, 13)
        )
        .is_none());
    }

    fn mkrange(s: u8, e: u8) -> OwnedRange {
        let start = RecordId::min_id().with(&[s]);
        let end = RecordId::max_id().with(&[e]);
        OwnedRange { start, end }
    }
}
