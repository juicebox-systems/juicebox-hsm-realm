use futures::future::join_all;
use futures::FutureExt;
use juicebox_networking::http;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, info, warn};
use url::Url;

use agent_api::StatusRequest;
use hsm_api::{GroupId, GroupStatus, HsmId, LeaderStatus, LogIndex, OwnedRange};
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc::{self, RpcError, SendOptions};
use juicebox_realm_api::types::RealmId;
use retry_loop::{retry_logging_debug, AttemptError, RetryError};
use store::{Lease, LeaseKey, LeaseType, StoreClient};

mod leader;
mod realm;
mod transfer;
pub mod workload;

pub use leader::{discover_hsm_ids, find_leaders};
pub use realm::{join_realm, new_group, new_realm, JoinRealmError, NewGroupError, NewRealmError};
pub use transfer::{perform_transfer, transfer, TransferChaos, TransferError, TransferRequest};

const LEASE_DURATION: Duration = Duration::from_secs(3);

/// When drop'd will remove the lease from the store.
pub struct ManagementGrant {
    key: ManagementLeaseKey,
    inner: Option<ManagementGrantInner>,
}

struct ManagementGrantInner {
    store: Arc<StoreClient>,
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
        store: Arc<StoreClient>,
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

    fn new(store: Arc<StoreClient>, key: ManagementLeaseKey, lease: Lease) -> Self {
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
    store: Arc<StoreClient>,
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

pub type HsmsStatus = HashMap<HsmId, (hsm_api::StatusResponse, Url)>;

pub async fn get_hsm_statuses(
    agents: &impl http::Client,
    agent_urls: impl Iterator<Item = &Url>,
    timeout: Option<Duration>,
) -> HsmsStatus {
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

pub fn find_leader(status: &HsmsStatus, realm: RealmId, group: GroupId) -> Option<(HsmId, Url)> {
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
// fully covered None is returned.
pub fn range_owners(
    hsm_status: &HsmsStatus,
    realm: RealmId,
    range_to_check: &OwnedRange,
) -> Option<Vec<(GroupId, OwnedRange)>> {
    let ranges: Vec<(GroupId, OwnedRange)> = hsm_status
        .values()
        .filter_map(|(s, _)| s.realm.as_ref())
        .filter(|rs| rs.id == realm)
        .flat_map(|rs| rs.groups.iter())
        .filter_map(|gs| {
            gs.leader
                .as_ref()
                .and_then(|ls| ls.owned_range.as_ref().map(|r| (gs.id, r.clone())))
        })
        .collect();
    range_is_covered(ranges, range_to_check)
}

// If the provided set of range owners fully cover the `range_to_check`, then
// the range owners that own part of `range_to_check` are returned. If
// `range_to_check` is not fully covered, then None is returned.
//
// This is broken out to simplify testing.
fn range_is_covered(
    mut owners: Vec<(GroupId, OwnedRange)>,
    range_to_check: &OwnedRange,
) -> Option<Vec<(GroupId, OwnedRange)>> {
    owners.retain(|(_, r)| range_to_check.overlaps(r));
    owners.sort_by(|a, b| a.1.start.cmp(&b.1.start));

    if !owners.is_empty()
        && owners
            .windows(2)
            .all(|pair| pair[0].1.end.next() == Some(pair[1].1.start.clone()))
        && owners[0].1.start <= range_to_check.start
        && owners.last().unwrap().1.end >= range_to_check.end
    {
        Some(owners)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hsm_api::{GroupId, OwnedRange, RecordId};

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
    fn test_range_is_covered() {
        let gids: Vec<GroupId> = (0..3).map(|i| GroupId([i; 16])).collect();

        assert!(
            range_is_covered(vec![(gids[0], OwnedRange::full())], &OwnedRange::full()).is_some()
        );
        assert!(range_is_covered(vec![(gids[0], OwnedRange::full())], &mkrange(0, 15)).is_some());
        assert!(
            range_is_covered(vec![(gids[0], OwnedRange::full())], &mkrange(0xfe, 0xff)).is_some()
        );
        assert!(range_is_covered(
            vec![(gids[0], mkrange(0, 15)), (gids[1], mkrange(16, 0xff))],
            &OwnedRange::full()
        )
        .is_some());
        // input not in order
        assert!(range_is_covered(
            vec![
                (gids[0], mkrange(11, 15)),
                (gids[1], mkrange(0, 10)),
                (gids[2], mkrange(16, 0xff))
            ],
            &OwnedRange::full()
        )
        .is_some());
        // hole in range, but not in the range we're checking
        assert!(range_is_covered(
            vec![
                (gids[0], mkrange(11, 15)),
                (gids[1], mkrange(0, 9)),
                (gids[2], mkrange(16, 0xff))
            ],
            &mkrange(12, 22)
        )
        .is_some());

        assert!(range_is_covered(
            vec![(gids[0], mkrange(1, 15)), (gids[1], mkrange(16, 0xff))],
            &OwnedRange::full()
        )
        .is_none());
        assert!(range_is_covered(
            vec![(gids[0], mkrange(0, 15)), (gids[1], mkrange(16, 0xfe))],
            &OwnedRange::full()
        )
        .is_none());
        assert!(range_is_covered(
            vec![(gids[0], mkrange(0, 15)), (gids[1], mkrange(17, 0xff))],
            &OwnedRange::full()
        )
        .is_none());
        assert!(range_is_covered(
            vec![
                (gids[0], mkrange(11, 15)),
                (gids[1], mkrange(0, 9)),
                (gids[2], mkrange(16, 0xff))
            ],
            &OwnedRange::full()
        )
        .is_none());
        assert!(range_is_covered(
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
        let mut start = RecordId::min_id();
        start.0[0] = s;
        let mut end = RecordId::max_id();
        end.0[0] = e;
        OwnedRange { start, end }
    }
}
