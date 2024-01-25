use futures::future::join_all;
use futures::FutureExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, info, warn};
use url::Url;

use agent_api::StatusRequest;
use hsm_api::{GroupId, GroupStatus, HsmId, LeaderStatus, LogIndex};
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc::{self, RpcError, SendOptions};
use juicebox_realm_api::types::RealmId;
use retry_loop::RetryError;
use service_core::http::ReqwestClientMetrics;
use store::{Lease, LeaseKey, LeaseType, StoreClient};

mod leader;
mod realm;
mod transfer;
pub mod workload;

pub use leader::{discover_hsm_ids, find_leaders};
pub use realm::{join_realm, new_group, new_realm, JoinRealmError, NewGroupError, NewRealmError};
pub use transfer::{perform_transfer, transfer, TransferError, TransferRequest};

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

pub async fn get_hsm_statuses(
    agents: &ReqwestClientMetrics,
    agent_urls: impl Iterator<Item = &Url>,
    timeout: Option<Duration>,
) -> HashMap<HsmId, (hsm_api::StatusResponse, Url)> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
