use futures::future::join_all;
use futures::FutureExt;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info};
use url::Url;

use agent_api::StatusRequest;
use hsm_api::{GroupId, GroupStatus, HsmId, LeaderStatus, LogIndex};
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc::{self, RpcError, SendOptions};
use juicebox_realm_api::types::RealmId;
use retry_loop::RetryError;
use service_core::http::ReqwestClientMetrics;

mod leader;
mod realm;
mod transfer;
pub mod workload;

pub use leader::{discover_hsm_ids, find_leaders};
pub use realm::{join_realm, new_group, new_realm, JoinRealmError, NewGroupError, NewRealmError};
pub use transfer::{transfer, TransferError, TransferRequest};

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
