use futures::future::join_all;
use futures::FutureExt;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info};
use url::Url;

use agent_api::{AgentService, StatusRequest};
use hsm_api::{GroupId, GroupStatus, HsmId, LeaderStatus, LogIndex};
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc::{self, RpcError};
use juicebox_realm_api::types::RealmId;
use service_core::http::ReqwestClientMetrics;

mod leader;
mod realm;
mod transfer;

pub use leader::{discover_hsm_ids, find_leaders};
pub use realm::{join_realm, new_group, new_realm, JoinRealmError, NewGroupError, NewRealmError};
pub use transfer::{transfer, TransferError};

#[derive(Debug)]
pub enum Error {
    Grpc(tonic::Status),
    Rpc(RpcError),
}
impl From<tonic::Status> for Error {
    fn from(value: tonic::Status) -> Self {
        Self::Grpc(value)
    }
}
impl From<RpcError> for Error {
    fn from(value: RpcError) -> Self {
        Self::Rpc(value)
    }
}

async fn wait_for_commit(
    leader: &Url,
    realm: RealmId,
    group_id: GroupId,
    agent_client: &Client<AgentService>,
) -> Result<(), RpcError> {
    debug!(?realm, group = ?group_id, "waiting for first log entry to commit");
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
    agents: &ReqwestClientMetrics<AgentService>,
    agent_urls: impl Iterator<Item = &Url>,
) -> HashMap<HsmId, (hsm_api::StatusResponse, Url)> {
    join_all(
        agent_urls.map(|url| rpc::send(agents, url, StatusRequest {}).map(|r| (r, url.clone()))),
    )
    .await
    .into_iter()
    .filter_map(|(r, url)| r.ok().and_then(|s| s.hsm).map(|s| (s.id, (s, url))))
    .collect()
}
