use futures::future::join_all;
use futures::FutureExt;
use std::collections::HashMap;
use std::iter::zip;
use tracing::{trace, warn};
use url::Url;

use super::super::agent::types::{AgentService, StatusRequest, StatusResponse};
use super::super::store::bigtable::{ServiceKind, StoreClient};
use hsm_types::{GroupId, HsmId};
use hsmcore::hsm::types as hsm_types;
use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_networking::reqwest::Client;
use juicebox_sdk_networking::rpc::{self};

pub async fn find_leaders(
    store: &StoreClient,
    agent_client: &Client<AgentService>,
) -> Result<HashMap<(RealmId, GroupId), (HsmId, Url)>, tonic::Status> {
    trace!("refreshing cluster information");
    let addresses: Vec<(Url, ServiceKind)> = store.get_addresses(Some(ServiceKind::Agent)).await?;

    let responses = join_all(
        addresses
            .iter()
            .map(|(address, _)| rpc::send(agent_client, address, StatusRequest {})),
    )
    .await;

    let mut leaders: HashMap<(RealmId, GroupId), (HsmId, Url)> = HashMap::new();
    for ((agent, _), response) in zip(addresses, responses) {
        match response {
            Ok(StatusResponse {
                hsm:
                    Some(hsm_types::StatusResponse {
                        realm: Some(status),
                        id: hsm_id,
                        ..
                    }),
                ..
            }) => {
                for group in status.groups {
                    if group.leader.is_some() {
                        leaders.insert((status.id, group.id), (hsm_id, agent.clone()));
                    }
                }
            }

            Ok(_) => {}

            Err(err) => {
                warn!(%agent, ?err, "could not get status");
            }
        }
    }
    trace!("done refreshing cluster information");
    Ok(leaders)
}

// Using service discovery returns all the HSM ids + the URL of their Agent.
pub async fn discover_hsm_ids(
    store: &StoreClient,
    agents_client: &Client<AgentService>,
) -> Result<impl Iterator<Item = (HsmId, Url)>, tonic::Status> {
    let agents = store.get_addresses(Some(ServiceKind::Agent)).await?;
    Ok(join_all(agents.iter().map(|(url, _)| {
        rpc::send(agents_client, url, StatusRequest {}).map(|status| (url.clone(), status))
    }))
    .await
    .into_iter()
    // skip network failures
    .filter_map(|(url, response)| response.map(|r| (url, r)).ok())
    .filter_map(|(url, status)| status.hsm.map(|hsm| (url, hsm)))
    .map(|(url, status)| (status.id, url)))
}
