use futures::future::join_all;
use std::collections::HashMap;
use std::iter::zip;
use tracing::{trace, warn};
use url::Url;

use super::super::super::http_client::Client;
use super::super::agent::types::{AgentService, StatusRequest, StatusResponse};
use super::super::store::bigtable::StoreClient;
use hsm_types::{GroupId, HsmId};
use hsmcore::hsm::types as hsm_types;
use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_networking::rpc::{self};

pub async fn find_leaders(
    store: &StoreClient,
    agent_client: &Client<AgentService>,
) -> Result<HashMap<(RealmId, GroupId), (HsmId, Url)>, tonic::Status> {
    trace!("refreshing cluster information");
    let addresses = store.get_addresses().await?;

    let responses = join_all(
        addresses
            .iter()
            .map(|(_, address)| rpc::send(agent_client, address, StatusRequest {})),
    )
    .await;

    let mut leaders: HashMap<(RealmId, GroupId), (HsmId, Url)> = HashMap::new();
    for ((_, agent), response) in zip(addresses, responses) {
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
