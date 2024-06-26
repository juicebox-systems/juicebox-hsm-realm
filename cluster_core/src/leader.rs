use futures::future::join_all;
use futures::FutureExt;
use std::collections::HashMap;
use std::iter::zip;
use std::time::Duration;
use tracing::{trace, warn};

use agent_api::{StatusRequest, StatusResponse};
use hsm_api::{GroupId, HsmId};
use jburl::Url;
use juicebox_networking::http;
use juicebox_networking::rpc::{self, SendOptions};
use juicebox_realm_api::types::RealmId;
use retry_loop::RetryError;
use store::{ServiceKind, StoreClient};

pub async fn find_leaders(
    store: &StoreClient,
    agent_client: &impl http::Client,
) -> Result<HashMap<(RealmId, GroupId), (HsmId, Url)>, RetryError<tonic::Status>> {
    trace!("refreshing cluster information");
    let addresses: Vec<(Url, ServiceKind)> = store.get_addresses(Some(ServiceKind::Agent)).await?;

    let responses = join_all(addresses.iter().map(|(address, _)| {
        rpc::send_with_options(
            agent_client,
            address,
            StatusRequest {},
            SendOptions::default().with_timeout(Duration::from_secs(5)),
        )
    }))
    .await;

    let mut leaders: HashMap<(RealmId, GroupId), (HsmId, Url)> = HashMap::new();
    for ((agent, _), response) in zip(addresses, responses) {
        match response {
            Ok(StatusResponse {
                hsm:
                    Some(hsm_api::StatusResponse {
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
    agents_client: &impl http::Client,
) -> Result<impl Iterator<Item = (HsmId, Url)>, RetryError<tonic::Status>> {
    let agents = store.get_addresses(Some(ServiceKind::Agent)).await?;
    let urls: Vec<Url> = agents.into_iter().map(|(url, _)| url).collect();
    Ok(hsm_ids(agents_client, &urls).await)
}

pub async fn hsm_ids<'a, 'b, 'c>(
    client: &'a impl http::Client,
    agents: &'b [Url],
) -> impl Iterator<Item = (HsmId, Url)> + 'c {
    join_all(agents.iter().map(|url| {
        rpc::send_with_options(
            client,
            url,
            StatusRequest {},
            SendOptions::default().with_timeout(Duration::from_secs(2)),
        )
        .map(|status| (url.clone(), status))
    }))
    .await
    .into_iter()
    // skip network failures
    .filter_map(|(url, response)| response.map(|r| (url, r)).ok())
    .filter_map(|(url, status)| status.hsm.map(|hsm| (hsm.id, url)))
}
