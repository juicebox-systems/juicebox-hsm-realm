use anyhow::Context;
use futures::future::join_all;
use reqwest::Url;
use tracing::debug;

use hsmcore::hsm::types::StatusResponse;
use juicebox_hsm::realm::agent::types::{AgentService, StatusRequest};
use juicebox_hsm::realm::store::bigtable::{ServiceKind, StoreClient};
use juicebox_sdk_networking::reqwest::Client;
use juicebox_sdk_networking::rpc;

/// Returns the status of every available HSM, sorted by HSM ID.
pub async fn get_hsm_statuses(
    agents_client: &Client<AgentService>,
    store: &StoreClient,
) -> anyhow::Result<Vec<(Url, StatusResponse)>> {
    let addresses: Vec<(Url, ServiceKind)> = store
        .get_addresses(Some(ServiceKind::Agent))
        .await
        .context("failed to get agent addresses from Bigtable")?;
    debug!("{} agent(s) listed in service discovery", addresses.len());

    let mut hsms: Vec<(Url, StatusResponse)> = join_all(
        addresses
            .iter()
            .map(|(url, _kind)| rpc::send(agents_client, url, StatusRequest {})),
    )
    .await
    .into_iter()
    .zip(addresses)
    .filter_map(|(result, (url, _kind))| {
        result
            .ok()
            .and_then(|status| status.hsm)
            .map(|status| (url, status))
    })
    .collect();
    hsms.sort_unstable_by_key(|(_, status)| status.id);
    Ok(hsms)
}
