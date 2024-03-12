use anyhow::Context;
use futures::future::join_all;
use tracing::debug;

use agent_api::StatusRequest;
use hsm_api::StatusResponse;
use jburl::Url;
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc;
use store::{ServiceKind, StoreClient};

/// Returns the status of every available HSM, sorted by HSM ID.
pub async fn get_hsm_statuses(
    agents_client: &Client,
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
