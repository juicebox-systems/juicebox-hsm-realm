use anyhow::Context;
use futures::future::join_all;
use reqwest::Url;
use tracing::debug;

use hsmcore::hsm::types::{HsmId, StatusResponse};
use loam_mvp::http_client::Client;
use loam_mvp::realm::agent::types::{AgentService, StatusRequest};
use loam_mvp::realm::store::bigtable::StoreClient;
use loam_sdk_networking::rpc;

/// Returns the status of every available HSM, sorted by HSM ID.
///
/// Ignores service discovery entries where an agent was registered with one
/// HSM but actually reports a different HSM in its status.
pub async fn get_hsm_statuses(
    agents_client: &Client<AgentService>,
    store: &StoreClient,
) -> anyhow::Result<Vec<(Url, StatusResponse)>> {
    let addresses: Vec<(HsmId, Url)> = store
        .get_addresses()
        .await
        .context("failed to get agent addresses from Bigtable")?;
    debug!("{} agent(s) listed in service discovery", addresses.len());

    let mut hsms: Vec<(Url, StatusResponse)> = join_all(
        addresses
            .iter()
            .map(|(_hsm_id, url)| rpc::send(agents_client, url, StatusRequest {})),
    )
    .await
    .into_iter()
    .zip(addresses)
    .filter_map(|(result, (hsm_id, url))| {
        result
            .ok()
            .and_then(|status| status.hsm)
            .filter(|hsm| hsm.id == hsm_id)
            .map(|status| (url, status))
    })
    .collect();
    hsms.sort_unstable_by_key(|(_, status)| status.id);
    Ok(hsms)
}
