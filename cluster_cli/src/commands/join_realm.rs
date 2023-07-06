use anyhow::anyhow;
use reqwest::Url;

use agent_api::AgentService;
use juicebox_hsm::realm::cluster;
use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_networking::reqwest::Client;
use store::StoreClient;

use crate::get_hsm_statuses;

pub async fn join_realm(
    realm: RealmId,
    agent_addresses: &[Url],
    agents_client: &Client<AgentService>,
    store: &StoreClient,
) -> anyhow::Result<()> {
    println!(
        "Requesting {} HSMs to join realm {realm:?}",
        agent_addresses.len()
    );

    let hsm_statuses = get_hsm_statuses(agents_client, store).await?;
    let Some((existing, _)) = hsm_statuses.into_iter().find(|(_, status)| {
        status
            .realm
            .as_ref()
            .is_some_and(|realm_status| realm_status.id == realm)
    }) else {
        return Err(anyhow!("could not find any available HSM that's already in the realm"));
    };

    cluster::join_realm(agents_client, realm, agent_addresses, &existing).await?;
    println!("HSMs done joining realm");
    Ok(())
}
