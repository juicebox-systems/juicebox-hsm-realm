use reqwest::Url;

use juicebox_hsm::realm::agent::types::AgentService;
use juicebox_hsm::realm::cluster;
use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_networking::reqwest::Client;

pub async fn new_group(
    realm: RealmId,
    agent_addresses: &[Url],
    agents_client: &Client<AgentService>,
) -> anyhow::Result<()> {
    println!("Creating new group in realm {realm:?}");
    let group = cluster::new_group(agents_client, realm, agent_addresses).await?;
    println!("Created group {group:?}");
    Ok(())
}
