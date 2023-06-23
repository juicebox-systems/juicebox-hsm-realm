use reqwest::Url;

use juicebox_hsm::http_client::Client;
use juicebox_hsm::realm::agent::types::AgentService;
use juicebox_hsm::realm::cluster;
use juicebox_sdk_core::types::RealmId;

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
