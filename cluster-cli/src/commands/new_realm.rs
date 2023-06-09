use reqwest::Url;

use juicebox_hsm::http_client::Client;
use juicebox_hsm::realm::agent::types::AgentService;
use juicebox_hsm::realm::cluster;

pub async fn new_realm(
    agent_address: &Url,
    agents_client: &Client<AgentService>,
) -> anyhow::Result<()> {
    println!("Creating new realm");
    let (realm, group) = cluster::new_realm(agents_client, agent_address).await?;
    println!("Created realm {realm:?} with starting group {group:?}");
    Ok(())
}
