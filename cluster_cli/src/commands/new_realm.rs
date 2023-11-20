use reqwest::Url;

use juicebox_networking::reqwest::Client;

pub async fn new_realm(agent_address: &Url, agents_client: &Client) -> anyhow::Result<()> {
    println!("Creating new realm");
    let (realm, group) = cluster_core::new_realm(agents_client, agent_address).await?;
    println!("Created realm {realm:?} with starting group {group:?}");
    Ok(())
}
