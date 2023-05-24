use reqwest::Url;

use juicebox_hsm::realm::cluster;

pub async fn new_realm(agent_addresses: &[Url]) -> anyhow::Result<()> {
    println!("Creating new realm");
    let (realm, group) = cluster::new_realm(agent_addresses).await?;
    println!("Created realm {realm:?} with starting group {group:?}");
    Ok(())
}
