use reqwest::Url;

use juicebox_hsm::realm::cluster;
use juicebox_sdk_core::types::RealmId;

pub async fn new_group(realm: RealmId, agent_addresses: &[Url]) -> anyhow::Result<()> {
    println!("Creating new group in realm {realm:?}");
    let group = cluster::new_group(realm, agent_addresses).await?;
    println!("Created group {group:?}");
    Ok(())
}
