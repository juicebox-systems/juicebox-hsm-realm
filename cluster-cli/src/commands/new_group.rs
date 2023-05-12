use reqwest::Url;

use loam_mvp::realm::cluster;
use loam_sdk_core::types::RealmId;

pub async fn new_group(realm: RealmId, agent_addresses: &[Url]) -> anyhow::Result<()> {
    println!("Creating new group in realm {realm:?}");
    let group = cluster::new_group(realm, agent_addresses).await?;
    println!("Created group {group:?}");
    Ok(())
}
