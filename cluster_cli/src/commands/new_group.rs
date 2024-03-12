use jburl::Url;
use juicebox_networking::reqwest::Client;
use juicebox_realm_api::types::RealmId;

pub async fn new_group(
    realm: RealmId,
    agent_addresses: &[Url],
    agents_client: &Client,
) -> anyhow::Result<()> {
    println!("Creating new group in realm {realm:?}");
    let group = cluster_core::new_group(agents_client, realm, agent_addresses).await?;
    println!("Created group {group:?}");
    Ok(())
}
