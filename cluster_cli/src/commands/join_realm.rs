use anyhow::anyhow;
use reqwest::Url;

use crate::cluster::ClusterInfo;
use juicebox_networking::reqwest::Client;
use juicebox_realm_api::types::RealmId;

pub async fn join_realm(
    realm: RealmId,
    agent_addresses: &[Url],
    agents_client: &Client,
    cluster: &ClusterInfo,
) -> anyhow::Result<()> {
    println!(
        "Requesting {} HSMs to join realm {realm:?}",
        agent_addresses.len()
    );

    let Some((_, existing)) = cluster.hsm_statuses().find(|(status, _)| {
        status
            .realm
            .as_ref()
            .is_some_and(|realm_status| realm_status.id == realm)
    }) else {
        return Err(anyhow!(
            "could not find any available HSM that's already in the realm"
        ));
    };

    cluster_core::join_realm(agents_client, realm, agent_addresses, existing).await?;
    println!("HSMs done joining realm");
    Ok(())
}
