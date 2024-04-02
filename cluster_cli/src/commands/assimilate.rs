use jburl::Url;
use juicebox_networking::reqwest::Client;
use juicebox_realm_api::types::RealmId;
use store::StoreClient;

pub async fn assimilate(
    realm: Option<RealmId>,
    group_size: usize,
    agents_client: &Client,
    store: &StoreClient,
    cluster_url: &Option<Url>,
) -> anyhow::Result<()> {
    cluster_core::assimilate(realm, group_size, agents_client, store, cluster_url).await?;
    Ok(())
}
