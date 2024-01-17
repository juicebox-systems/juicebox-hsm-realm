use anyhow::{anyhow, Context};
use hsm_api::{GroupId, OwnedRange};
use reqwest::Url;

use cluster_api::TransferRequest;
use juicebox_networking::reqwest::{Client, ClientOptions};
use juicebox_networking::rpc;
use juicebox_realm_api::types::RealmId;
use store::{ServiceKind, StoreClient};

pub async fn transfer(
    cluster_url: &Option<Url>,
    realm: RealmId,
    source: GroupId,
    destination: GroupId,
    range: OwnedRange,
    store: &StoreClient,
) -> anyhow::Result<()> {
    println!("Transferring range {range:?} from group {source:?} to {destination:?}");

    let url = match cluster_url {
        Some(url) => url.clone(),
        None => {
            let managers: Vec<(Url, _)> = store
                .get_addresses(Some(ServiceKind::ClusterManager))
                .await?;
            if managers.is_empty() {
                return Err(anyhow!("No cluster managers in service discovery, and no explicit cluster manager URL set."));
            }
            managers[0].0.clone()
        }
    };

    let req = TransferRequest {
        realm,
        source,
        destination,
        range,
    };

    let client = Client::new(ClientOptions::default());
    rpc::send(&client, &url, req)
        .await
        .context("error while asking cluster manager to perform ownership transfer")??;
    println!("Ownership transfer completed successfully");
    Ok(())
}
