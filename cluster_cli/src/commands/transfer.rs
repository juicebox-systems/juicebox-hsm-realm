use anyhow::{anyhow, Context};
use hsm_api::{GroupId, OwnedRange};
use reqwest::Url;
use std::env;

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

    if env::var("CMGR_TRANSFER").is_ok_and(|v| v == "1") {
        println!("Doing a cluster manager transfer. Unset CMGR_TRANSFER for a locally coordinated transfer");

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
    } else {
        println!("Doing a locally coordinated transfer. Set CMGR_TRANSFER=1 for a transfer through the cluster manager");
        cluster_core::transfer(realm, source, destination, range, store).await?;
    }
    Ok(())
}
