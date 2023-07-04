use anyhow::anyhow;
use anyhow::Context;
use reqwest::Url;

use hsmcore::hsm::types::HsmId;
use juicebox_hsm::realm::cluster::types::{ClusterService, StepDownRequest, StepDownResponse};
use juicebox_hsm::realm::store::bigtable::{ServiceKind, StoreClient};
use juicebox_sdk_networking::reqwest::{Client, ClientOptions};
use juicebox_sdk_networking::rpc;

pub async fn stepdown(
    store: &StoreClient,
    cluster_url: &Option<Url>,
    hsm: HsmId,
) -> anyhow::Result<()> {
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
    let c = Client::<ClusterService>::new(ClientOptions::default());
    let r = rpc::send(&c, &url, StepDownRequest::Hsm(hsm)).await;
    match r.context("error while asking cluster manager to perform leadership stepdown")? {
        StepDownResponse::Ok => {
            println!("Leader stepdown successfully completed");
        }
        s => {
            println!("Leader stepdown had error: {s:?}");
        }
    }
    Ok(())
}
