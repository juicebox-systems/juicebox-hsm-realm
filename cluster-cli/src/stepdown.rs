use anyhow::Context;
use reqwest::Url;

use hsmcore::hsm::types::HsmId;
use loam_mvp::{
    http_client::{Client, ClientOptions},
    realm::cluster::types::{ClusterService, StepDownRequest, StepDownResponse},
};
use loam_sdk_networking::rpc::{self};

pub async fn stepdown(cluster_url: &Url, hsm: HsmId) -> anyhow::Result<()> {
    let c = Client::<ClusterService>::new(ClientOptions::default());
    let r = rpc::send(&c, cluster_url, StepDownRequest::Hsm(hsm)).await;
    match r.context("While asking cluster manager to perform leadership stepdown")? {
        StepDownResponse::Ok => {
            println!("Leader stepdown successfully completed");
        }
        s => {
            println!("Leader stepdown had error {s:?}");
        }
    }
    Ok(())
}
