use reqwest::Url;

use hsmcore::hsm::types::HsmId;
use loam_mvp::{
    http_client::{Client, ClientOptions},
    realm::cluster::types::{ClusterService, StepdownAsLeaderRequest, StepdownAsLeaderResponse},
};
use loam_sdk_networking::rpc::{self, RpcError};

pub async fn stepdown(cluster_url: &Url, hsm: HsmId) -> Result<(), RpcError> {
    let c = Client::<ClusterService>::new(ClientOptions::default());
    let r = rpc::send(&c, cluster_url, StepdownAsLeaderRequest::Hsm(hsm)).await;
    match r {
        Ok(StepdownAsLeaderResponse::Ok) => {
            println!("Leader stepdown successfully completed");
            Ok(())
        }
        Ok(s) => {
            println!("Leader stepdown had error {s:?}");
            Ok(())
        }
        Err(err) => {
            println!("Leader stepdown had rpc error: {err:?}");
            Err(err)
        }
    }
}
