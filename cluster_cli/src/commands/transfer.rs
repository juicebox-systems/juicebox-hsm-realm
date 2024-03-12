use anyhow::{anyhow, Context};
use hsm_api::{GroupId, OwnedRange};

use super::super::cluster::ClusterInfo;
use cluster_api::TransferRequest;
use jburl::Url;
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc;
use juicebox_realm_api::types::RealmId;

pub async fn transfer(
    cluster: &ClusterInfo,
    client: &Client,
    cluster_url: &Option<Url>,
    realm: RealmId,
    source: GroupId,
    destination: GroupId,
    range: OwnedRange,
) -> anyhow::Result<()> {
    println!(
        "Transferring range {range} in realm {realm:?} from group {source:?} to {destination:?}"
    );

    let url = match cluster_url {
        Some(url) => url,
        None => {
            if cluster.managers.is_empty() {
                return Err(anyhow!("No cluster managers in service discovery, and no explicit cluster manager URL set."));
            }
            &cluster.managers[0]
        }
    };

    let req = TransferRequest {
        realm,
        source,
        destination,
        range,
    };

    rpc::send(client, url, req)
        .await
        .context("error while asking cluster manager to perform ownership transfer")??;
    println!("Ownership transfer completed successfully");
    Ok(())
}
