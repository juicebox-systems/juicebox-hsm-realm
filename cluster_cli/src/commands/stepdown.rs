use anyhow::anyhow;
use anyhow::Context;

use super::super::cluster::{ClusterInfo, IdError};
use super::super::StepdownType;
use cluster_api::{StepDownRequest, StepDownResponse};
use hsm_api::HsmId;
use jburl::Url;
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc;

pub(crate) async fn stepdown(
    cluster_info: &ClusterInfo,
    client: &Client,
    cluster_url: &Option<Url>,
    stepdown_type: Option<StepdownType>,
    id: &str,
) -> anyhow::Result<()> {
    let url = match cluster_url {
        Some(url) => url,
        None => {
            if cluster_info.managers.is_empty() {
                return Err(anyhow!("No cluster managers in service discovery, and no explicit cluster manager URL set."));
            }
            &cluster_info.managers[0]
        }
    };
    let req = resolve_stepdown_req(cluster_info, stepdown_type, id).await?;

    let r = rpc::send(client, url, req).await;
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

async fn resolve_stepdown_req(
    cluster: &ClusterInfo,
    stepdown_type: Option<StepdownType>,
    id: &str,
) -> anyhow::Result<StepDownRequest> {
    let prefix = hex::decode(id)?;
    if prefix.len() == 16 && matches!(stepdown_type, Some(StepdownType::Hsm)) {
        return Ok(StepDownRequest::Hsm(HsmId(prefix.try_into().unwrap())));
    }
    // id can match a hsm or group id unless stepdown_type is set to a specific type.
    let mut options = Vec::new();
    if !matches!(stepdown_type, Some(StepdownType::Group)) {
        options.extend(
            cluster
                .hsms
                .iter()
                .filter(|id| id.0.starts_with(&prefix))
                .map(|id| StepDownRequest::Hsm(*id)),
        )
    }
    if !matches!(stepdown_type, Some(StepdownType::Hsm)) {
        options.extend(
            cluster
                .groups
                .iter()
                .filter(|rg| rg.group.0.starts_with(&prefix))
                .map(|rg| StepDownRequest::Group {
                    realm: rg.realm,
                    group: rg.group,
                }),
        );
    }
    match options.len() {
        0 => Err(IdError::NoMatch.into()),
        1 => Ok(options[0].clone()),
        _ => Err(IdError::AmbiguousId.into()),
    }
}
