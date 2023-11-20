use anyhow::anyhow;
use anyhow::Context;
use futures::future::join_all;
use reqwest::Url;
use std::collections::HashSet;
use thiserror::Error;

use crate::StepdownType;
use agent_api::StatusRequest;
use cluster_api::{StepDownRequest, StepDownResponse};
use hsm_api::{GroupId, HsmId};
use juicebox_networking::reqwest::{Client, ClientOptions};
use juicebox_networking::rpc;
use juicebox_sdk::RealmId;
use store::{ServiceKind, StoreClient};

pub(crate) async fn stepdown(
    store: &StoreClient,
    agent_client: &Client,
    cluster_url: &Option<Url>,
    stepdown_type: Option<StepdownType>,
    id: &str,
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
    let req = resolve_stepdown_req(store, agent_client, stepdown_type, id).await?;

    let c = Client::new(ClientOptions::default());
    let r = rpc::send(&c, &url, req).await;
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
    store: &StoreClient,
    agent_client: &Client,
    stepdown_type: Option<StepdownType>,
    id: &str,
) -> anyhow::Result<StepDownRequest> {
    if id.len() == 32 && matches!(stepdown_type, Some(StepdownType::Hsm)) {
        let h = hex::decode(id).context("error decoding id")?;
        return Ok(StepDownRequest::Hsm(HsmId(h.try_into().unwrap())));
    }
    // id can match a hsm or group id unless stepdown_type is set to a specific type.
    let id = id.to_lowercase();
    let (hsms, groups) = collect_cluster_info(store, agent_client).await?;
    let mut options = Vec::new();
    if !matches!(stepdown_type, Some(StepdownType::Group)) {
        for hsm in hsms {
            if hsm.to_string().to_lowercase().starts_with(&id) {
                options.push(StepDownRequest::Hsm(hsm));
            }
        }
    }
    if !matches!(stepdown_type, Some(StepdownType::Hsm)) {
        for (realm, group) in groups {
            if group.to_string().to_lowercase().starts_with(&id) {
                options.push(StepDownRequest::Group { realm, group });
            }
        }
    }
    match options.len() {
        0 => Err(IdError::NoMatch.into()),
        1 => Ok(options[0].clone()),
        c => Err(IdError::AmbiguousId(c).into()),
    }
}

async fn collect_cluster_info(
    store: &StoreClient,
    agent_client: &Client,
) -> anyhow::Result<(HashSet<HsmId>, HashSet<(RealmId, GroupId)>)> {
    let mut hsms = HashSet::new();
    let mut groups = HashSet::new();
    join_all(
        store
            .get_addresses(Some(store::ServiceKind::Agent))
            .await
            .context("RPC error to bigtable")?
            .iter()
            .map(|(url, _)| rpc::send(agent_client, url, StatusRequest {})),
    )
    .await
    .into_iter()
    .filter_map(|s| s.ok())
    .filter_map(|s| s.hsm)
    .for_each(|sr| {
        hsms.insert(sr.id);
        if let Some(r) = sr.realm {
            for gs in r.groups {
                groups.insert((r.id, gs.id));
            }
        }
    });
    Ok((hsms, groups))
}

#[derive(Error, Debug)]
enum IdError {
    #[error("no HSM or Group with that ID")]
    NoMatch,
    #[error("ambiguous ID: {0} Groups/HSMs share that prefix")]
    AmbiguousId(usize),
}
