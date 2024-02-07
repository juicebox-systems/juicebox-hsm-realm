use anyhow::Context;
use futures::future::join_all;
use futures::FutureExt;
use hex::FromHexError;
use reqwest::Url;
use std::collections::HashSet;
use std::fmt::Debug;
use thiserror::Error;

use agent_api::{StatusRequest, StatusResponse};
use hsm_api::{GroupId, HsmId};
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc;
use juicebox_sdk::RealmId;
use store::{ServiceKind, StoreClient};

#[derive(Clone)]
pub struct ResolvableRealmId(Vec<u8>);

impl ResolvableRealmId {
    pub fn resolve(&self, c: &ClusterInfo) -> anyhow::Result<RealmId> {
        let m: Vec<_> = c
            .realms
            .iter()
            .filter(|realm| realm.0.starts_with(&self.0))
            .take(2)
            .collect();
        match m.len() {
            0 => Err(IdError::NoMatch),
            1 => Ok(*m[0]),
            _ => Err(IdError::AmbiguousId),
        }
        .context("resolving a realm id")
    }
}

pub fn parse_resolvable_realm_id(buf: &str) -> anyhow::Result<ResolvableRealmId> {
    let id = hex::decode(buf)?;
    if id.len() > 16 {
        return Err(FromHexError::InvalidStringLength.into());
    }
    Ok(ResolvableRealmId(id))
}

#[derive(Clone)]
pub struct ResolvableGroupId(Vec<u8>);

impl ResolvableGroupId {
    pub fn resolve(&self, c: &ClusterInfo) -> anyhow::Result<RealmGroup> {
        let m: Vec<_> = c
            .groups
            .iter()
            .filter(|rg| rg.group.0.starts_with(&self.0))
            .take(2)
            .collect();
        match m.len() {
            0 => Err(IdError::NoMatch),
            1 => Ok(m[0].clone()),
            _ => Err(IdError::AmbiguousId),
        }
        .context("resolving a group id")
    }
}

pub fn parse_resolvable_group_id(buf: &str) -> anyhow::Result<ResolvableGroupId> {
    let id = hex::decode(buf)?;
    if id.len() > 16 {
        return Err(FromHexError::InvalidStringLength.into());
    }
    Ok(ResolvableGroupId(id))
}

pub struct ClusterInfo {
    pub statuses: Vec<(StatusResponse, Url)>,
    pub hsms: HashSet<HsmId>,
    pub realms: HashSet<RealmId>,
    pub groups: HashSet<RealmGroup>,
    pub agents: Vec<Url>,
    pub managers: Vec<Url>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RealmGroup {
    pub realm: RealmId,
    pub group: GroupId,
}

impl ClusterInfo {
    pub async fn new(store: &StoreClient, client: &Client) -> anyhow::Result<Self> {
        let mut ids = ClusterInfo {
            statuses: Vec::new(),
            hsms: HashSet::new(),
            realms: HashSet::new(),
            groups: HashSet::new(),
            agents: Vec::new(),
            managers: Vec::new(),
        };
        for (url, k) in store
            .get_addresses(None)
            .await
            .context("RPC error to bigtable")?
        {
            match k {
                ServiceKind::Agent => ids.agents.push(url),
                ServiceKind::ClusterManager => ids.managers.push(url),
                ServiceKind::LoadBalancer => {}
            }
        }
        ids.statuses = join_all(
            ids.agents
                .iter()
                .map(|url| rpc::send(client, url, StatusRequest {}).map(|r| (r, url.clone()))),
        )
        .await
        .into_iter()
        .filter_map(|(s, url)| s.ok().map(|s| (s, url)))
        .collect();

        ids.statuses
            .iter()
            .filter_map(|(s, _url)| s.hsm.as_ref())
            .for_each(|sr| {
                ids.hsms.insert(sr.id);
                if let Some(r) = &sr.realm {
                    ids.realms.insert(r.id);
                    for gs in &r.groups {
                        ids.groups.insert(RealmGroup {
                            realm: r.id,
                            group: gs.id,
                        });
                    }
                }
            });
        Ok(ids)
    }

    pub fn hsm_statuses(&self) -> impl Iterator<Item = (&hsm_api::StatusResponse, &Url)> {
        self.statuses
            .iter()
            .filter_map(|(s, url)| s.hsm.as_ref().map(|hsm| (hsm, url)))
    }
}

#[derive(Error, Debug)]
pub enum IdError {
    #[error("no item with that ID")]
    NoMatch,
    #[error("ambiguous ID: 2 or more items share that prefix")]
    AmbiguousId,
}
