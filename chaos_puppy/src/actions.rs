use anyhow::anyhow;
use async_trait::async_trait;
use rand::seq::SliceRandom;
use rand_core::OsRng;
use std::fmt::Debug;

use cluster_core::HsmStatuses;
use hsm_api::{GroupId, OwnedRange};
use jburl::Url;
use juicebox_networking::reqwest::Client;
use juicebox_realm_api::types::RealmId;
use store::{ServiceKind, StoreClient};

mod leadership;
mod ownership;

pub fn actions() -> Vec<Box<dyn Puppy>> {
    vec![
        Box::new(ownership::OwnershipTransfer),
        Box::new(leadership::GracefulStepdown),
        Box::new(leadership::DirectAgentStepDown),
        Box::new(leadership::BecomeLeader),
    ]
}

#[async_trait]
pub trait Puppy: Debug {
    async fn run(&self, store: &StoreClient, client: &Client) -> anyhow::Result<()>;
}

async fn cluster_manager(store: &StoreClient) -> anyhow::Result<Url> {
    let cluster_managers: Vec<(Url, ServiceKind)> = store
        .get_addresses(Some(ServiceKind::ClusterManager))
        .await?;

    cluster_managers
        .choose(&mut OsRng)
        .map(|(url, _kind)| url.clone())
        .ok_or_else(|| anyhow!("no cluster managers found in service discovery"))
}

struct GroupLeaderInfo {
    realm: RealmId,
    group: GroupId,
    range: Option<OwnedRange>,
    agent: Url,
}

// Return summary information about every group that has a leader. If a group
// has multiple members that think they are leader they are all included.
fn find_groups(statuses: &HsmStatuses) -> Vec<GroupLeaderInfo> {
    let mut groups = Vec::new();
    for (sr, url) in statuses.values() {
        if let Some(rs) = &sr.realm {
            for gs in &rs.groups {
                if let Some(ls) = &gs.leader {
                    groups.push(GroupLeaderInfo {
                        realm: rs.id,
                        group: gs.id,
                        range: ls.owned_range.clone(),
                        agent: url.clone(),
                    });
                }
            }
        }
    }
    groups
}
