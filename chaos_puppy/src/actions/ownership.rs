use anyhow::{anyhow, Context};
use async_trait::async_trait;
use rand::Rng;
use rand_core::OsRng;
use tracing::info;

use super::{cluster_manager, find_groups, GroupLeaderInfo, Puppy};
use cluster_core::discover_hsm_statuses;
use hsm_api::RecordId;
use hsm_api::{GroupId, OwnedRange};
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc;
use store::StoreClient;

/// This moves part of all of a record id range from one replication group to another.
#[derive(Debug)]
pub struct OwnershipTransfer;

#[async_trait]
impl Puppy for OwnershipTransfer {
    async fn run(&self, store: &StoreClient, client: &Client) -> anyhow::Result<()> {
        let statuses = discover_hsm_statuses(store, client).await?;
        let groups = find_groups(&statuses);
        let (mut owners, empty_groups): (Vec<_>, Vec<_>) =
            groups.into_iter().partition(|g| g.range.is_some());

        fn start(g: &GroupLeaderInfo) -> &RecordId {
            &g.range.as_ref().unwrap().start
        }
        owners.sort_by(|a, b| a.realm.cmp(&b.realm).then_with(|| start(a).cmp(start(b))));
        for o in &owners {
            info!(realm=?o.realm, group=?o.group, agent=?o.agent, range=?o.range, "group owns range");
        }
        if !empty_groups.is_empty() {
            let ids: Vec<GroupId> = empty_groups.iter().map(|g| g.group).collect();
            info!(groups=?ids, "empty groups");
        }
        if owners.is_empty() {
            return Err(anyhow!(
                "Unable to find any groups that own a record id range"
            ));
        }
        let source_idx = OsRng.gen_range(0..owners.len());
        let (dest, range) =
            if !empty_groups.is_empty() && (owners.len() < 2 || OsRng.gen_bool(0.33)) {
                // Move some or all of the range to a group that currently doesn't own anything.
                (
                    empty_groups[0].group,
                    cut_range(owners[source_idx].range.as_ref().unwrap(), Side::Left),
                )
            } else {
                // Pick a destination, remembering that it must own an adjacent range.
                let dest_idx = if source_idx == 0 {
                    1
                } else if source_idx == owners.len() - 1 {
                    source_idx - 1
                } else if OsRng.gen_bool(0.5) {
                    source_idx + 1
                } else {
                    source_idx - 1
                };
                let side = if dest_idx > source_idx {
                    Side::Right
                } else {
                    Side::Left
                };
                (
                    owners[dest_idx].group,
                    cut_range(owners[source_idx].range.as_ref().unwrap(), side),
                )
            };

        let cluster_manager = cluster_manager(store).await?;
        info!(%range, source=?owners[source_idx].group, ?dest, "will transfer range");
        rpc::send(
            client,
            &cluster_manager,
            cluster_api::TransferRequest {
                realm: owners[source_idx].realm,
                source: owners[source_idx].group,
                destination: dest,
                range,
            },
        )
        .await?
        .context("asking cluster manager to do an ownership transfer")
        .map(|_| ())
    }
}

enum Side {
    Left,
    Right,
}

fn cut_range(r: &OwnedRange, return_side: Side) -> OwnedRange {
    if OsRng.gen_bool(0.2) {
        // move the entire thing
        return r.clone();
    }
    let cut_point = OsRng.gen_range(r.start.0[0]..=r.end.0[0]);
    let mut left = r.clone();
    let mut right = r.clone();
    left.end.0[0] = cut_point;
    right.start.0[0] = cut_point;
    match return_side {
        Side::Left => left,
        Side::Right => right,
    }
}
