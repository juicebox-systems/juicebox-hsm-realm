use agent_api::StatusRequest;
use futures::future::{join_all, try_join_all};
use std::cmp::min;
use std::collections::HashSet;
use thiserror::Error;
use tracing::{debug, info};

use super::{
    join_realm, new_group, new_realm, partition_evenly, JoinRealmError, NewGroupError,
    NewRealmError,
};
use cluster_api::{TransferError, TransferRequest};
use hsm_api::{GroupId, HsmId, OwnedRange, RecordId, StatusResponse};
use jburl::Url;
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc::{self, RpcError};
use juicebox_realm_api::types::RealmId;
use retry_loop::RetryError;
use store::{ServiceKind, StoreClient};

#[derive(Debug, Error)]
pub enum AssimilateError {
    #[error("No cluster managers in service discovery, and no explicit cluster manager URL set.")]
    NoClusterManager,
    #[error("Realm not specified and found multiple realms: {0:?}")]
    AmbiguousRealm(HashSet<RealmId>),
    #[error("Not enough HSMs: found {have} but need {need}")]
    NotEnoughHsms { have: usize, need: usize },
    #[error("Error creating new realm: {0}")]
    NewRealmError(#[from] NewRealmError),
    #[error("Unable to join HSM to realm: {0}")]
    JoinRealmError(#[from] JoinRealmError),
    #[error("Unable to create new group: {0}")]
    NewGroupError(#[from] NewGroupError),
    #[error("Could not find any available HSMs in realm {0:?} (need at least one)")]
    NoHsmInRealm(RealmId),
    #[error("Could not find owner for record id: {0:?}")]
    NoOwner(RecordId),
    #[error("Unable to transfer record id range: {0}")]
    TransferError(#[from] TransferError),
    #[error("Error making gRPC request: {0}")]
    GrpcError(#[from] RetryError<tonic::Status>),
    #[error("Error making RPC request: {0}")]
    RpcError(#[from] RpcError),
}

pub async fn assimilate(
    realm: Option<RealmId>,
    group_size: usize,
    agents_client: &Client,
    store: &StoreClient,
    cluster_url: &Option<Url>,
) -> Result<(), AssimilateError> {
    assert_ne!(group_size, 0);

    let cluster_url = match cluster_url {
        Some(url) => url.clone(),
        None => {
            let managers: Vec<(Url, _)> = store
                .get_addresses(Some(ServiceKind::ClusterManager))
                .await?;
            if managers.is_empty() {
                return Err(AssimilateError::NoClusterManager);
            }
            managers[0].0.clone()
        }
    };

    let get_checked_hsm_statuses = || async {
        let hsm_statuses = get_hsm_statuses(agents_client, store).await?;
        if hsm_statuses.len() < group_size {
            return Err(AssimilateError::NotEnoughHsms {
                have: hsm_statuses.len(),
                need: group_size,
            });
        }
        Ok(hsm_statuses)
    };

    let mut hsm_statuses: Vec<(Url, StatusResponse)> = get_checked_hsm_statuses().await?;

    let realm = match realm {
        Some(realm) => realm,
        None => match get_unique_realm(&hsm_statuses)? {
            Some(realm) => realm,
            None => {
                let realm = new_realm(agents_client, &hsm_statuses[0].0).await?.0;
                // We need to update the status for this HSM, since it now owns
                // the entire range. Out of laziness, refresh all of them.
                hsm_statuses = get_checked_hsm_statuses().await?;
                realm
            }
        },
    };

    // Join any more HSMs into the realm.
    match hsm_statuses
        .iter()
        .find(|(_, status)| status.realm.as_ref().is_some_and(|rs| rs.id == realm))
    {
        None => {
            // This should only happen if the user provided a (possibly
            // incorrect) realm ID.
            return Err(AssimilateError::NoHsmInRealm(realm));
        }

        Some((existing, _)) => {
            let new: Vec<Url> = hsm_statuses
                .iter()
                .filter(|(_, status)| status.realm.is_none())
                .map(|(url, _)| url.clone())
                .collect();
            join_realm(agents_client, realm, &new, existing).await?;
            hsm_statuses = get_checked_hsm_statuses().await?;
        }
    }

    hsm_statuses.retain(|(_, status)| status.realm.as_ref().is_some_and(|rs| rs.id == realm));

    let new_groups: Vec<GroupId> =
        nominal_groups(group_size, realm, &hsm_statuses, agents_client).await?;

    // Each iteration of this loop ensures that one new group owns its entire
    // assigned partition. The owned range may have to be transferred from one
    // or more of the old groups.
    for (new_range, new_group) in partition_evenly(new_groups.len())
        .into_iter()
        .zip(new_groups.into_iter())
    {
        let mut next: RecordId = new_range.start.clone();

        // Each iteration of this loop ensures that `new_group` owns `next`,
        // often by transferring a subrange starting with `next` from another
        // group.
        //
        // TODO: This has two known limitations:
        //
        // 1. If the new group already owns a non-adjacent range, it cannot yet
        //    accept the new range. To resolve this, the new group would have
        //    to give away its old range to another group first.
        //
        // 2. If the old group owns a range that's bigger than the range to be
        //    transferred to the new group on both sides (both smaller start
        //    and larger end), it can't yet transfer the smaller range because
        //    that would leave a hole in the old group's ownership. To resolve
        //    this, the old group would need to split its range and give away
        //    an excess portion to another group first.
        loop {
            // Find the group that currently owns `next`.
            let old: Option<(GroupId, OwnedRange)> = hsm_statuses.iter().find_map(|(_, status)| {
                status.realm.as_ref().and_then(|realm| {
                    realm.groups.iter().find_map(|group| {
                        group
                            .leader
                            .as_ref()
                            .and_then(|leader| {
                                leader.owned_range.as_ref().filter(|r| r.contains(&next))
                            })
                            .cloned()
                            .map(|r| (group.id, r))
                    })
                })
            });
            let Some((old_group, old_range)) = old else {
                return Err(AssimilateError::NoOwner(next));
            };

            let end = min(&old_range.end, &new_range.end);
            let transfer = OwnedRange {
                start: next,
                end: end.clone(),
            };

            if old_group != new_group {
                info!(range=%transfer, from=?old_group, to=?new_group, "transferring ownership of range");

                rpc::send(
                    agents_client,
                    &cluster_url,
                    TransferRequest {
                        realm,
                        source: old_group,
                        destination: new_group,
                        range: transfer,
                    },
                )
                .await??;
            }

            if end == &new_range.end {
                break;
            }
            next = end.next().unwrap();
        }
    }

    Ok(())
}

fn get_unique_realm(
    hsm_statuses: &[(Url, StatusResponse)],
) -> Result<Option<RealmId>, AssimilateError> {
    let realms: HashSet<RealmId> = hsm_statuses
        .iter()
        .filter_map(|(_, status)| status.realm.as_ref())
        .map(|realm| realm.id)
        .collect();
    if realms.len() > 1 {
        return Err(AssimilateError::AmbiguousRealm(realms));
    }
    Ok(realms.into_iter().next())
}

/// Finds or creates groups such that each HSM is a member of `group_size`
/// groups in a particular cyclic sorted order.
///
/// Note: This is unstable in that adding/removing an HSM to the cluster can
/// cause a whole new set of groups to be created.
async fn nominal_groups(
    group_size: usize,
    realm: RealmId,
    hsm_statuses: &[(Url, StatusResponse)],
    agents_client: &Client,
) -> Result<Vec<GroupId>, NewGroupError> {
    // Groups are not "reused" so that if the number of HSMs is exactly the
    // group size, then the result is that many groups, not just one.
    let mut used: HashSet<GroupId> = HashSet::new();

    // The outcome for a particular search is summarized and cloned into this
    // enum to avoid shared state with async code.
    enum Group {
        Existing { id: GroupId },
        New { agent_urls: Vec<Url> },
    }

    let mut groups: Vec<GroupId> =
        try_join_all(hsm_statuses.iter().enumerate().map(|(i, (_, status0))| {
            let target = hsm_statuses.iter().cycle().skip(i).take(group_size);
            let target_hsms: HashSet<&HsmId> =
                target.clone().map(|(_, status)| &status.id).collect();

            // Look for a not-yet-used group consisting of `target_hsms`. For
            // stability, pick the group with the smallest ID if there are
            // multiple candidates.
            let group: Group = match status0.realm.as_ref().and_then(|realm_status| {
                realm_status
                    .groups
                    .iter()
                    .filter(|group| !used.contains(&group.id))
                    .filter(|group| target_hsms == HashSet::from_iter(&group.configuration))
                    .map(|group| group.id)
                    .min()
            }) {
                Some(id) => {
                    used.insert(id);
                    Group::Existing { id }
                }
                None => Group::New {
                    agent_urls: target.map(|(url, _)| url.clone()).collect(),
                },
            };

            // Actually create the group, if needed.
            async move {
                match group {
                    Group::Existing { id } => Ok(id),
                    Group::New { agent_urls } => new_group(agents_client, realm, &agent_urls).await,
                }
            }
        }))
        .await?;

    groups.sort_unstable();
    Ok(groups)
}

/// Returns the status of every available HSM, sorted by HSM ID.
async fn get_hsm_statuses(
    agents_client: &Client,
    store: &StoreClient,
) -> Result<Vec<(Url, StatusResponse)>, RetryError<tonic::Status>> {
    let addresses: Vec<(Url, ServiceKind)> = store.get_addresses(Some(ServiceKind::Agent)).await?;
    debug!("{} agent(s) listed in service discovery", addresses.len());

    let mut hsms: Vec<(Url, StatusResponse)> = join_all(
        addresses
            .iter()
            .map(|(url, _kind)| rpc::send(agents_client, url, StatusRequest {})),
    )
    .await
    .into_iter()
    .zip(addresses)
    .filter_map(|(result, (url, _kind))| {
        result
            .ok()
            .and_then(|status| status.hsm)
            .map(|status| (url, status))
    })
    .collect();
    hsms.sort_unstable_by_key(|(_, status)| status.id);
    Ok(hsms)
}
