use anyhow::anyhow;
use futures::future::try_join_all;
use reqwest::Url;
use std::cmp::min;
use std::collections::HashSet;

use cluster_api::TransferRequest;
use hsm_api::{GroupId, HsmId, OwnedRange, RecordId, StatusResponse};
use juicebox_marshalling::to_be4;
use juicebox_networking::reqwest::Client;
use juicebox_realm_api::types::RealmId;
use store::StoreClient;

use crate::get_hsm_statuses;

pub async fn assimilate(
    realm: Option<RealmId>,
    group_size: usize,
    agents_client: &Client,
    store: &StoreClient,
) -> anyhow::Result<()> {
    assert_ne!(group_size, 0);

    let get_checked_hsm_statuses = || async {
        let hsm_statuses = get_hsm_statuses(agents_client, store).await?;
        if hsm_statuses.len() < group_size {
            return Err(anyhow!(
                "not enough HSMs: found {hsms} but need {group_size}",
                hsms = hsm_statuses.len()
            ));
        }
        Ok(hsm_statuses)
    };

    let mut hsm_statuses: Vec<(Url, StatusResponse)> = get_checked_hsm_statuses().await?;

    let realm = match realm {
        Some(realm) => realm,
        None => match get_unique_realm(&hsm_statuses)? {
            Some(realm) => realm,
            None => {
                let realm = cluster_core::new_realm(agents_client, &hsm_statuses[0].0)
                    .await?
                    .0;
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
            return Err(anyhow!(
                "could not find any available HSMs in realm {realm:?} (need at least one)"
            ));
        }

        Some((existing, _)) => {
            let new: Vec<Url> = hsm_statuses
                .iter()
                .filter(|(_, status)| status.realm.is_none())
                .map(|(url, _)| url.clone())
                .collect();
            cluster_core::join_realm(agents_client, realm, &new, existing).await?;
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
                return Err(anyhow!("cannot find owner for {next:?}"));
            };

            let end = min(&old_range.end, &new_range.end);
            let transfer = OwnedRange {
                start: next,
                end: end.clone(),
            };

            if old_group != new_group {
                println!(
                    "transferring {transfer} from {old_group:?} to {new_group:?}",
                    transfer = format_owned_range(&transfer)
                );

                // TODO: should use cluster manager.
                cluster_core::transfer(
                    store,
                    agents_client,
                    TransferRequest {
                        realm,
                        source: old_group,
                        destination: new_group,
                        range: transfer,
                    },
                )
                .await?;
            }

            if end == &new_range.end {
                break;
            }
            next = end.next().unwrap();
        }
    }

    Ok(())
}

fn get_unique_realm(hsm_statuses: &[(Url, StatusResponse)]) -> anyhow::Result<Option<RealmId>> {
    let realms: HashSet<RealmId> = hsm_statuses
        .iter()
        .filter_map(|(_, status)| status.realm.as_ref())
        .map(|realm| realm.id)
        .collect();
    if realms.len() > 1 {
        return Err(anyhow!(
            "cannot assimilate: realm not specified and found multiple realms: {realms:?}"
        ));
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
) -> anyhow::Result<Vec<GroupId>> {
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
                    Group::New { agent_urls } => {
                        cluster_core::new_group(agents_client, realm, &agent_urls).await
                    }
                }
            }
        }))
        .await?;

    groups.sort_unstable();
    Ok(groups)
}

fn partition_evenly(n: usize) -> Vec<OwnedRange> {
    // It's difficult to divide a 256-bit space into even ranges using only
    // 64-bit integers. This divides a 32-bit space instead and gets close
    // enough for our purposes. Dividing 2^32 by n is better than dividing
    // (2^64-1) by n because it gets the exact results you'd expect when n is a
    // small power of two.
    if n > 1_000_000 {
        unimplemented!("no guarantees here");
    }
    let n = u64::try_from(n).unwrap();
    let partition_size = 2u64.pow(32) / n;

    (0..n)
        .map(|i| {
            let mut start = [0; RecordId::NUM_BYTES];
            start[..4].copy_from_slice(&to_be4(partition_size * i));
            let mut end = [0xff; RecordId::NUM_BYTES];
            if i + 1 < n {
                end[..4].copy_from_slice(&to_be4(partition_size * (i + 1) - 1));
                OwnedRange {
                    start: RecordId(start),
                    end: RecordId(end),
                }
            } else {
                OwnedRange {
                    start: RecordId(start),
                    end: RecordId(end),
                }
            }
        })
        .collect()
}

fn format_owned_range(range: &OwnedRange) -> String {
    format!(
        "{}-{}",
        hex::encode(range.start.0),
        hex::encode(range.end.0)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use expect_test::expect;
    use std::fmt::Write;

    #[test]
    fn test_partition_evenly_full_coverage() {
        for i in [1, 2, 3, 15, 32, 108] {
            let mut last: Option<RecordId> = None;
            for range in partition_evenly(i) {
                let next = match &last {
                    None => RecordId::min_id(),
                    Some(id) => id.next().unwrap(),
                };
                assert_eq!(range.start, next);
                assert!(range.end >= range.start);
                last = Some(range.end);
            }
            assert_eq!(last, Some(RecordId::max_id()));
        }
    }

    #[test]
    fn test_partition_evenly_snapshot() {
        let mut buf = String::new();
        for i in 1..10 {
            writeln!(buf, "partition_evenly({i}):").unwrap();
            for range in partition_evenly(i) {
                writeln!(buf, "  {}", format_owned_range(&range)).unwrap();
            }
        }

        expect![[r#"
            partition_evenly(1):
              0000000000000000000000000000000000000000000000000000000000000000-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            partition_evenly(2):
              0000000000000000000000000000000000000000000000000000000000000000-7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              8000000000000000000000000000000000000000000000000000000000000000-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            partition_evenly(3):
              0000000000000000000000000000000000000000000000000000000000000000-55555554ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              5555555500000000000000000000000000000000000000000000000000000000-aaaaaaa9ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              aaaaaaaa00000000000000000000000000000000000000000000000000000000-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            partition_evenly(4):
              0000000000000000000000000000000000000000000000000000000000000000-3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              4000000000000000000000000000000000000000000000000000000000000000-7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              8000000000000000000000000000000000000000000000000000000000000000-bfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              c000000000000000000000000000000000000000000000000000000000000000-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            partition_evenly(5):
              0000000000000000000000000000000000000000000000000000000000000000-33333332ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              3333333300000000000000000000000000000000000000000000000000000000-66666665ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              6666666600000000000000000000000000000000000000000000000000000000-99999998ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              9999999900000000000000000000000000000000000000000000000000000000-cccccccbffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              cccccccc00000000000000000000000000000000000000000000000000000000-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            partition_evenly(6):
              0000000000000000000000000000000000000000000000000000000000000000-2aaaaaa9ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              2aaaaaaa00000000000000000000000000000000000000000000000000000000-55555553ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              5555555400000000000000000000000000000000000000000000000000000000-7ffffffdffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              7ffffffe00000000000000000000000000000000000000000000000000000000-aaaaaaa7ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              aaaaaaa800000000000000000000000000000000000000000000000000000000-d5555551ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              d555555200000000000000000000000000000000000000000000000000000000-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            partition_evenly(7):
              0000000000000000000000000000000000000000000000000000000000000000-24924923ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              2492492400000000000000000000000000000000000000000000000000000000-49249247ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              4924924800000000000000000000000000000000000000000000000000000000-6db6db6bffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              6db6db6c00000000000000000000000000000000000000000000000000000000-9249248fffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              9249249000000000000000000000000000000000000000000000000000000000-b6db6db3ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              b6db6db400000000000000000000000000000000000000000000000000000000-db6db6d7ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              db6db6d800000000000000000000000000000000000000000000000000000000-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            partition_evenly(8):
              0000000000000000000000000000000000000000000000000000000000000000-1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              2000000000000000000000000000000000000000000000000000000000000000-3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              4000000000000000000000000000000000000000000000000000000000000000-5fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              6000000000000000000000000000000000000000000000000000000000000000-7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              8000000000000000000000000000000000000000000000000000000000000000-9fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              a000000000000000000000000000000000000000000000000000000000000000-bfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              c000000000000000000000000000000000000000000000000000000000000000-dfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              e000000000000000000000000000000000000000000000000000000000000000-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            partition_evenly(9):
              0000000000000000000000000000000000000000000000000000000000000000-1c71c71bffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              1c71c71c00000000000000000000000000000000000000000000000000000000-38e38e37ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              38e38e3800000000000000000000000000000000000000000000000000000000-55555553ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              5555555400000000000000000000000000000000000000000000000000000000-71c71c6fffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              71c71c7000000000000000000000000000000000000000000000000000000000-8e38e38bffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              8e38e38c00000000000000000000000000000000000000000000000000000000-aaaaaaa7ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              aaaaaaa800000000000000000000000000000000000000000000000000000000-c71c71c3ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              c71c71c400000000000000000000000000000000000000000000000000000000-e38e38dfffffffffffffffffffffffffffffffffffffffffffffffffffffffff
              e38e38e000000000000000000000000000000000000000000000000000000000-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        "#]].assert_eq(&buf);
    }
}
