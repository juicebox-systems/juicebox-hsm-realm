use std::collections::{HashMap, HashSet};
use std::time::Duration;

use super::{find_leader, HsmsStatus, ManagementGrant, ManagementLeaseKey, Manager};
use agent_api::{
    CompleteTransferRequest, CompleteTransferResponse, GroupOwnsRangeRequest,
    GroupOwnsRangeResponse,
};
use cluster_api::{TransferError, TransferRequest, TransferSuccess};
use futures::future::join_all;
use hsm_api::{GroupId, LeaderStatus, OwnedRange, Transferring, TransferringIn, TransferringOut};
use juicebox_networking::rpc::{self, RpcError};
use juicebox_realm_api::types::RealmId;
use service_core::rpc::HandlerError;
use tracing::{debug, info, warn};

impl Manager {
    pub(super) async fn handle_transfer(
        &self,
        req: cluster_api::TransferRequest,
    ) -> Result<Result<TransferSuccess, TransferError>, HandlerError> {
        info!(?req, "starting ownership transfer");
        let result = self.handle_transfer_inner(req).await;
        info!(?result, "ownership transfer done");
        Ok(result)
    }

    async fn handle_transfer_inner(
        &self,
        req: cluster_api::TransferRequest,
    ) -> Result<TransferSuccess, TransferError> {
        match ManagementGrant::obtain(self.clone(), ManagementLeaseKey::Ownership(req.realm)).await
        {
            Ok(Some(_grant)) => {
                cluster_core::transfer(&self.0.store, &self.0.agents, req).await?;
                Ok(TransferSuccess {})
            }
            Ok(None) => Err(TransferError::ManagerBusy),
            Err(err) => {
                warn!(?err, "failed to get management lease");
                Err(TransferError::ManagerBusy)
            }
        }
    }

    pub(super) async fn ensure_transfers_finished(&self) -> Result<(), TransferError> {
        let realms_with_transfers: HashSet<RealmId> = self
            .0
            .status
            .status(Duration::from_millis(20))
            .await
            .map_err(|_| TransferError::NoStore)?
            .into_values()
            .filter_map(|(s, _)| s.realm)
            .flat_map(|rs| {
                rs.groups
                    .into_iter()
                    .filter(|g| g.leader.as_ref().is_some_and(|l| l.transferring.is_some()))
                    .map(move |_| rs.id)
            })
            .collect();

        for realm in realms_with_transfers {
            match ManagementGrant::obtain(self.clone(), ManagementLeaseKey::Ownership(realm)).await
            {
                Ok(Some(grant)) => {
                    self.ensure_realm_transfers_finished(realm, grant).await?;
                    self.0.status.mark_dirty();
                }
                Ok(None) => {
                    debug!(
                        ?realm,
                        "skipping ensure_realm_transfers_finished, unable to get lease"
                    );
                }
                Err(err) => {
                    warn!(?err, "failed to get management lease");
                }
            }
        }
        Ok(())
    }

    async fn ensure_realm_transfers_finished(
        &self,
        realm: RealmId,
        _grant: ManagementGrant,
    ) -> Result<(), TransferError> {
        // now we have the lease, get a fresh set of status's / transfers
        let hsms_status = self
            .0
            .status
            .refresh()
            .await
            .map_err(|_| TransferError::NoStore)?;

        // A list of groups with Prepared Transfers. The groupId is the
        // destination group.
        type TransferringIns = Vec<Option<(GroupId, TransferringIn)>>;
        // A list of groups that have uncompleted TransferOuts. The groupId is
        // the source group.
        type TransferringOuts = Vec<Option<(GroupId, TransferringOut)>>;

        let (transfer_ins, transfer_outs): (TransferringIns, TransferringOuts) = hsms_status
            .clone()
            .into_values()
            .filter_map(|(s, _)| s.realm)
            .filter(|rs| rs.id == realm)
            .flat_map(|rs| {
                rs.groups.into_iter().filter_map(|gs| match gs.leader {
                    Some(LeaderStatus {
                        committed,
                        transferring: Some(Transferring::Out(tout)),
                        ..
                    }) if committed >= Some(tout.at) => Some((None, Some((gs.id, tout)))),

                    Some(LeaderStatus {
                        committed,
                        transferring: Some(Transferring::In(tin)),
                        ..
                    }) if committed >= Some(tin.at) => Some((Some((gs.id, tin)), None)),
                    Some(_) | None => None,
                })
            })
            .unzip();

        let mut transfer_outs: HashMap<GroupId, TransferringOut> =
            transfer_outs.into_iter().flatten().collect();

        for (destination, t_in) in transfer_ins.iter().flatten() {
            let source = t_in.source;
            // ensure the status's we're looking at include both the source & destination leaders.
            if find_leader(&hsms_status, realm, *destination).is_none()
                || find_leader(&hsms_status, realm, source).is_none()
            {
                warn!(
                    ?realm,
                    ?source,
                    ?destination,
                    "skipping resolving pending transfer due to missing leader(s)"
                );
                continue;
            }
            // re-run the transfer to get it to completion.
            transfer_outs.remove(&source);
            info!(?realm, ?source, ?destination, range=?t_in.range, "found PreparedTransfer, re-running transfer");
            if let Err(err) = cluster_core::transfer(
                &self.0.store,
                &self.0.agents,
                TransferRequest {
                    realm,
                    source,
                    destination: *destination,
                    range: t_in.range.clone(),
                },
            )
            .await
            {
                warn!(
                    ?err,
                    ?realm,
                    ?source,
                    ?destination,
                    "transfer failed while attempting to complete existing partial transfer"
                );
            }
        }

        // TransferOuts with no matching TransferIn. This transfer has
        // completed, verify that someone owns the transfer out range, and then
        // tell the source its completed.
        for (source, t_out) in transfer_outs {
            let destination = t_out.destination;
            // ensure the status's we're looking at include both the source & destination leaders.
            if find_leader(&hsms_status, realm, destination).is_none()
                || find_leader(&hsms_status, realm, source).is_none()
            {
                warn!(
                    ?realm,
                    ?source,
                    ?destination,
                    "skipping resolving pending transfer due to missing leader(s)"
                );
                continue;
            }
            match range_owners(&hsms_status, realm, &t_out.partition.range) {
                None => {
                    warn!(?realm, source=?source, ?destination, range=?t_out.partition.range,
                        "found TransferOut with no matching PreparedTransfer. range is not fully owned! doing nothing");
                    continue;
                }
                Some(owners) => {
                    assert!(!owners.is_empty());
                    // for each owner have them verify ownership and that the ownership info is committed.
                    let results = join_all(owners.into_iter().map(|(group, range)| {
                        self.confirm_range_owner(&hsms_status, realm, group, range)
                    }))
                    .await;
                    if !results
                        .into_iter()
                        .all(|r| matches!(r, Ok(GroupOwnsRangeResponse::Ok)))
                    {
                        // confirm_range_owner logged all the individual results.
                        warn!(?realm, ?source, ?destination, range=?t_out.partition.range,
                            "failed to verify range ownership, doing nothing");
                        continue;
                    }
                    info!(?realm, ?source, ?destination, range=?t_out.partition.range,
                        "found TransferOut with no matching PreparedTransfer. Transferred range is fully owned, marking it complete");
                    if let Err(err) = self
                        .complete_transfer(
                            &hsms_status,
                            realm,
                            source,
                            destination,
                            t_out.partition.range,
                        )
                        .await
                    {
                        warn!(
                            ?err,
                            "failed to complete transfer for existing partial transfer"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    async fn confirm_range_owner(
        &self,
        hsms_status: &HsmsStatus,
        realm: RealmId,
        group: GroupId,
        range: OwnedRange,
    ) -> Result<GroupOwnsRangeResponse, RpcError> {
        let Some((_, leader)) = find_leader(hsms_status, realm, group) else {
            return Ok(GroupOwnsRangeResponse::NotLeader);
        };

        let result = rpc::send(
            &self.0.agents,
            &leader,
            GroupOwnsRangeRequest {
                realm,
                group,
                range: range.clone(),
            },
        )
        .await;
        match &result {
            Err(err) => {
                warn!(%err, ?realm, ?group, ?range, "RPC error while trying to confirm range ownership");
            }
            Ok(resp) => {
                if matches!(resp, GroupOwnsRangeResponse::Ok) {
                    info!(?realm, ?group, ?range, %leader, "has confirmed ownership of range");
                } else {
                    warn!(
                        ?realm,
                        ?group,
                        ?range,
                        %leader,
                        ?resp,
                        "did not confirm ownership of range"
                    );
                }
            }
        }
        result
    }

    async fn complete_transfer(
        &self,
        s: &HsmsStatus,
        realm: RealmId,
        source: GroupId,
        destination: GroupId,
        range: OwnedRange,
    ) -> Result<(), TransferError> {
        let Some((_, src_leader)) = find_leader(s, realm, source) else {
            return Err(TransferError::NoSourceLeader);
        };

        match rpc::send(
            &self.0.agents,
            &src_leader,
            CompleteTransferRequest {
                realm,
                source,
                destination,
                range,
            },
        )
        .await
        {
            Ok(CompleteTransferResponse::Ok) => Ok(()),
            Ok(CompleteTransferResponse::CommitTimeout) => Err(TransferError::CommitTimeout),
            Ok(CompleteTransferResponse::InvalidGroup) => unreachable!(),
            Ok(CompleteTransferResponse::InvalidRealm) => unreachable!(),
            Ok(CompleteTransferResponse::NotLeader | CompleteTransferResponse::NoHsm) => {
                Err(TransferError::NoSourceLeader)
            }
            Ok(CompleteTransferResponse::NotTransferring) => {
                warn!("CompleteTransfer on pending transfer failed with NotTransferring");
                Ok(())
            }
            Err(err) => {
                warn!(%err, "RPC error while trying to mark transfer completed");
                Err(TransferError::RpcError(err))
            }
        }
    }
}

// extracts the range owners from the provided StatusRequest results and returns
// the set of owners that cover `range_to_check`. If `range_to_check` is not
// fully covered None is returned.
fn range_owners(
    hsm_status: &HsmsStatus,
    realm: RealmId,
    range_to_check: &OwnedRange,
) -> Option<Vec<(GroupId, OwnedRange)>> {
    let ranges: Vec<(GroupId, OwnedRange)> = hsm_status
        .values()
        .filter_map(|(s, _)| s.realm.as_ref())
        .filter(|rs| rs.id == realm)
        .flat_map(|rs| rs.groups.iter())
        .filter_map(|gs| {
            gs.leader
                .as_ref()
                .and_then(|ls| ls.owned_range.as_ref().map(|r| (gs.id, r.clone())))
        })
        .collect();
    range_is_covered(ranges, range_to_check)
}

// If the provided set of range owners fully cover the `range_to_check`, then
// the range owners that own part of `range_to_check` are returned. If
// `range_to_check` is not fully covered, then None is returned.
//
// This is broken out to simplify testing.
fn range_is_covered(
    mut owners: Vec<(GroupId, OwnedRange)>,
    range_to_check: &OwnedRange,
) -> Option<Vec<(GroupId, OwnedRange)>> {
    owners.retain(|(_, r)| range_to_check.overlaps(r));
    owners.sort_by(|a, b| a.1.start.cmp(&b.1.start));

    if !owners.is_empty()
        && owners
            .windows(2)
            .all(|pair| pair[0].1.end.next() == Some(pair[1].1.start.clone()))
        && owners[0].1.start <= range_to_check.start
        && owners.last().unwrap().1.end >= range_to_check.end
    {
        Some(owners)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::range_is_covered;
    use hsm_api::{GroupId, OwnedRange, RecordId};

    #[test]
    fn test_range_is_covered() {
        let gids: Vec<GroupId> = (0..3).map(|i| GroupId([i; 16])).collect();

        assert!(
            range_is_covered(vec![(gids[0], OwnedRange::full())], &OwnedRange::full()).is_some()
        );
        assert!(range_is_covered(vec![(gids[0], OwnedRange::full())], &mkrange(0, 15)).is_some());
        assert!(
            range_is_covered(vec![(gids[0], OwnedRange::full())], &mkrange(0xfe, 0xff)).is_some()
        );
        assert!(range_is_covered(
            vec![(gids[0], mkrange(0, 15)), (gids[1], mkrange(16, 0xff))],
            &OwnedRange::full()
        )
        .is_some());
        // input not in order
        assert!(range_is_covered(
            vec![
                (gids[0], mkrange(11, 15)),
                (gids[1], mkrange(0, 10)),
                (gids[2], mkrange(16, 0xff))
            ],
            &OwnedRange::full()
        )
        .is_some());
        // hole in range, but not in the range we're checking
        assert!(range_is_covered(
            vec![
                (gids[0], mkrange(11, 15)),
                (gids[1], mkrange(0, 9)),
                (gids[2], mkrange(16, 0xff))
            ],
            &mkrange(12, 22)
        )
        .is_some());

        assert!(range_is_covered(
            vec![(gids[0], mkrange(1, 15)), (gids[1], mkrange(16, 0xff))],
            &OwnedRange::full()
        )
        .is_none());
        assert!(range_is_covered(
            vec![(gids[0], mkrange(0, 15)), (gids[1], mkrange(16, 0xfe))],
            &OwnedRange::full()
        )
        .is_none());
        assert!(range_is_covered(
            vec![(gids[0], mkrange(0, 15)), (gids[1], mkrange(17, 0xff))],
            &OwnedRange::full()
        )
        .is_none());
        assert!(range_is_covered(
            vec![
                (gids[0], mkrange(11, 15)),
                (gids[1], mkrange(0, 9)),
                (gids[2], mkrange(16, 0xff))
            ],
            &OwnedRange::full()
        )
        .is_none());
        assert!(range_is_covered(
            vec![
                (gids[0], mkrange(11, 15)),
                (gids[1], mkrange(0, 9)),
                (gids[2], mkrange(16, 0xff))
            ],
            &mkrange(5, 13)
        )
        .is_none());
    }

    fn mkrange(s: u8, e: u8) -> OwnedRange {
        let mut start = RecordId::min_id();
        start.0[0] = s;
        let mut end = RecordId::max_id();
        end.0[0] = e;
        OwnedRange { start, end }
    }
}
