use futures::future::join_all;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use super::{ManagementGrant, ManagementLeaseKey, Manager};
use agent_api::{
    CompleteTransferRequest, CompleteTransferResponse, GroupOwnsRangeRequest,
    GroupOwnsRangeResponse,
};
use cluster_api::{TransferError, TransferRequest, TransferSuccess};
use cluster_core::{
    discover_hsm_statuses, find_leader, perform_transfer, range_owners, wait_for_management_grant,
    HsmStatuses, WaitForGrantError,
};
use hsm_api::{GroupId, OwnedRange, Transferring, TransferringIn, TransferringOut};
use juicebox_networking::rpc::{self, RpcError};
use juicebox_realm_api::types::RealmId;
use service_core::rpc::HandlerError;
use tracing::{debug, info, warn};

impl Manager {
    pub(super) async fn handle_transfer(
        &self,
        req: cluster_api::TransferRequest,
    ) -> Result<Result<TransferSuccess, TransferError>, HandlerError> {
        info!(realm=?req.realm, source=?req.source, destination=?req.destination, range=%req.range,
            "starting ownership transfer");

        // As the management grants are dropped async, you can end up where
        // doing a transfer followed by another one will fail because the grant
        // is not available yet. So wait for a small amount of time for it to be
        // available to simplify the callers.
        let result = match wait_for_management_grant(
            self.0.store.clone(),
            self.0.name.clone(),
            ManagementLeaseKey::Ownership(req.realm),
            Duration::from_secs(1),
        )
        .await
        {
            Ok(grant) => perform_transfer(&self.0.store, &self.0.agents, &grant, None, req)
                .await
                .map_err(|e| e.last().unwrap_or(TransferError::Timeout)),
            Err(WaitForGrantError::Timeout) => Err(TransferError::ManagerBusy),
            Err(err) => {
                warn!(?err, "failed to get management lease");
                Err(TransferError::ManagerBusy)
            }
        };
        info!(?result, "ownership transfer done");
        Ok(result)
    }

    pub(super) async fn ensure_transfers_finished(&self) -> Result<(), TransferError> {
        let hsm_statuses = discover_hsm_statuses(&self.0.store, &self.0.agents)
            .await
            .map_err(|_| TransferError::NoStore)?;

        let realms_with_transfers: HashSet<RealmId> = hsm_statuses
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
            match ManagementGrant::obtain(
                self.0.store.clone(),
                self.0.name.clone(),
                ManagementLeaseKey::Ownership(realm),
            )
            .await
            {
                Ok(Some(grant)) => {
                    self.ensure_realm_transfers_finished(realm, grant).await?;
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
        grant: ManagementGrant,
    ) -> Result<(), TransferError> {
        // now we have the lease, get a fresh set of status's / transfers
        let hsms_status = discover_hsm_statuses(&self.0.store, &self.0.agents)
            .await
            .map_err(|_| TransferError::NoStore)?;

        // A list of groups with Prepared Transfers. The groupId is the
        // destination group.
        let mut transfer_ins: Vec<(GroupId, TransferringIn)> = Vec::new();
        // Groups that have uncompleted TransferOuts. The groupId is the source
        // group.
        let mut transfer_outs: HashMap<GroupId, TransferringOut> = HashMap::new();
        for (sr, _) in hsms_status.values() {
            if let Some(rs) = sr.realm.as_ref() {
                if rs.id == realm {
                    for gs in rs.groups.iter() {
                        if let Some(ls) = gs.leader.as_ref() {
                            match ls.transferring.as_ref() {
                                Some(Transferring::In(tin)) if ls.committed >= Some(tin.at) => {
                                    transfer_ins.push((gs.id, tin.clone()));
                                }
                                Some(Transferring::Out(tout)) if ls.committed >= Some(tout.at) => {
                                    transfer_outs.insert(gs.id, tout.clone());
                                }
                                Some(_) | None => {}
                            }
                        }
                    }
                }
            }
        }

        for (destination, t_in) in transfer_ins {
            let source = t_in.source;
            // ensure the status's we're looking at include both the source & destination leaders.
            if find_leader(&hsms_status, realm, destination).is_none()
                || find_leader(&hsms_status, realm, source).is_none()
            {
                warn!(
                    ?realm,
                    ?source,
                    ?destination,
                    range=%t_in.range,
                    "skipping resolving pending transfer due to missing leader(s), will retry later"
                );
                continue;
            }
            // re-run the transfer to get it to completion.
            transfer_outs.remove(&source);
            info!(?realm, ?source, ?destination, range=%t_in.range, "found PreparedTransfer, re-running transfer");
            if let Err(err) = cluster_core::perform_transfer(
                &self.0.store,
                &self.0.agents,
                &grant,
                None,
                TransferRequest {
                    realm,
                    source,
                    destination,
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
                    range = ?t_in.range,
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
                    range=%t_out.partition.range,
                    "skipping resolving pending transfer due to missing leader(s)"
                );
                continue;
            }
            match range_owners(
                hsms_status.values().map(|(s, _url)| s),
                realm,
                &t_out.partition.range,
            ) {
                None => {
                    warn!(?realm, source=?source, ?destination, range=%t_out.partition.range,
                        "found TransferOut with no matching PreparedTransfer. range is not fully owned! doing nothing. Will retry later");
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
                        warn!(?realm, ?source, ?destination, range=%t_out.partition.range,
                            "failed to verify range ownership, doing nothing. Will retry later");
                        continue;
                    }
                    info!(?realm, ?source, ?destination, range=%t_out.partition.range,
                        "found TransferOut with no matching PreparedTransfer. Transferred range is fully owned. Marking it complete");
                    if let Err(err) = self
                        .complete_transfer(
                            &hsms_status,
                            realm,
                            source,
                            destination,
                            t_out.partition.range.clone(),
                        )
                        .await
                    {
                        warn!(
                            ?err, ?realm, ?source, ?destination, range=%t_out.partition.range,
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
        hsms_status: &HsmStatuses,
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
                warn!(%err, ?realm, ?group, %range, "RPC error while trying to confirm range ownership");
            }
            Ok(resp) => {
                if matches!(resp, GroupOwnsRangeResponse::Ok) {
                    info!(?realm, ?group, %range, %leader, "has confirmed ownership of range");
                } else {
                    warn!(
                        ?realm,
                        ?group,
                        %range,
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
        s: &HsmStatuses,
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
                // This shouldn't be possible if the caller verified that the
                // source has a transferOut while holding the management grant.
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
