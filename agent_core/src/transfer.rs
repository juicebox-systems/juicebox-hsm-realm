use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{debug, trace, warn};

use super::append::Append;
use super::{group_state, merkle, Agent, Transport};
use agent_api::merkle::TreeStoreError;
use agent_api::{
    CancelPreparedTransferRequest, CancelPreparedTransferResponse, CompleteTransferRequest,
    CompleteTransferResponse, GroupOwnsRangeRequest, GroupOwnsRangeResponse,
    PrepareTransferRequest, PrepareTransferResponse, TransferInRequest, TransferInResponse,
    TransferOutRequest, TransferOutResponse,
};
use hsm_api::merkle::{Dir, StoreDelta};
use hsm_api::{
    GroupId, GroupMemberRole, LogIndex, RealmStatus, RoleLogicalClock, StatusRequest,
    StatusResponse, TransferInProofs,
};
use juicebox_realm_api::types::RealmId;
use observability::metrics_tag as tag;
use retry_loop::RetryError;
use service_core::rpc::HandlerError;
use store::log::ReadLastLogEntryFatal;

impl<T: Transport + 'static> Agent<T> {
    pub(super) async fn handle_prepare_transfer(
        &self,
        request: PrepareTransferRequest,
    ) -> Result<PrepareTransferResponse, HandlerError> {
        type Response = PrepareTransferResponse;
        type HsmResponse = hsm_api::PrepareTransferResponse;

        match self
            .0
            .hsm
            .send(hsm_api::PrepareTransferRequest {
                realm: request.realm,
                source: request.source,
                destination: request.destination,
                range: request.range,
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::UnacceptableRange) => Ok(Response::UnacceptableRange),
            Ok(HsmResponse::OtherTransferPending) => Ok(Response::OtherTransferPending),
            Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
            Ok(HsmResponse::Ok(prepared)) => {
                if let Some(entry) = prepared.entry {
                    self.append(
                        request.realm,
                        request.destination,
                        Append {
                            entry,
                            delta: StoreDelta::default(),
                        },
                    )
                }
                match self
                    .wait_for_commit(
                        request.realm,
                        request.destination,
                        prepared.wait_til_committed,
                        prepared.clock,
                        Duration::from_secs(60),
                    )
                    .await
                {
                    WaitForCommitResult::Committed => Ok(Response::Ok {
                        nonce: prepared.nonce,
                        statement: prepared.statement,
                    }),
                    WaitForCommitResult::NotLeader => Ok(Response::NotLeader),
                    WaitForCommitResult::Timeout => {
                        warn!(realm=?request.realm, group=?request.destination, "Timed out waiting for the PrepareTransfer log entry to commit");
                        Ok(Response::CommitTimeout)
                    }
                }
            }
        }
    }

    pub(super) async fn handle_cancel_prepared_transfer(
        &self,
        request: CancelPreparedTransferRequest,
    ) -> Result<CancelPreparedTransferResponse, HandlerError> {
        type Response = CancelPreparedTransferResponse;
        type HsmResponse = hsm_api::CancelPreparedTransferResponse;

        match self
            .0
            .hsm
            .send(hsm_api::CancelPreparedTransferRequest {
                realm: request.realm,
                source: request.source,
                destination: request.destination,
                range: request.range,
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
            Ok(HsmResponse::NotPrepared) => Ok(Response::NotPrepared),
            Ok(HsmResponse::Ok { entry, clock }) => {
                let entry_index = entry.index;
                self.append(
                    request.realm,
                    request.destination,
                    Append {
                        entry,
                        delta: StoreDelta::default(),
                    },
                );
                match self
                    .wait_for_commit(
                        request.realm,
                        request.destination,
                        entry_index,
                        clock,
                        Duration::from_secs(60),
                    )
                    .await
                {
                    WaitForCommitResult::Committed => Ok(Response::Ok),
                    WaitForCommitResult::NotLeader => Ok(Response::NotLeader),
                    WaitForCommitResult::Timeout => Ok(Response::CommitTimeout),
                }
            }
        }
    }

    pub(super) async fn handle_transfer_out(
        &self,
        request: TransferOutRequest,
    ) -> Result<TransferOutResponse, HandlerError> {
        type Response = TransferOutResponse;
        type HsmResponse = hsm_api::TransferOutResponse;
        let realm = request.realm;
        let source = request.source;

        let hsm = &self.0.hsm;
        let store = &self.0.store;

        // This loop handles retries if the read from the store is stale. It's
        // expected to run just once.
        //
        // TODO: put some retry limit on this
        // TODO: replace ad hoc retry loop with retry_loop::Retry
        loop {
            let last_entry = match store
                .read_last_log_entry(&request.realm, &request.source)
                .await
            {
                Ok(entry) => entry,
                Err(
                    err @ RetryError::Fatal {
                        error: ReadLastLogEntryFatal::EmptyLog,
                    },
                ) => todo!("{err}"),
                Err(_) => return Ok(Response::NoStore),
            };
            // The transfer coordinator will recover from crashes and other issues by
            // walking through the entire transfer process from scratch again. That means
            // at this point the transfer out may have already been processed, and so the
            // partition information in the last log entry reflects that the transfer out
            // has already occurred. In that event we can't / don't need to build any proofs.
            let proof = match last_entry.transferring {
                None => {
                    let Some(partition) = last_entry.partition else {
                        return Ok(Response::NotOwner);
                    };

                    // if we're splitting, then we need the proof for the split point.
                    if partition.range == request.range {
                        None
                    } else {
                        let rec_id = match partition.range.split_at(&request.range) {
                            Some(id) => id,
                            None => return Ok(Response::UnacceptableRange),
                        };
                        match merkle::read(
                            &request.realm,
                            store,
                            &partition.range,
                            &partition.root_hash,
                            &rec_id,
                            &self.0.metrics,
                            &[tag!(?realm), tag!("group": ?source)],
                        )
                        .await
                        {
                            Ok(proof) => Some(proof),
                            Err(err @ TreeStoreError::MissingNode) => todo!("{err:?}"),
                            Err(TreeStoreError::Network(e)) => {
                                warn!(error = ?e, "handle_transfer_out: error reading proof");
                                return Ok(Response::NoStore);
                            }
                        }
                    }
                }
                Some(_) => None,
            };

            let transferring_partition = match hsm
                .send(hsm_api::TransferOutRequest {
                    realm: request.realm,
                    source: request.source,
                    destination: request.destination,
                    range: request.range.clone(),
                    nonce: request.nonce,
                    statement: request.statement.clone(),
                    proof,
                })
                .await
            {
                Err(_) => return Ok(Response::NoHsm),
                Ok(HsmResponse::InvalidRealm) => return Ok(Response::InvalidRealm),
                Ok(HsmResponse::InvalidGroup) => return Ok(Response::InvalidGroup),
                Ok(HsmResponse::NotLeader) => return Ok(Response::NotLeader),
                Ok(HsmResponse::NotOwner) => return Ok(Response::NotOwner),
                Ok(r @ HsmResponse::MissingProof) => todo!("{r:?}"),
                Ok(HsmResponse::InvalidProof) => return Ok(Response::InvalidProof),
                Ok(HsmResponse::InvalidStatement) => return Ok(Response::InvalidStatement),
                Ok(HsmResponse::OtherTransferPending) => return Ok(Response::OtherTransferPending),
                Ok(HsmResponse::StaleProof) => {
                    trace!("hsm said stale proof, will retry");
                    sleep(Duration::from_millis(1)).await;
                    continue;
                }
                Ok(HsmResponse::Ok {
                    entry,
                    delta,
                    partition: transferring_partition,
                    wait_til_committed,
                    clock,
                }) => {
                    match entry {
                        Some(entry) => self.append(realm, source, Append { entry, delta }),
                        None => assert!(delta.is_empty()),
                    }
                    match self
                        .wait_for_commit(
                            request.realm,
                            request.source,
                            wait_til_committed,
                            clock,
                            Duration::from_secs(60),
                        )
                        .await
                    {
                        WaitForCommitResult::Committed => {}
                        WaitForCommitResult::NotLeader => return Ok(Response::NotLeader),
                        WaitForCommitResult::Timeout => return Ok(Response::CommitTimeout),
                    }
                    transferring_partition
                }
            };

            // TODO: replace ad hoc retry loop with retry_loop::Retry
            loop {
                match self
                    .0
                    .hsm
                    .send(hsm_api::TransferStatementRequest {
                        realm: request.realm,
                        source: request.source,
                        destination: request.destination,
                        nonce: request.nonce,
                    })
                    .await
                {
                    Err(_) => return Ok(Response::NoHsm),
                    Ok(hsm_api::TransferStatementResponse::Ok(statement)) => {
                        return Ok(Response::Ok {
                            transferring: transferring_partition,
                            statement,
                        })
                    }
                    Ok(hsm_api::TransferStatementResponse::InvalidRealm) => {
                        return Ok(Response::InvalidRealm)
                    }
                    Ok(hsm_api::TransferStatementResponse::InvalidGroup) => {
                        return Ok(Response::InvalidGroup)
                    }
                    Ok(hsm_api::TransferStatementResponse::NotLeader) => {
                        return Ok(Response::NotLeader)
                    }
                    Ok(hsm_api::TransferStatementResponse::NotTransferring) => {
                        panic!("failed to generate transfer statement, HSM says not transferring");
                    }
                    Ok(hsm_api::TransferStatementResponse::Busy) => {
                        warn!(group=?request.source, index=?last_entry.index, "Agent thinks log entry is committed, but HSM does not");
                        sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
            }
        }
    }

    pub(super) async fn handle_transfer_in(
        &self,
        request: TransferInRequest,
    ) -> Result<TransferInResponse, HandlerError> {
        type Response = TransferInResponse;
        type HsmResponse = hsm_api::TransferInResponse;

        let hsm = &self.0.hsm;
        let store = &self.0.store;
        let tags = [
            tag!("realm": ?request.realm),
            tag!("group": ?request.destination),
        ];

        // This loop handles retries if the read from the store is stale. It's
        // expected to run just once.
        // TODO: replace ad hoc retry loop with retry_loop::Retry
        loop {
            let last_entry = match store
                .read_last_log_entry(&request.realm, &request.destination)
                .await
            {
                Ok(entry) => entry,
                Err(
                    err @ RetryError::Fatal {
                        error: ReadLastLogEntryFatal::EmptyLog,
                    },
                ) => todo!("{err}"),
                Err(_) => return Ok(Response::NoStore),
            };

            let proofs = match last_entry.partition {
                None => None,
                Some(partition) => match partition.range.join(&request.transferring.range) {
                    // An invalid TransferIn request might specify mismatched
                    // ranges. In this case we skip getting the proofs, and let
                    // the HSM decide the outcome (probably NotPrepared)
                    None => None,
                    Some(jr) => {
                        let proof_dir = if jr.start == request.transferring.range.start {
                            Dir::Right
                        } else {
                            Dir::Left
                        };

                        let transferring_in_proof_req = merkle::read_tree_side(
                            &request.realm,
                            store,
                            &request.transferring.range,
                            &request.transferring.root_hash,
                            proof_dir,
                            &tags,
                        );
                        let owned_range_proof_req = merkle::read_tree_side(
                            &request.realm,
                            store,
                            &partition.range,
                            &partition.root_hash,
                            proof_dir.opposite(),
                            &tags,
                        );
                        let transferring_in_proof = match transferring_in_proof_req.await {
                            Err(TreeStoreError::Network(_)) => return Ok(Response::NoStore),
                            Err(err @ TreeStoreError::MissingNode) => todo!("{err:?}"),
                            Ok(proof) => proof,
                        };
                        let owned_range_proof = match owned_range_proof_req.await {
                            Err(TreeStoreError::Network(_)) => return Ok(Response::NoStore),
                            Err(err @ TreeStoreError::MissingNode) => todo!("{err:?}"),
                            Ok(proof) => proof,
                        };
                        Some(TransferInProofs {
                            owned: owned_range_proof,
                            transferring: transferring_in_proof,
                        })
                    }
                },
            };

            return match hsm
                .send(hsm_api::TransferInRequest {
                    realm: request.realm,
                    source: request.source,
                    destination: request.destination,
                    transferring: request.transferring.clone(),
                    proofs,
                    nonce: request.nonce,
                    statement: request.statement.clone(),
                })
                .await
            {
                Err(_) => Ok(Response::NoHsm),
                Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
                Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
                Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
                Ok(HsmResponse::InvalidNonce) => Ok(Response::InvalidNonce),
                Ok(HsmResponse::InvalidStatement) => Ok(Response::InvalidStatement),
                Ok(HsmResponse::NotPrepared) => Ok(Response::NotPrepared),
                Ok(r @ HsmResponse::InvalidProof) => todo!("{r:?}"),
                Ok(r @ HsmResponse::MissingProofs) => todo!("{r:?}"),
                Ok(HsmResponse::StaleProof) => {
                    trace!(?hsm, "hsm said stale proof, will retry");
                    // TODO: slow down and/or limit attempts
                    continue;
                }
                Ok(HsmResponse::Ok {
                    entry,
                    delta,
                    clock,
                }) => {
                    let index = entry.index;
                    self.append(request.realm, request.destination, Append { entry, delta });
                    match self
                        .wait_for_commit(
                            request.realm,
                            request.destination,
                            index,
                            clock,
                            Duration::from_secs(60),
                        )
                        .await
                    {
                        WaitForCommitResult::Committed => Ok(Response::Ok),
                        WaitForCommitResult::NotLeader => Ok(Response::NotLeader),
                        WaitForCommitResult::Timeout => Ok(Response::CommitTimeout),
                    }
                }
            };
        }
    }

    pub(super) async fn handle_complete_transfer(
        &self,
        request: CompleteTransferRequest,
    ) -> Result<CompleteTransferResponse, HandlerError> {
        type Response = CompleteTransferResponse;
        type HsmResponse = hsm_api::CompleteTransferResponse;
        let hsm = &self.0.hsm;

        let result = hsm
            .send(hsm_api::CompleteTransferRequest {
                realm: request.realm,
                source: request.source,
                destination: request.destination,
                range: request.range,
            })
            .await;
        match result {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
            Ok(HsmResponse::NotTransferring) => Ok(Response::NotTransferring),
            Ok(HsmResponse::Ok { entry, clock }) => {
                let index = entry.index;
                self.append(
                    request.realm,
                    request.source,
                    Append {
                        entry,
                        delta: StoreDelta::default(),
                    },
                );
                match self
                    .wait_for_commit(
                        request.realm,
                        request.source,
                        index,
                        clock,
                        Duration::from_secs(60),
                    )
                    .await
                {
                    WaitForCommitResult::Committed => Ok(Response::Ok),
                    WaitForCommitResult::NotLeader => Ok(Response::NotLeader),
                    WaitForCommitResult::Timeout => Ok(Response::CommitTimeout),
                }
            }
        }
    }
    pub(super) async fn handle_group_owns_range(
        &self,
        request: GroupOwnsRangeRequest,
    ) -> Result<GroupOwnsRangeResponse, HandlerError> {
        type Response = GroupOwnsRangeResponse;
        let hsm = &self.0.hsm;

        let (wait_for_index, role) = match hsm.send(StatusRequest {}).await {
            Err(_) => return Ok(Response::NoHsm),
            Ok(StatusResponse {
                realm: Some(RealmStatus { id, groups, .. }),
                ..
            }) if id == request.realm => {
                let Some(gs) = groups.into_iter().find(|gs| gs.id == request.group) else {
                    return Ok(Response::InvalidGroup);
                };
                let Some(ls) = gs.leader else {
                    return Ok(Response::NotLeader);
                };
                if ls.transferring.is_some() {
                    return Ok(Response::TransferInProgress);
                }
                if !ls
                    .owned_range
                    .as_ref()
                    .is_some_and(|owned| owned.contains_range(&request.range))
                {
                    return Ok(Response::NotOwned {
                        has: ls.owned_range,
                    });
                }
                if Some(ls.last) == ls.committed {
                    return Ok(Response::Ok);
                }
                (ls.last, gs.role)
            }
            Ok(_) => return Ok(Response::InvalidRealm),
        };

        match self
            .wait_for_commit(
                request.realm,
                request.group,
                wait_for_index,
                role.at,
                Duration::from_secs(60),
            )
            .await
        {
            WaitForCommitResult::Committed => Ok(Response::Ok),
            WaitForCommitResult::NotLeader => Ok(Response::NotLeader),
            WaitForCommitResult::Timeout => Ok(Response::TimedOut),
        }
    }

    async fn wait_for_commit(
        &self,
        realm: RealmId,
        group: GroupId,
        // The LogIndex we're waiting to be committed.
        wait_for_index: LogIndex,
        // The leaders role clock at the time `wait_for_index` was generated.
        clock_at_index: RoleLogicalClock,
        timeout: Duration,
    ) -> WaitForCommitResult {
        let start = Instant::now();
        loop {
            {
                let locked = self.0.state.lock().unwrap();
                let gs = group_state(&locked.groups, realm, group);
                if !(gs.role.at == clock_at_index
                    || (gs.role.at == clock_at_index.next()
                        && matches!(gs.role.role, GroupMemberRole::SteppingDown { .. })))
                {
                    // In order for this to be safe, we need to have been
                    // leader, or stepping down from leader for the entire
                    // duration since the HSM indicated the log index to wait
                    // for.
                    return WaitForCommitResult::NotLeader;
                }
                match &gs.leader {
                    None => return WaitForCommitResult::NotLeader,
                    Some(leader) if leader.committed >= Some(wait_for_index) => {
                        debug!(?group, committed=?leader.committed, wait_for=?wait_for_index, "log index committed");
                        return WaitForCommitResult::Committed;
                    }
                    Some(leader) => {
                        debug!(?group, committed=?leader.committed, wait_for=?wait_for_index, "waiting for log entry to commit");
                    }
                }
            }
            if start.elapsed() > timeout {
                warn!(?group, "timed out waiting for log entry to be committed");
                return WaitForCommitResult::Timeout;
            }
            sleep(Duration::from_millis(10)).await;
        }
    }
}

enum WaitForCommitResult {
    /// The requested index is committed.
    Committed,
    /// Not leader for the group, or lost leadership while waiting.
    NotLeader,
    /// Timed out waiting for the entry to be committed.
    Timeout,
}
