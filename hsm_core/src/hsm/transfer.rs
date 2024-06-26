use tracing::{instrument, warn};

use super::super::hal::{CryptoRng, Platform};
use super::super::merkle::{proof::ProofError, MergeError, Tree};
use super::mac::{CtMac, PreparedTransferStatementMessage, TransferStatementMessage};
use super::{is_group_leader, GroupLeaderError, Hsm, LogEntryBuilder, Metrics};
use hsm_api::merkle::StoreDelta;
use hsm_api::{
    CancelPreparedTransferRequest, CancelPreparedTransferResponse, CompleteTransferRequest,
    CompleteTransferResponse, Partition, PrepareTransferRequest, PrepareTransferResponse,
    PreparedTransfer, TransferInRequest, TransferInResponse, TransferNonce, TransferOutRequest,
    TransferOutResponse, TransferStatementRequest, TransferStatementResponse, Transferring,
    TransferringIn, TransferringOut,
};

impl<P: Platform> Hsm<P> {
    #[instrument(level = "trace", skip(self, _metrics), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_prepare_transfer(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: PrepareTransferRequest,
    ) -> PrepareTransferResponse {
        type Response = PrepareTransferResponse;

        if request.destination == request.source {
            return Response::InvalidGroup;
        }
        if !request.range.is_valid() {
            return Response::UnacceptableRange;
        }

        let leader = match is_group_leader(
            &self.persistent,
            &mut self.volatile.groups,
            request.realm,
            request.destination,
        ) {
            Ok(leader) => leader,
            Err(GroupLeaderError::InvalidRealm) => return Response::InvalidRealm,
            Err(GroupLeaderError::InvalidGroup) => return Response::InvalidGroup,
            Err(GroupLeaderError::NotLeader(_)) => return Response::NotLeader,
        };
        let last_entry = &leader.log.last().entry;

        let (entry, wait_til_committed) = match &last_entry.transferring {
            None => {
                // No other transfer pending, can proceed.
                if let Some(part) = &leader.log.last().entry.partition {
                    if part.range.join(&request.range).is_none() {
                        return Response::UnacceptableRange;
                    }
                }

                let index = last_entry.index.next();
                let entry = LogEntryBuilder {
                    hsm: self.persistent.id,
                    realm: request.realm,
                    group: request.destination,
                    index,
                    partition: last_entry.partition.clone(),
                    transferring: Some(Transferring::In(TransferringIn {
                        source: request.source,
                        range: request.range.clone(),
                        at: index,
                    })),
                    prev_mac: last_entry.entry_mac.clone(),
                }
                .build(&self.realm_keys.mac);

                leader.log.append(entry.clone(), None);
                (Some(entry), index)
            }
            Some(Transferring::Out(_)) => {
                // Can't accept an inbound transfer while we're still transferring out.
                return Response::OtherTransferPending;
            }
            Some(Transferring::In(transferring))
                if transferring.source == request.source && transferring.range == request.range =>
            {
                // This transfer was already prepared.
                (None, transferring.at)
            }
            Some(_) => {
                return Response::OtherTransferPending;
            }
        };

        let nonce = create_random_transfer_nonce(&mut self.platform);
        leader.incoming = Some(nonce);

        let clock = self
            .volatile
            .groups
            .get(&request.destination)
            .expect("already validated this is a member of the group")
            .at;

        let prepared_stmt =
            self.realm_keys
                .mac
                .prepared_transfer_mac(&PreparedTransferStatementMessage {
                    realm: request.realm,
                    source: request.source,
                    destination: request.destination,
                    range: &request.range,
                    nonce,
                });

        Response::Ok(PreparedTransfer {
            nonce,
            wait_til_committed,
            entry,
            clock,
            statement: prepared_stmt,
        })
    }

    #[instrument(level = "trace", skip(self, _metrics), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_transfer_out(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: TransferOutRequest,
    ) -> TransferOutResponse {
        type Response = TransferOutResponse;

        if request.source == request.destination {
            return Response::InvalidGroup;
        }
        if !request.range.is_valid() {
            return Response::NotOwner;
        }

        let leader = match is_group_leader(
            &self.persistent,
            &mut self.volatile.groups,
            request.realm,
            request.source,
        ) {
            Ok(leader) => leader,
            Err(GroupLeaderError::InvalidRealm) => return Response::InvalidRealm,
            Err(GroupLeaderError::InvalidGroup) => return Response::InvalidGroup,
            Err(GroupLeaderError::NotLeader(_)) => return Response::NotLeader,
        };

        let last_entry = &leader.log.last().entry;

        if self
            .realm_keys
            .mac
            .prepared_transfer_mac(&PreparedTransferStatementMessage {
                realm: request.realm,
                source: request.source,
                destination: request.destination,
                range: &request.range,
                nonce: request.nonce,
            })
            .verify(&request.statement)
            .is_err()
        {
            return Response::InvalidStatement;
        }

        match last_entry.transferring.as_ref() {
            None => {
                // No in progress transfer out, can start a new one.
            }
            Some(Transferring::In(_)) => {
                // Can't transfer out while we're waiting for a transfer_in to arrive.
                return Response::OtherTransferPending;
            }
            Some(Transferring::Out(transferring))
                if transferring.destination == request.destination
                    && transferring.partition.range == request.range =>
            {
                // request is the for the same thing we're already doing.
                let transferring_partition = transferring.partition.clone();
                let wait_til_committed = transferring.at;

                let clock = self
                    .volatile
                    .groups
                    .get(&request.source)
                    .expect("We already verified we're a member of the group")
                    .at;

                return Response::Ok {
                    entry: None,
                    delta: StoreDelta::default(),
                    partition: transferring_partition,
                    wait_til_committed,
                    clock,
                };
            }
            Some(Transferring::Out(_)) => return Response::OtherTransferPending,
        }

        // Note: The owned_range found in the last entry might not have
        // committed yet. We think that's OK. The source group won't
        // produce a transfer statement unless this last entry and the
        // transferring out entry have committed.
        let Some(owned_partition) = &last_entry.partition else {
            return Response::NotOwner;
        };

        // This supports two options: moving out the entire owned range or
        // splitting the range in two at some key and moving out one of the
        // resulting trees.
        let keeping_partition: Option<Partition>;
        let transferring_partition: Partition;
        let delta;

        if request.range == owned_partition.range {
            keeping_partition = None;
            transferring_partition = owned_partition.clone();
            delta = StoreDelta::default();
        } else {
            let Some(request_proof) = request.proof else {
                return Response::MissingProof;
            };
            match owned_partition.range.split_at(&request.range) {
                None => return Response::NotOwner,
                Some(key) => {
                    if key != request_proof.key {
                        return Response::MissingProof;
                    }
                }
            }
            let tree = leader
                .tree
                .take()
                .expect("tree must be set if leader owns a partition");
            let (keeping, transferring, split_delta) = match tree.range_split(request_proof) {
                Err(ProofError::Stale) => return Response::StaleProof,
                Err(ProofError::Invalid) => return Response::InvalidProof,
                Ok(split) => {
                    if split.left.range == request.range {
                        (split.right, split.left, split.delta)
                    } else if split.right.range == request.range {
                        (split.left, split.right, split.delta)
                    } else {
                        panic!(
                            "The tree was split but neither half contains the expected key range."
                        );
                    }
                }
            };
            keeping_partition = Some(Partition {
                root_hash: keeping.root_hash,
                range: keeping.range,
            });
            transferring_partition = Partition {
                root_hash: transferring.root_hash,
                range: transferring.range,
            };
            delta = split_delta;
        }

        leader.tree = keeping_partition
            .as_ref()
            .map(|p| Tree::with_existing_root(p.root_hash, self.options.tree_overlay_size));

        let index = last_entry.index.next();
        let entry = LogEntryBuilder {
            hsm: self.persistent.id,
            realm: request.realm,
            group: request.source,
            index,
            partition: keeping_partition,
            transferring: Some(Transferring::Out(TransferringOut {
                destination: request.destination,
                partition: transferring_partition.clone(),
                at: index,
            })),
            prev_mac: last_entry.entry_mac.clone(),
        }
        .build(&self.realm_keys.mac);

        leader.log.append(entry.clone(), None);

        let clock = self
            .volatile
            .groups
            .get(&request.source)
            .expect("We already verified we're a member of the group")
            .at;

        TransferOutResponse::Ok {
            wait_til_committed: entry.index,
            entry: Some(entry),
            delta,
            clock,
            partition: transferring_partition,
        }
    }

    #[instrument(level = "trace", skip(self, _metrics), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_transfer_statement(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: TransferStatementRequest,
    ) -> TransferStatementResponse {
        type Response = TransferStatementResponse;

        if request.source == request.destination {
            return Response::InvalidGroup;
        }

        let leader = match is_group_leader(
            &self.persistent,
            &mut self.volatile.groups,
            request.realm,
            request.source,
        ) {
            Ok(leader) => leader,
            Err(GroupLeaderError::InvalidRealm) => return Response::InvalidRealm,
            Err(GroupLeaderError::InvalidGroup) => return Response::InvalidGroup,
            Err(GroupLeaderError::NotLeader(_)) => return Response::NotLeader,
        };

        let Some(Transferring::Out(TransferringOut {
            destination,
            partition,
            at: transferring_at,
        })) = &leader.log.last().entry.transferring
        else {
            return Response::NotTransferring;
        };
        if *destination != request.destination {
            return Response::NotTransferring;
        }
        if !matches!(leader.committed, Some(c) if c >= *transferring_at) {
            warn!(group=?request.source, committed=?leader.committed, ?transferring_at,
                "transfer out not yet committed");
            return Response::Busy;
        }

        let statement = self.realm_keys.mac.transfer_mac(&TransferStatementMessage {
            realm: request.realm,
            destination: *destination,
            partition,
            nonce: request.nonce,
        });

        Response::Ok(statement)
    }

    #[instrument(level = "trace", skip(self, _metrics), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_transfer_in(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: TransferInRequest,
    ) -> TransferInResponse {
        type Response = TransferInResponse;

        let leader = match is_group_leader(
            &self.persistent,
            &mut self.volatile.groups,
            request.realm,
            request.destination,
        ) {
            Ok(leader) => leader,
            Err(GroupLeaderError::InvalidRealm) => return Response::InvalidRealm,
            Err(GroupLeaderError::InvalidGroup) => return Response::InvalidGroup,
            Err(GroupLeaderError::NotLeader(_)) => return Response::NotLeader,
        };

        let last_entry = &leader.log.last().entry;

        match last_entry.transferring.as_ref() {
            Some(Transferring::In(transferring_in))
                if transferring_in.range == request.transferring.range
                    && transferring_in.source == request.source => {}
            None | Some(Transferring::In(_)) | Some(Transferring::Out(_)) => {
                return Response::NotPrepared
            }
        }

        if leader.incoming != Some(request.nonce) {
            return Response::InvalidNonce;
        }
        leader.incoming = None;

        let needs_merge = match &last_entry.partition {
            None => false,
            Some(part) => match part.range.join(&request.transferring.range) {
                None => panic!("Unable to join ranges during transferIn. but this was verified to be possible during prepareTransfer"),
                Some(_) => {
                    // We need to verify that the transferring proof matches the
                    // transferring partition. We don't need to do this for owned
                    // as the Merkle tree can deal with that from its overlay.
                    if let Some(proofs) = &request.proofs {
                        if request.transferring.range != proofs.transferring.range
                            || request.transferring.root_hash != proofs.transferring.root_hash
                        {
                            return Response::InvalidProof;
                        }
                    } else {
                        return Response::MissingProofs;
                    }
                    true
                }
            },
        };

        if self
            .realm_keys
            .mac
            .transfer_mac(&TransferStatementMessage {
                realm: request.realm,
                destination: request.destination,
                partition: &request.transferring,
                nonce: request.nonce,
            })
            .verify(&request.statement)
            .is_err()
        {
            return Response::InvalidStatement;
        }

        let (partition, delta) = if needs_merge {
            let tree = leader.tree.take().unwrap();
            let proofs = request.proofs.unwrap();
            match tree.merge(proofs.owned, proofs.transferring) {
                Err(MergeError::NotAdjacentRanges) => {
                    // Shouldn't be able to get here, this was verified above
                    // and during prepareTransfer
                    unreachable!("merkle tree merge reported NotAdjacentRanges")
                }
                Err(MergeError::Proof(ProofError::Stale)) => return Response::StaleProof,
                Err(MergeError::Proof(ProofError::Invalid)) => return Response::InvalidProof,
                Ok(merge_result) => (
                    Partition {
                        range: merge_result.range,
                        root_hash: merge_result.root_hash,
                    },
                    merge_result.delta,
                ),
            }
        } else {
            (request.transferring, StoreDelta::default())
        };

        let entry = LogEntryBuilder {
            hsm: self.persistent.id,
            realm: request.realm,
            group: request.destination,
            index: last_entry.index.next(),
            partition: Some(partition.clone()),
            transferring: None,
            prev_mac: last_entry.entry_mac.clone(),
        }
        .build(&self.realm_keys.mac);

        leader.log.append(entry.clone(), None);

        leader.tree = Some(Tree::with_existing_root(
            partition.root_hash,
            self.options.tree_overlay_size,
        ));

        let clock = self
            .volatile
            .groups
            .get(&request.destination)
            .expect("already verified group membership")
            .at;

        Response::Ok {
            entry,
            delta,
            clock,
        }
    }

    #[instrument(level = "trace", skip(self, _metrics), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_complete_transfer(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: CompleteTransferRequest,
    ) -> CompleteTransferResponse {
        type Response = CompleteTransferResponse;

        if request.source == request.destination {
            return Response::InvalidGroup;
        }

        let leader = match is_group_leader(
            &self.persistent,
            &mut self.volatile.groups,
            request.realm,
            request.source,
        ) {
            Ok(leader) => leader,
            Err(GroupLeaderError::InvalidRealm) => return Response::InvalidRealm,
            Err(GroupLeaderError::InvalidGroup) => return Response::InvalidGroup,
            Err(GroupLeaderError::NotLeader(_)) => return Response::NotLeader,
        };

        let last_entry = &leader.log.last().entry;
        match &last_entry.transferring {
            None => return Response::NotTransferring,
            Some(Transferring::In(_)) => return Response::NotTransferring,
            Some(Transferring::Out(transferring_out))
                if transferring_out.destination == request.destination
                    && transferring_out.partition.range == request.range => {}
            Some(Transferring::Out(_)) => return Response::NotTransferring,
        }

        let entry = LogEntryBuilder {
            hsm: self.persistent.id,
            realm: request.realm,
            group: request.source,
            index: last_entry.index.next(),
            partition: last_entry.partition.clone(),
            transferring: None,
            prev_mac: last_entry.entry_mac.clone(),
        }
        .build(&self.realm_keys.mac);

        leader.log.append(entry.clone(), None);

        let clock = self
            .volatile
            .groups
            .get(&request.source)
            .expect("already verified group membership")
            .at;
        Response::Ok { entry, clock }
    }

    #[instrument(level = "trace", skip(self, _metrics), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_cancel_prepared_transfer(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: CancelPreparedTransferRequest,
    ) -> CancelPreparedTransferResponse {
        type Response = CancelPreparedTransferResponse;

        let leader = match is_group_leader(
            &self.persistent,
            &mut self.volatile.groups,
            request.realm,
            request.destination,
        ) {
            Ok(leader) => leader,
            Err(GroupLeaderError::InvalidRealm) => return Response::InvalidRealm,
            Err(GroupLeaderError::InvalidGroup) => return Response::InvalidGroup,
            Err(GroupLeaderError::NotLeader(_)) => return Response::NotLeader,
        };

        let last_entry = &leader.log.last().entry;
        match &last_entry.transferring {
            None | Some(Transferring::Out(_)) => return Response::NotPrepared,
            Some(Transferring::In(t)) if t.range != request.range || t.source != request.source => {
                return Response::NotPrepared;
            }
            Some(_) => {}
        }

        let entry = LogEntryBuilder {
            hsm: self.persistent.id,
            realm: request.realm,
            group: request.destination,
            index: last_entry.index.next(),
            partition: last_entry.partition.clone(),
            transferring: None,
            prev_mac: last_entry.entry_mac.clone(),
        }
        .build(&self.realm_keys.mac);

        leader.log.append(entry.clone(), None);
        leader.incoming = None;

        let clock = self
            .volatile
            .groups
            .get(&request.destination)
            .expect("already verified group membership")
            .at;

        Response::Ok { entry, clock }
    }
}

fn create_random_transfer_nonce(rng: &mut impl CryptoRng) -> TransferNonce {
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    TransferNonce(nonce)
}
