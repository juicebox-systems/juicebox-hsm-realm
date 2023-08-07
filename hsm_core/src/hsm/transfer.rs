use tracing::instrument;

use super::super::hal::{CryptoRng, Platform};
use super::super::merkle::{proof::ProofError, MergeError, Tree};
use super::mac::{CtMac, TransferStatementMessage};
use super::{Hsm, LogEntryBuilder, Metrics};
use hsm_api::merkle::StoreDelta;
use hsm_api::{
    CompleteTransferRequest, CompleteTransferResponse, Partition, TransferInRequest,
    TransferInResponse, TransferNonce, TransferNonceRequest, TransferNonceResponse,
    TransferOutRequest, TransferOutResponse, TransferStatementRequest, TransferStatementResponse,
    TransferringOut,
};

impl<P: Platform> Hsm<P> {
    #[instrument(level = "trace", skip(self, _metrics), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_transfer_out(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: TransferOutRequest,
    ) -> TransferOutResponse {
        type Response = TransferOutResponse;

        let Some(realm) = &self.persistent.realm else {
            return Response::InvalidRealm;
        };
        if realm.id != request.realm {
            return Response::InvalidRealm;
        }

        if realm.groups.get(&request.source).is_none() || request.source == request.destination {
            return Response::InvalidGroup;
        }

        let Some(leader) = self.volatile.leader.get_mut(&request.source) else {
            return Response::NotLeader;
        };

        let last_entry = &leader.log.last().entry;

        // Note: The owned_range found in the last entry might not have
        // committed yet. We think that's OK. The source group won't
        // produce a transfer statement unless this last entry and the
        // transferring out entry have committed.
        let Some(owned_partition) = &last_entry.partition else {
            return Response::NotOwner;
        };

        if last_entry.transferring_out.is_some() {
            // TODO: should return an error, not panic
            panic!("can't transfer because already transferring");
        }

        // TODO: This will always return StaleIndex if we're pipelining
        // changes while transferring ownership. We need to bring
        // `request.proof` forward by applying recent changes to it.
        if request.index != last_entry.index {
            return Response::StaleIndex;
        }

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
            transferring_out: Some(TransferringOut {
                destination: request.destination,
                partition: transferring_partition,
                at: index,
            }),
            prev_mac: last_entry.entry_mac.clone(),
        }
        .build(&self.realm_keys.mac);

        leader.log.append(entry.clone(), None);

        TransferOutResponse::Ok { entry, delta }
    }

    #[instrument(level = "trace", skip(self, _metrics), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_transfer_nonce(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: TransferNonceRequest,
    ) -> TransferNonceResponse {
        type Response = TransferNonceResponse;

        let Some(realm) = &self.persistent.realm else {
            return Response::InvalidRealm;
        };
        if realm.id != request.realm {
            return Response::InvalidRealm;
        }

        if realm.groups.get(&request.destination).is_none() {
            return Response::InvalidGroup;
        }

        let Some(leader) = self.volatile.leader.get_mut(&request.destination) else {
            return Response::NotLeader;
        };

        let nonce = create_random_transfer_nonce(&mut self.platform);
        leader.incoming = Some(nonce);
        Response::Ok(nonce)
    }

    #[instrument(level = "trace", skip(self, _metrics), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_transfer_statement(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: TransferStatementRequest,
    ) -> TransferStatementResponse {
        type Response = TransferStatementResponse;

        let Some(realm) = &self.persistent.realm else {
            return Response::InvalidRealm;
        };
        if realm.id != request.realm {
            return Response::InvalidRealm;
        }

        if realm.groups.get(&request.source).is_none() || request.source == request.destination {
            return Response::InvalidGroup;
        }

        let Some(leader) = self.volatile.leader.get_mut(&request.source) else {
            return Response::NotLeader;
        };

        let Some(TransferringOut {
            destination,
            partition,
            at: transferring_at,
        }) = &leader.log.last().entry.transferring_out
        else {
            return Response::NotTransferring;
        };
        if *destination != request.destination {
            return Response::NotTransferring;
        }
        if !matches!(leader.committed, Some(c) if c >= *transferring_at) {
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

        let Some(realm) = &self.persistent.realm else {
            return Response::InvalidRealm;
        };
        if realm.id != request.realm {
            return Response::InvalidRealm;
        }

        if realm.groups.get(&request.destination).is_none() {
            return Response::InvalidGroup;
        }

        let Some(leader) = self.volatile.leader.get_mut(&request.destination) else {
            return Response::NotLeader;
        };

        if leader.incoming != Some(request.nonce) {
            return Response::InvalidNonce;
        }
        leader.incoming = None;

        let last_entry = &leader.log.last().entry;
        let needs_merge = match &last_entry.partition {
            None => false,
            Some(part) => match part.range.join(&request.transferring.range) {
                None => return Response::UnacceptableRange,
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
                Err(MergeError::NotAdjacentRanges) => return Response::UnacceptableRange,
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
            transferring_out: last_entry.transferring_out.clone(),
            prev_mac: last_entry.entry_mac.clone(),
        }
        .build(&self.realm_keys.mac);

        leader.log.append(entry.clone(), None);

        leader.tree = Some(Tree::with_existing_root(
            partition.root_hash,
            self.options.tree_overlay_size,
        ));
        Response::Ok { entry, delta }
    }

    #[instrument(level = "trace", skip(self, _metrics), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_complete_transfer(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: CompleteTransferRequest,
    ) -> CompleteTransferResponse {
        type Response = CompleteTransferResponse;

        let Some(realm) = &self.persistent.realm else {
            return Response::InvalidRealm;
        };
        if realm.id != request.realm {
            return Response::InvalidRealm;
        }

        if realm.groups.get(&request.source).is_none() || request.source == request.destination {
            return Response::InvalidGroup;
        }

        let Some(leader) = self.volatile.leader.get_mut(&request.source) else {
            return Response::NotLeader;
        };

        let last_entry = &leader.log.last().entry;
        if let Some(transferring_out) = &last_entry.transferring_out {
            if transferring_out.destination != request.destination
                || transferring_out.partition.range != request.range
            {
                return Response::NotTransferring;
            }
        } else {
            return Response::NotTransferring;
        }

        let entry = LogEntryBuilder {
            hsm: self.persistent.id,
            realm: request.realm,
            group: request.source,
            index: last_entry.index.next(),
            partition: last_entry.partition.clone(),
            transferring_out: None,
            prev_mac: last_entry.entry_mac.clone(),
        }
        .build(&self.realm_keys.mac);

        leader.log.append(entry.clone(), None);

        Response::Ok(entry)
    }
}

fn create_random_transfer_nonce(rng: &mut impl CryptoRng) -> TransferNonce {
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    TransferNonce(nonce)
}
