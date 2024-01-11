use std::time::Duration;
use tokio::time::sleep;
use tracing::{trace, warn};

use super::append::Append;
use super::{merkle, Agent, Transport};
use agent_api::merkle::TreeStoreError;
use agent_api::{
    CompleteTransferRequest, CompleteTransferResponse, TransferInRequest, TransferInResponse,
    TransferNonceRequest, TransferNonceResponse, TransferOutRequest, TransferOutResponse,
    TransferStatementRequest, TransferStatementResponse,
};
use hsm_api::merkle::{Dir, StoreDelta};
use hsm_api::TransferInProofs;
use observability::metrics_tag as tag;
use service_core::rpc::HandlerError;
use store::{self, ReadLastLogEntryError};

impl<T: Transport + 'static> Agent<T> {
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
        loop {
            let entry = match store
                .read_last_log_entry(&request.realm, &request.source)
                .await
            {
                Ok(entry) => entry,
                Err(err @ ReadLastLogEntryError::EmptyLog) => todo!("{err}"),
                Err(ReadLastLogEntryError::Grpc(_)) => return Ok(Response::NoStore),
            };
            let Some(partition) = entry.partition else {
                return Ok(Response::NotOwner);
            };

            // if we're splitting, then we need the proof for the split point.
            let proof = if partition.range == request.range {
                None
            } else {
                let rec_id = match partition.range.split_at(&request.range) {
                    Some(id) => id,
                    None => return Ok(Response::NotOwner),
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
            };

            return match hsm
                .send(hsm_api::TransferOutRequest {
                    realm: request.realm,
                    source: request.source,
                    destination: request.destination,
                    range: request.range.clone(),
                    index: entry.index,
                    proof,
                })
                .await
            {
                Err(_) => Ok(Response::NoHsm),
                Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
                Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
                Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
                Ok(HsmResponse::NotOwner) => Ok(Response::NotOwner),
                Ok(r @ HsmResponse::StaleIndex) => todo!("{r:?}"),
                Ok(r @ HsmResponse::MissingProof) => todo!("{r:?}"),
                Ok(HsmResponse::InvalidProof) => Ok(Response::InvalidProof),
                Ok(HsmResponse::StaleProof) => {
                    trace!("hsm said stale proof, will retry");
                    sleep(Duration::from_millis(1)).await;
                    continue;
                }
                Ok(HsmResponse::Ok { entry, delta }) => {
                    let transferring_partition = match &entry.transferring_out {
                        Some(t) => t.partition.clone(),
                        None => panic!("Log entry missing TransferringOut section"),
                    };
                    self.append(realm, source, Append { entry, delta });
                    Ok(Response::Ok {
                        transferring: transferring_partition,
                    })
                }
            };
        }
    }

    pub(super) async fn handle_transfer_nonce(
        &self,
        request: TransferNonceRequest,
    ) -> Result<TransferNonceResponse, HandlerError> {
        type Response = TransferNonceResponse;
        type HsmResponse = hsm_api::TransferNonceResponse;

        match self
            .0
            .hsm
            .send(hsm_api::TransferNonceRequest {
                realm: request.realm,
                destination: request.destination,
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::Ok(nonce)) => Ok(Response::Ok(nonce)),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
        }
    }

    pub(super) async fn handle_transfer_statement(
        &self,
        request: TransferStatementRequest,
    ) -> Result<TransferStatementResponse, HandlerError> {
        type Response = TransferStatementResponse;
        type HsmResponse = hsm_api::TransferStatementResponse;
        loop {
            return match self
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
                Err(_) => Ok(Response::NoHsm),
                Ok(HsmResponse::Ok(statement)) => Ok(Response::Ok(statement)),
                Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
                Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
                Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
                Ok(HsmResponse::NotTransferring) => Ok(Response::NotTransferring),
                Ok(HsmResponse::Busy) => {
                    sleep(Duration::from_millis(1)).await;
                    continue;
                }
            };
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
        loop {
            let entry = match store
                .read_last_log_entry(&request.realm, &request.destination)
                .await
            {
                Ok(entry) => entry,
                Err(err @ ReadLastLogEntryError::EmptyLog) => todo!("{err}"),
                Err(ReadLastLogEntryError::Grpc(_)) => return Ok(Response::NoStore),
            };

            let proofs = match entry.partition {
                None => None,
                Some(partition) => {
                    let proof_dir = match partition.range.join(&request.transferring.range) {
                        None => return Ok(Response::UnacceptableRange),
                        Some(jr) => {
                            if jr.start == request.transferring.range.start {
                                Dir::Right
                            } else {
                                Dir::Left
                            }
                        }
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
            };

            return match hsm
                .send(hsm_api::TransferInRequest {
                    realm: request.realm,
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
                Ok(HsmResponse::UnacceptableRange) => Ok(Response::UnacceptableRange),
                Ok(HsmResponse::InvalidNonce) => Ok(Response::InvalidNonce),
                Ok(HsmResponse::InvalidStatement) => Ok(Response::InvalidStatement),
                Ok(r @ HsmResponse::InvalidProof) => todo!("{r:?}"),
                Ok(r @ HsmResponse::MissingProofs) => todo!("{r:?}"),
                Ok(HsmResponse::StaleProof) => {
                    trace!(?hsm, "hsm said stale proof, will retry");
                    // TODO: slow down and/or limit attempts
                    continue;
                }
                Ok(HsmResponse::Ok { entry, delta }) => {
                    let index = entry.index;
                    self.append(request.realm, request.destination, Append { entry, delta });
                    Ok(Response::Ok(index))
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
            Ok(HsmResponse::Ok(entry)) => {
                let index = entry.index;
                self.append(
                    request.realm,
                    request.source,
                    Append {
                        entry,
                        delta: StoreDelta::default(),
                    },
                );
                Ok(Response::Ok(index))
            }
        }
    }
}
