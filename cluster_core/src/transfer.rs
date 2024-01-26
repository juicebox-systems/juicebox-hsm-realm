use retry_loop::{retry_logging_debug, AttemptError, RetryError};
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::{find_leaders, ManagementGrant, ManagementLeaseKey};
use agent_api::{
    CancelPreparedTransferRequest, CancelPreparedTransferResponse, CompleteTransferRequest,
    CompleteTransferResponse, PrepareTransferRequest, PrepareTransferResponse, TransferInRequest,
    TransferInResponse, TransferOutRequest, TransferOutResponse,
};
use cluster_api::TransferSuccess;
use juicebox_networking::http;
use juicebox_networking::rpc;
use store::StoreClient;

pub use cluster_api::{TransferError, TransferRequest};

// This is a helper stub that calls the transfer API on the cluster manager.
pub async fn transfer(
    store: &StoreClient,
    client: &impl http::Client,
    transfer: TransferRequest,
) -> Result<(), TransferError> {
    let cluster_managers = store
        .get_addresses(Some(store::ServiceKind::ClusterManager))
        .await
        .map_err(|_| TransferError::NoStore)?;

    if cluster_managers.is_empty() {
        return Err(TransferError::NoSourceLeader);
    }

    rpc::send(client, &cluster_managers[0].0, transfer)
        .await
        .map_err(TransferError::RpcError)?
        .map(|_| ())
}

/// To simplify testing, callers to [`perform_transfer`] can indicate different
/// ways to leave the transfer in a partial state, simulating a coordinator
/// crash, or an error that persists past the retry limits etc.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum TransferChaos {
    StopAfterPrepare,
    StopAfterTransferOut,
    StopBeforeComplete,
}

// Performs an record id range ownership transfer between 2 groups. This is
// exposed purely for testing. Use the cluster_manager RPC API for normal use.
pub async fn perform_transfer(
    store: &StoreClient,
    client: &impl http::Client,
    grant: &ManagementGrant,
    chaos: Option<TransferChaos>,
    transfer: TransferRequest,
) -> Result<TransferSuccess, RetryError<TransferError>> {
    type Error = TransferError;

    if transfer.source == transfer.destination {
        warn!(
            group=?transfer.source,
            "cannot transfer ownership to the same group (unsupported)"
        );
        return Err(RetryError::Fatal {
            error: Error::InvalidGroup,
        });
    }

    // check the caller supplied grant.
    let ManagementLeaseKey::Ownership(grant_realm) = &grant.key else {
        panic!("supplied grant of wrong type/value {:?}", grant.key);
    };
    assert_eq!(*grant_realm, transfer.realm);

    // In the event of an unexpected path out of here, or a crash the transfer recovery checker will
    // spot the transferring in and/or out entries and restart the transfer as appropriate.
    let state = Mutex::new(TransferState::Transferring);

    let run = |_| async {
        let mut state = state.lock().await;
        let transfer = transfer.clone();

        let leaders = find_leaders(store, client).await.unwrap_or_default();

        let Some((_, source_leader)) = leaders.get(&(transfer.realm, transfer.source)) else {
            return Err(classify(Error::NoSourceLeader));
        };

        let Some((_, dest_leader)) = leaders.get(&(transfer.realm, transfer.destination)) else {
            return Err(classify(Error::NoDestinationLeader));
        };

        // Once the source group commits the log entry that the range is
        // transferring out, the range must then move to the destination group.
        // Having the destination have to prepare first and subsequently reject any
        // other transfers ensures that when the process gets around to transfer_in,
        // it'll succeed. This is an issue with each group owning 0 or 1 ranges: the
        // only group that can accept a range is one that owns no range or one that
        // owns an adjacent range.

        // The Agents will not respond to these RPCs until the related log entry is
        // committed. (where protocol safety requires the log entry to commit).
        if *state == TransferState::Transferring {
            info!(realm=?transfer.realm, source=?transfer.source, destination=?transfer.destination, "starting PrepareTransfer");
            let (nonce, prepared_stmt) = match rpc::send(
                client,
                dest_leader,
                PrepareTransferRequest {
                    realm: transfer.realm,
                    source: transfer.source,
                    destination: transfer.destination,
                    range: transfer.range.clone(),
                },
            )
            .await
            {
                Ok(PrepareTransferResponse::Ok { nonce, statement }) => (nonce, statement),
                Ok(PrepareTransferResponse::InvalidRealm) => {
                    // In theory you should never be able to get here, as the checks
                    // to find the leaders wouldn't find any leaders for an unknown
                    // realm/group
                    unreachable!(
                        "PrepareTransfer to group:{:?} in realm:{:?} failed with InvalidRealm",
                        transfer.destination, transfer.realm,
                    );
                }
                Ok(PrepareTransferResponse::InvalidGroup) => {
                    return Err(classify(Error::InvalidGroup))
                }
                Ok(PrepareTransferResponse::OtherTransferPending) => {
                    return Err(classify(Error::OtherTransferPending))
                }
                Ok(PrepareTransferResponse::UnacceptableRange) => {
                    return Err(classify(Error::UnacceptableRange))
                }
                Ok(PrepareTransferResponse::CommitTimeout) => {
                    return Err(classify(Error::CommitTimeout))
                }
                Ok(PrepareTransferResponse::NoStore) => return Err(classify(Error::NoStore)),
                Ok(PrepareTransferResponse::NoHsm) => {
                    return Err(classify(Error::NoDestinationLeader));
                }
                Ok(PrepareTransferResponse::NotLeader) => {
                    return Err(classify(Error::NoDestinationLeader));
                }
                Err(error) => {
                    return Err(classify(Error::RpcError(error)));
                }
            };

            if chaos == Some(TransferChaos::StopAfterPrepare) {
                return Err(classify(Error::Timeout));
            }

            info!(realm=?transfer.realm, source=?transfer.source, destination=?transfer.destination, "transfer prepared, starting TransferOut");
            let (transferring_partition, transfer_stmt) = match rpc::send(
                client,
                source_leader,
                TransferOutRequest {
                    realm: transfer.realm,
                    source: transfer.source,
                    destination: transfer.destination,
                    range: transfer.range.clone(),
                    nonce,
                    statement: prepared_stmt.clone(),
                },
            )
            .await
            {
                Ok(TransferOutResponse::Ok {
                    transferring,
                    statement,
                }) => (transferring, statement),
                Ok(TransferOutResponse::UnacceptableRange) => {
                    cancel_prepared_transfer(client, store, transfer).await;
                    return Err(classify(Error::UnacceptableRange));
                }
                Ok(TransferOutResponse::InvalidGroup) => {
                    cancel_prepared_transfer(client, store, transfer).await;
                    return Err(classify(Error::InvalidGroup));
                }
                Ok(TransferOutResponse::OtherTransferPending) => {
                    cancel_prepared_transfer(client, store, transfer).await;
                    return Err(classify(Error::OtherTransferPending));
                }
                Ok(TransferOutResponse::CommitTimeout) => {
                    // This might still commit, so we shouldn't cancel the prepare.
                    return Err(classify(Error::CommitTimeout));
                }
                Ok(TransferOutResponse::NoStore) => return Err(classify(Error::NoStore)),
                Ok(
                    TransferOutResponse::NotOwner
                    | TransferOutResponse::NoHsm
                    | TransferOutResponse::NotLeader,
                ) => {
                    return Err(classify(Error::NoSourceLeader));
                }
                Ok(TransferOutResponse::InvalidProof) => {
                    panic!("TransferOut reported invalid proof");
                }
                Ok(TransferOutResponse::InvalidRealm) => {
                    unreachable!(
                        "TransferOut reported invalid realm for realm:{:?}",
                        transfer.realm
                    )
                }
                Ok(TransferOutResponse::InvalidStatement) => {
                    panic!(
                    "the destination group leader provided an invalid prepared transfer statement"
                );
                }
                Err(error) => {
                    return Err(classify(Error::RpcError(error)));
                }
            };

            if chaos == Some(TransferChaos::StopAfterTransferOut) {
                return Err(classify(Error::Timeout));
            }

            info!(realm=?transfer.realm, source=?transfer.source, destination=?transfer.destination, "transfer out completed, starting TransferIn");
            match rpc::send(
                client,
                dest_leader,
                TransferInRequest {
                    realm: transfer.realm,
                    source: transfer.source,
                    destination: transfer.destination,
                    transferring: transferring_partition.clone(),
                    nonce,
                    statement: transfer_stmt.clone(),
                },
            )
            .await
            {
                Ok(TransferInResponse::Ok) => {
                    *state = TransferState::Completing;
                }
                Ok(TransferInResponse::CommitTimeout) => {
                    return Err(classify(Error::CommitTimeout))
                }
                Ok(TransferInResponse::NotPrepared) => {
                    unreachable!(
                        "TransferIn reported Not Prepared, but we just called prepareTransfer"
                    );
                }
                Ok(TransferInResponse::InvalidStatement) => {
                    panic!("TransferIn reported an invalid transfer statement");
                }
                Ok(r @ TransferInResponse::InvalidGroup | r @ TransferInResponse::InvalidRealm) => {
                    unreachable!("Only a buggy coordinator can get these errors by this point in the process. Got {r:?}");
                }
                Ok(TransferInResponse::InvalidNonce) => {
                    return Err(classify(Error::InvalidNonce));
                }
                Ok(TransferInResponse::NoStore) => {
                    return Err(classify(Error::NoStore));
                }
                Ok(
                    TransferInResponse::NoHsm
                    | TransferInResponse::NotLeader
                    | TransferInResponse::NotOwner,
                ) => {
                    return Err(classify(Error::NoDestinationLeader));
                }
                Err(error) => {
                    return Err(classify(Error::RpcError(error)));
                }
            };
        }

        if chaos == Some(TransferChaos::StopBeforeComplete) {
            return Err(classify(Error::Timeout));
        }

        // the TransferIn agent RPC waits for the log entry to commit, so
        // its safe to call CompleteTransfer now.
        info!(realm=?transfer.realm, source=?transfer.source,
                destination=?transfer.destination,
                "transfer in completed, starting CompleteTransfer");

        match rpc::send(
            client,
            source_leader,
            CompleteTransferRequest {
                realm: transfer.realm,
                source: transfer.source,
                destination: transfer.destination,
                range: transfer.range.clone(),
            },
        )
        .await
        {
            Ok(CompleteTransferResponse::Ok) => Ok(TransferSuccess {}),
            Ok(CompleteTransferResponse::CommitTimeout) => Err(classify(Error::CommitTimeout)),
            Ok(CompleteTransferResponse::NoHsm | CompleteTransferResponse::NotLeader) => {
                Err(classify(Error::NoSourceLeader))
            }
            Ok(CompleteTransferResponse::InvalidRealm | CompleteTransferResponse::InvalidGroup) => {
                unreachable!();
            }
            Ok(CompleteTransferResponse::NotTransferring) => {
                warn!("got NotTransferring during complete transfer");
                // This could happen if retried for a transient error but the request
                // had actually succeeded (e.g. commit timeout)
                Ok(TransferSuccess {})
            }
            Err(error) => Err(classify(Error::RpcError(error))),
        }
    };

    retry_loop::Retry::new("run cluster transfer process")
        .with_exponential_backoff(Duration::from_millis(10), 1.1, Duration::from_millis(500))
        .retry(run, retry_logging_debug!())
        .await
}

fn classify(e: TransferError) -> AttemptError<TransferError> {
    let tags = Vec::new();
    match e {
        error @ TransferError::NoSourceLeader => AttemptError::Retryable { error, tags },
        error @ TransferError::NoDestinationLeader => AttemptError::Retryable { error, tags },
        error @ TransferError::ManagerBusy => AttemptError::Fatal { error, tags },
        error @ TransferError::InvalidGroup => AttemptError::Fatal { error, tags },
        error @ TransferError::UnacceptableRange => AttemptError::Fatal { error, tags },
        error @ TransferError::OtherTransferPending => AttemptError::Fatal { error, tags },
        error @ TransferError::NoStore => AttemptError::Retryable { error, tags },
        error @ TransferError::Timeout => AttemptError::Fatal { error, tags },
        error @ TransferError::CommitTimeout => AttemptError::Fatal { error, tags },
        error @ TransferError::InvalidNonce => AttemptError::Retryable { error, tags },
        error @ TransferError::RpcError(_) => AttemptError::Retryable { error, tags },
    }
}

#[derive(Debug, Eq, PartialEq)]
enum TransferState {
    Transferring,
    Completing,
}

async fn cancel_prepared_transfer(
    client: &impl http::Client,
    store: &StoreClient,
    t: TransferRequest,
) {
    let leaders = find_leaders(store, client).await.unwrap_or_default();

    let Some((_, dest_leader)) = leaders.get(&(t.realm, t.destination)) else {
        warn!(group=?t.destination, "couldn't find a leader for the group");
        return;
    };
    info!(realm=?t.realm, source=?t.source, destination=?t.destination, "cancelling preparedTransfer");

    match rpc::send(
        client,
        dest_leader,
        CancelPreparedTransferRequest {
            realm: t.realm,
            source: t.source,
            destination: t.destination,
            range: t.range.clone(),
        },
    )
    .await
    {
        Ok(CancelPreparedTransferResponse::Ok) => {
            info!(realm=?t.realm, source=?t.source, destination=?t.destination, "canceled previously prepared transfer");
        }
        Ok(other) => {
            warn!(result=?other, realm=?t.realm, source=?t.source, destination=?t.destination, "CancelPreparedTransfer failed");
        }
        Err(err) => {
            warn!(%err,realm=?t.realm, source=?t.source, destination=?t.destination, "RPC error while trying to cancel prepared transfer");
        }
    }
}
