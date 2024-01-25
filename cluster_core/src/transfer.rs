use std::sync::Arc;
use std::time::Duration;

use super::{find_leaders, ManagementGrant, ManagementLeaseKey};
use agent_api::{
    CancelPreparedTransferRequest, CancelPreparedTransferResponse, CompleteTransferRequest,
    CompleteTransferResponse, PrepareTransferRequest, PrepareTransferResponse, TransferInRequest,
    TransferInResponse, TransferOutRequest, TransferOutResponse,
};
use cluster_api::TransferSuccess;
use juicebox_networking::http;
use juicebox_networking::rpc::{self};
use store::StoreClient;
use tokio::time::sleep;
use tracing::{info, warn};

pub use cluster_api::{TransferError, TransferRequest};

/// This is a helper stub that calls the cluster manager API to do an ownership transfer.
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

// To simplify testing, callers to transfer can indicate different ways to leave
// the transfer in a partial state, simulating a coordinator crash, or an error
// that persists past the retry limits etc.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum TransferChaos {
    StopAfterPrepare,
    StopAfterTransferOut,
    StopBeforeComplete,
}

// Performs an record id range ownership transfer between 2 groups. This is
// exposed purely for testing use the cluster_manager RPC API for normal use.
pub async fn perform_transfer(
    store: Arc<StoreClient>,
    lease_owner: String,
    client: &impl http::Client,
    transfer: TransferRequest,
    chaos: Option<TransferChaos>,
) -> Result<TransferSuccess, TransferError> {
    type Error = TransferError;

    if transfer.source == transfer.destination {
        warn!(
            group=?transfer.source,
            "cannot transfer ownership to the same group (unsupported)"
        );
        return Err(Error::InvalidGroup);
    }

    let _grant: ManagementGrant = match ManagementGrant::obtain(
        store.clone(),
        lease_owner,
        ManagementLeaseKey::Ownership(transfer.realm),
    )
    .await
    {
        Ok(Some(grant)) => grant,
        Ok(None) => return Err(TransferError::ManagerBusy),
        Err(err) => {
            warn!(?err, "failed to get management lease");
            return Err(TransferError::ManagerBusy);
        }
    };

    let mut state = TransferState::Transferring;
    let mut last_error: Option<Error> = None;

    // In the event of an unexpected path out of here, or a crash the transfer recovery checker will
    // spot the transferring in and/or out entries and restart the transfer as appropriate.

    let mut tries = 0;
    loop {
        tries += 1;
        if tries > 20 {
            return Err(last_error.unwrap_or(Error::TooManyRetries));
        } else if tries > 1 {
            sleep(Duration::from_millis(25)).await;
            warn!(?state, ?last_error, "retrying transfer due to error");
        }

        let leaders = find_leaders(&store, client).await.unwrap_or_default();

        let Some((_, source_leader)) = leaders.get(&(transfer.realm, transfer.source)) else {
            last_error = Some(Error::NoSourceLeader);
            continue;
        };

        let Some((_, dest_leader)) = leaders.get(&(transfer.realm, transfer.destination)) else {
            last_error = Some(Error::NoDestinationLeader);
            continue;
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
        if state == TransferState::Transferring {
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
                Ok(PrepareTransferResponse::InvalidGroup) => return Err(Error::InvalidGroup),
                Ok(PrepareTransferResponse::OtherTransferPending) => {
                    return Err(Error::OtherTransferPending)
                }
                Ok(PrepareTransferResponse::UnacceptableRange) => {
                    return Err(Error::UnacceptableRange)
                }
                Ok(PrepareTransferResponse::CommitTimeout) => return Err(Error::CommitTimeout),
                Ok(PrepareTransferResponse::NoStore) => return Err(Error::NoStore),
                Ok(PrepareTransferResponse::NoHsm) => {
                    last_error = Some(Error::NoDestinationLeader);
                    continue;
                }
                Ok(PrepareTransferResponse::NotLeader) => {
                    last_error = Some(Error::NoDestinationLeader);
                    continue;
                }
                Err(error) => {
                    warn!(%error, "RPC error with destination leader during PrepareTransfer");
                    last_error = Some(Error::RpcError(error));
                    continue;
                }
            };

            if chaos == Some(TransferChaos::StopAfterPrepare) {
                return Err(Error::TooManyRetries);
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
                    cancel_prepared_transfer(client, &store, transfer).await;
                    return Err(Error::UnacceptableRange);
                }
                Ok(TransferOutResponse::InvalidGroup) => {
                    cancel_prepared_transfer(client, &store, transfer).await;
                    return Err(Error::InvalidGroup);
                }
                Ok(TransferOutResponse::OtherTransferPending) => {
                    cancel_prepared_transfer(client, &store, transfer).await;
                    return Err(Error::OtherTransferPending);
                }
                Ok(TransferOutResponse::CommitTimeout) => {
                    // This might still commit, so we shouldn't cancel the prepare.
                    return Err(Error::CommitTimeout);
                }
                Ok(TransferOutResponse::NoStore) => return Err(Error::NoStore),
                Ok(
                    TransferOutResponse::NotOwner
                    | TransferOutResponse::NoHsm
                    | TransferOutResponse::NotLeader,
                ) => {
                    last_error = Some(Error::NoSourceLeader);
                    continue;
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
                    warn!(%error, "RPC error with source leader during TransferOut");
                    last_error = Some(Error::RpcError(error));
                    continue;
                }
            };

            if chaos == Some(TransferChaos::StopAfterTransferOut) {
                return Err(Error::TooManyRetries);
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
                    state = TransferState::Completing;
                }
                Ok(TransferInResponse::CommitTimeout) => return Err(Error::CommitTimeout),
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
                    last_error = Some(Error::InvalidNonce);
                    continue;
                }
                Ok(TransferInResponse::NoStore) => {
                    last_error = Some(Error::NoStore);
                    continue;
                }
                Ok(
                    TransferInResponse::NoHsm
                    | TransferInResponse::NotLeader
                    | TransferInResponse::NotOwner,
                ) => {
                    last_error = Some(Error::NoDestinationLeader);
                    continue;
                }
                Err(error) => {
                    warn!(%error, "RPC Error reported while calling TransferIn");
                    last_error = Some(Error::RpcError(error));
                    continue;
                }
            };
        }

        if chaos == Some(TransferChaos::StopBeforeComplete) {
            return Err(Error::TooManyRetries);
        }

        if state == TransferState::Completing {
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
                Ok(CompleteTransferResponse::Ok) => return Ok(TransferSuccess {}),
                Ok(CompleteTransferResponse::CommitTimeout) => return Err(Error::CommitTimeout),
                Ok(CompleteTransferResponse::NoHsm | CompleteTransferResponse::NotLeader) => {
                    last_error = Some(Error::NoSourceLeader);
                    continue;
                }
                Ok(
                    CompleteTransferResponse::InvalidRealm | CompleteTransferResponse::InvalidGroup,
                ) => {
                    unreachable!();
                }
                Ok(CompleteTransferResponse::NotTransferring) => {
                    warn!("got NotTransferring during complete transfer");
                    // This could happen if retried for a transient error but the request
                    // had actually succeeded (e.g. commit timeout)
                    return Ok(TransferSuccess {});
                }
                Err(error) => {
                    warn!(%error, "RPC error during CompleteTransfer request");
                    last_error = Some(Error::RpcError(error));
                    continue;
                }
            }
        }
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
