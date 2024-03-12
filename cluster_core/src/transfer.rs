use std::time::{Duration, Instant};
use tracing::{info, warn};

use super::{find_leaders, ManagementGrant, ManagementLeaseKey};
use agent_api::{
    CancelPreparedTransferRequest, CancelPreparedTransferResponse, CompleteTransferRequest,
    CompleteTransferResponse, PrepareTransferRequest, PrepareTransferResponse, TransferInRequest,
    TransferInResponse, TransferOutRequest, TransferOutResponse,
};
pub use cluster_api::{TransferError, TransferRequest, TransferSuccess};
use hsm_api::{Partition, PreparedTransferStatement, TransferNonce, TransferStatement};
use jburl::Url;
use juicebox_networking::{http, rpc};
use retry_loop::{retry_logging, AttemptError, RetryError};
use store::StoreClient;

/// To simplify testing, callers to [`perform_transfer`] can indicate different
/// ways to leave the transfer in a partial state, simulating a coordinator
/// crash, or an error that persists past the retry limits etc.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub enum TransferChaos {
    StopAfterPrepare,
    StopAfterTransferOut,
    StopAfterTransferIn,
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

    let run_transfer = |_| async {
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

        info!(realm=?transfer.realm, source=?transfer.source, destination=?transfer.destination,
            range=%transfer.range, "starting PrepareTransfer");
        let (nonce, prepared_stmt) = prepare_transfer(
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
        .map_err(classify)?;

        if chaos == Some(TransferChaos::StopAfterPrepare) {
            return Err(classify(Error::Timeout));
        }

        info!(realm=?transfer.realm, source=?transfer.source, destination=?transfer.destination,
            range=%transfer.range, "transfer prepared, starting TransferOut");
        let (transferring_partition, transfer_stmt) = transfer_out(
            client,
            source_leader,
            dest_leader,
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
        .map_err(classify)?;

        if chaos == Some(TransferChaos::StopAfterTransferOut) {
            return Err(classify(Error::Timeout));
        }

        info!(realm=?transfer.realm, source=?transfer.source, destination=?transfer.destination,
            range=%transfer.range, "transfer out completed, starting TransferIn");
        transfer_in(
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
        .map_err(classify)
    };

    let deadline = Instant::now() + Duration::from_secs(60 * 2);

    retry_loop::Retry::new("transferring ownership of record ID range")
        .with_deadline(Some(deadline))
        .with_exponential_backoff(Duration::from_millis(10), 1.1, Duration::from_millis(500))
        .retry(run_transfer, retry_logging!())
        .await?;

    if chaos == Some(TransferChaos::StopAfterTransferIn) {
        return Err(RetryError::Fatal {
            error: Error::Timeout,
        });
    }

    let run_complete = |_| async {
        // Its not ideal that we have to go do all the discovery again to get
        // the source group leader. But the transferred partition is live at the
        // destination and can service requests. So if this step takes longer
        // all it's blocking are other transfers.
        let leaders = find_leaders(store, client).await.unwrap_or_default();

        let Some((_, source_leader)) = leaders.get(&(transfer.realm, transfer.source)) else {
            return Err(classify(Error::NoSourceLeader));
        };

        complete_transfer(
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
        .map_err(classify)
    };

    info!(realm=?transfer.realm, source=?transfer.source, destination=?transfer.destination,
        range=%transfer.range, "transfer in completed, starting CompleteTransfer");

    retry_loop::Retry::new("completing transfer of ownership of record ID range")
        .with_deadline(Some(deadline))
        .with_exponential_backoff(Duration::from_millis(10), 2.0, Duration::from_secs(1))
        .retry(run_complete, retry_logging!())
        .await
}

async fn prepare_transfer(
    client: &impl http::Client,
    dest_leader: &Url,
    transfer: PrepareTransferRequest,
) -> Result<(TransferNonce, PreparedTransferStatement), TransferError> {
    type Error = TransferError;

    match rpc::send(client, dest_leader, transfer.clone()).await {
        Ok(PrepareTransferResponse::Ok { nonce, statement }) => Ok((nonce, statement)),
        Ok(PrepareTransferResponse::InvalidRealm) => {
            // In theory you should never be able to get here, as the checks
            // to find the leaders wouldn't find any leaders for an unknown
            // realm/group
            unreachable!(
                "PrepareTransfer to group:{:?} in realm:{:?} failed with InvalidRealm",
                transfer.destination, transfer.realm,
            );
        }
        Ok(PrepareTransferResponse::InvalidGroup) => Err(Error::InvalidGroup),
        Ok(PrepareTransferResponse::OtherTransferPending) => Err(Error::OtherTransferPending),
        Ok(PrepareTransferResponse::UnacceptableRange) => Err(Error::UnacceptableRange),
        Ok(PrepareTransferResponse::CommitTimeout) => Err(Error::CommitTimeout),
        Ok(PrepareTransferResponse::NoStore) => Err(Error::NoStore),
        Ok(PrepareTransferResponse::NoHsm) => Err(Error::NoDestinationLeader),
        Ok(PrepareTransferResponse::NotLeader) => Err(Error::NoDestinationLeader),
        Err(error) => Err(Error::RpcError(error)),
    }
}

async fn transfer_out(
    client: &impl http::Client,
    source_leader: &Url,
    dest_leader: &Url,
    transfer: TransferOutRequest,
) -> Result<(Partition, TransferStatement), TransferError> {
    type Error = TransferError;

    match rpc::send(client, source_leader, transfer.clone()).await {
        Ok(TransferOutResponse::Ok {
            transferring,
            statement,
        }) => Ok((transferring, statement)),
        Ok(TransferOutResponse::UnacceptableRange) => {
            cancel_prepared_transfer(client, dest_leader, transfer).await;
            Err(Error::UnacceptableRange)
        }
        Ok(TransferOutResponse::InvalidGroup) => {
            cancel_prepared_transfer(client, dest_leader, transfer).await;
            Err(Error::InvalidGroup)
        }
        Ok(TransferOutResponse::OtherTransferPending) => {
            cancel_prepared_transfer(client, dest_leader, transfer).await;
            Err(Error::OtherTransferPending)
        }
        Ok(TransferOutResponse::InvalidProof) => {
            warn!("TransferOut reported invalid proof");
            cancel_prepared_transfer(client, dest_leader, transfer).await;
            Err(Error::UnacceptableRange)
        }
        Ok(TransferOutResponse::CommitTimeout) => {
            // This might still commit, so we shouldn't cancel the prepare.
            Err(Error::CommitTimeout)
        }
        Ok(TransferOutResponse::NoStore) => Err(Error::NoStore),
        Ok(
            TransferOutResponse::NotOwner
            | TransferOutResponse::NoHsm
            | TransferOutResponse::NotLeader,
        ) => Err(Error::NoSourceLeader),
        Ok(TransferOutResponse::InvalidRealm) => {
            unreachable!(
                "TransferOut reported invalid realm for realm:{:?}",
                transfer.realm
            )
        }
        Ok(TransferOutResponse::InvalidStatement) => {
            panic!("the destination group leader provided an invalid prepared transfer statement");
        }
        Err(error) => Err(Error::RpcError(error)),
    }
}

async fn transfer_in(
    client: &impl http::Client,
    dest_leader: &Url,
    transfer: TransferInRequest,
) -> Result<(), TransferError> {
    type Error = TransferError;

    match rpc::send(client, dest_leader, transfer).await {
        Ok(TransferInResponse::Ok) => Ok(()),
        Ok(TransferInResponse::CommitTimeout) => Err(Error::CommitTimeout),
        Ok(TransferInResponse::NotPrepared) => {
            unreachable!("TransferIn reported Not Prepared, but we just called prepareTransfer");
        }
        Ok(TransferInResponse::InvalidStatement) => {
            panic!("TransferIn reported an invalid transfer statement");
        }
        Ok(r @ TransferInResponse::InvalidGroup | r @ TransferInResponse::InvalidRealm) => {
            unreachable!("Only a buggy coordinator can get these errors by this point in the process. Got {r:?}");
        }
        Ok(TransferInResponse::InvalidNonce) => Err(Error::InvalidNonce),
        Ok(TransferInResponse::NoStore) => Err(Error::NoStore),
        Ok(
            TransferInResponse::NoHsm
            | TransferInResponse::NotLeader
            | TransferInResponse::NotOwner,
        ) => Err(Error::NoDestinationLeader),
        Err(error) => Err(Error::RpcError(error)),
    }
}

async fn complete_transfer(
    client: &impl http::Client,
    source_leader: &Url,
    transfer: CompleteTransferRequest,
) -> Result<TransferSuccess, TransferError> {
    type Error = TransferError;

    match rpc::send(client, source_leader, transfer.clone()).await {
        Ok(CompleteTransferResponse::Ok) => Ok(TransferSuccess {}),
        Ok(CompleteTransferResponse::CommitTimeout) => Err(Error::CommitTimeout),
        Ok(CompleteTransferResponse::NoHsm | CompleteTransferResponse::NotLeader) => {
            Err(Error::NoSourceLeader)
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
        Err(error) => Err(Error::RpcError(error)),
    }
}

fn classify(e: TransferError) -> AttemptError<TransferError> {
    // Classify an error as retryable or not for the retry loop. When the loop
    // is executed the management grant is already held.
    let tags = Vec::new();
    match e {
        // These can happen at any time, the cluster manager should be dealing
        // with assigning a new leader, so retry to try and find it.
        error @ TransferError::NoSourceLeader => AttemptError::Retryable { error, tags },
        error @ TransferError::NoDestinationLeader => AttemptError::Retryable { error, tags },
        // This is expected if the destination leader changed between prepare transfer and transfer in.
        error @ TransferError::InvalidNonce => AttemptError::Retryable { error, tags },
        // Transient RPC errors to the leader agents.
        error @ TransferError::RpcError(_) => AttemptError::Retryable { error, tags },
        // Likely transient error dealing with bigtable.
        error @ TransferError::NoStore => AttemptError::Retryable { error, tags },

        // The requested transfer is invalid, and retrying isn't going to fix that.
        error @ TransferError::InvalidGroup => AttemptError::Fatal { error, tags },
        error @ TransferError::UnacceptableRange => AttemptError::Fatal { error, tags },
        error @ TransferError::OtherTransferPending => AttemptError::Fatal { error, tags },

        // This happens if the agent has a timeout waiting for a log entry to
        // commit. Hitting this very generous timeout indicates a more serious
        // issue going on with the cluster.
        error @ TransferError::CommitTimeout => AttemptError::Fatal { error, tags },

        // Timeout is only hit inside the retry loop if the transfer chaos is enabled.
        error @ TransferError::Timeout => AttemptError::Fatal { error, tags },

        // This should never happen inside the retry loop as the caller needs to
        // provide the management grant. It's here as an artifact of the fact
        // that the RPC TransferError is reused as the error type inside the
        // retry loop.
        TransferError::ManagerBusy => unreachable!(
            "The management grant is already owned when the transfer retry loop is executed"
        ),
    }
}

/// Cancel's a previously prepared transfer. The caller must ensure that the
/// associated TransferOut has not been performed.
async fn cancel_prepared_transfer(
    client: &impl http::Client,
    dest_leader: &Url,
    t: TransferOutRequest,
) {
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
