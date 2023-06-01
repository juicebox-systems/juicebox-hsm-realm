use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;
use tracing::info;

use super::super::super::http_client::{Client, ClientOptions};
use super::super::agent::types::{
    CompleteTransferRequest, CompleteTransferResponse, TransferInRequest, TransferInResponse,
    TransferNonceRequest, TransferNonceResponse, TransferOutRequest, TransferOutResponse,
    TransferStatementRequest, TransferStatementResponse,
};
use super::super::store::bigtable::StoreClient;
use hsm_types::{GroupId, OwnedRange};
use hsmcore::hsm::types as hsm_types;
use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_networking::rpc;

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("source group missing leader")]
    NoSourceLeader,
    #[error("destination missing leader")]
    NoDestinationLeader,
    // TODO: more error cases hidden in todo!()s.
}

pub async fn transfer(
    realm: RealmId,
    source: GroupId,
    destination: GroupId,
    range: OwnedRange,
    store: &StoreClient,
) -> Result<(), TransferError> {
    type Error = TransferError;

    info!(
        ?realm,
        ?source,
        ?destination,
        ?range,
        "transferring ownership"
    );
    assert_ne!(
        source, destination,
        "cannot transfer ownership to the same group (unsupported)"
    );

    let agent_client = Client::new(ClientOptions::default());

    let leaders = super::leader::find_leaders(store, &agent_client)
        .await
        .expect("TODO");

    let Some((_, source_leader)) = leaders.get(&(realm, source)) else {
        return Err(Error::NoSourceLeader);
    };

    let Some((_, dest_leader)) = leaders.get(&(realm, destination)) else {
        return Err(Error::NoDestinationLeader);
    };

    // The current ownership transfer protocol is dangerous in that the moment
    // the source group commits the log entry that the prefix is transferring
    // out, the prefix must then move to the destination group. However, we
    // don't have any guarantee that the destination group will accept the
    // prefix. This is an issue with each group owning 0 or 1 ranges: the only
    // group that can accept a range is one that owns no range or one that owns
    // an adjacent range.

    let transferring_partition = match rpc::send(
        &agent_client,
        source_leader,
        TransferOutRequest {
            realm,
            source,
            destination,
            range: range.clone(),
        },
    )
    .await
    {
        Err(e) => todo!("{e:?}"),
        Ok(TransferOutResponse::Ok { transferring }) => transferring,
        Ok(r) => todo!("{r:?}"),
    };

    let nonce = match rpc::send(
        &agent_client,
        dest_leader,
        TransferNonceRequest { realm, destination },
    )
    .await
    {
        Err(e) => todo!("{e:?}"),
        Ok(TransferNonceResponse::Ok(nonce)) => nonce,
        Ok(r) => todo!("{r:?}"),
    };

    let statement = match rpc::send(
        &agent_client,
        source_leader,
        TransferStatementRequest {
            realm,
            source,
            destination,
            nonce,
        },
    )
    .await
    {
        Err(e) => todo!("{e:?}"),
        Ok(TransferStatementResponse::Ok(statement)) => statement,
        Ok(r) => todo!("{r:?}"),
    };

    let dest_index = match rpc::send(
        &agent_client,
        dest_leader,
        TransferInRequest {
            realm,
            source,
            destination,
            transferring: transferring_partition,
            nonce,
            statement,
        },
    )
    .await
    {
        Err(e) => todo!("{e:?}"),
        Ok(TransferInResponse::Ok(index)) => index,
        Ok(r) => todo!("{r:?}"),
    };

    // TODO: This part is dangerous because TransferInRequest returns before
    // the transfer has committed (for now). If that log entry doesn't commit
    // and this calls CompleteTransferRequest, the keyspace will be lost
    // forever.

    let src_index = match rpc::send(
        &agent_client,
        source_leader,
        CompleteTransferRequest {
            realm,
            source,
            destination,
            range,
        },
    )
    .await
    {
        Err(e) => todo!("{e:?}"),
        Ok(CompleteTransferResponse::Ok(index)) => index,
        Ok(r) => todo!("{r:?}"),
    };
    // At this point the agents have queued the log entry that contained
    // the completed transfer but may or may not have actually written
    // it to the store yet. So we need to wait for that to happen.
    // TODO: this should really wait for commit, and handled in the agent
    // to be resolved with the overall transfer review/update.
    let wait_for_entry = |group, index| async move {
        loop {
            if let Some(e) = store
                .read_last_log_entry(&realm, &group)
                .await
                .expect("TODO")
            {
                if e.index >= index {
                    return;
                }
                sleep(Duration::from_millis(1)).await;
            }
        }
    };
    wait_for_entry(source, src_index).await;
    wait_for_entry(destination, dest_index).await;

    Ok(())
}
