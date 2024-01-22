use tracing::info;

use agent_api::{
    CompleteTransferRequest, CompleteTransferResponse, PrepareTransferRequest,
    PrepareTransferResponse, TransferInRequest, TransferInResponse, TransferOutRequest,
    TransferOutResponse,
};
pub use cluster_api::TransferError;
use hsm_api::{GroupId, OwnedRange};
use juicebox_networking::reqwest::{Client, ClientOptions};
use juicebox_networking::rpc;
use juicebox_realm_api::types::RealmId;
use store::StoreClient;

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
        .unwrap_or_default();

    let Some((_, source_leader)) = leaders.get(&(realm, source)) else {
        return Err(Error::NoSourceLeader);
    };

    let Some((_, dest_leader)) = leaders.get(&(realm, destination)) else {
        return Err(Error::NoDestinationLeader);
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

    let (nonce, prepared_stmt) = match rpc::send(
        &agent_client,
        dest_leader,
        PrepareTransferRequest {
            realm,
            source,
            destination,
            range: range.clone(),
        },
    )
    .await
    {
        Ok(PrepareTransferResponse::Ok { nonce, statement }) => (nonce, statement),
        Ok(r) => todo!("{r:?}"),
        Err(e) => todo!("{e:?}"),
    };

    let (transferring_partition, transfer_stmt) = match rpc::send(
        &agent_client,
        source_leader,
        TransferOutRequest {
            realm,
            source,
            destination,
            range: range.clone(),
            nonce,
            statement: prepared_stmt,
        },
    )
    .await
    {
        Ok(TransferOutResponse::Ok {
            transferring,
            statement,
        }) => (transferring, statement),
        Ok(r) => todo!("{r:?}"),
        Err(e) => todo!("{e:?}"),
    };

    match rpc::send(
        &agent_client,
        dest_leader,
        TransferInRequest {
            realm,
            source,
            destination,
            transferring: transferring_partition,
            nonce,
            statement: transfer_stmt,
        },
    )
    .await
    {
        Ok(TransferInResponse::Ok) => {}
        Ok(r) => todo!("{r:?}"),
        Err(e) => todo!("{e:?}"),
    };

    match rpc::send(
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
        Ok(CompleteTransferResponse::Ok) => {}
        Ok(r) => todo!("{r:?}"),
        Err(e) => todo!("{e:?}"),
    };

    Ok(())
}
