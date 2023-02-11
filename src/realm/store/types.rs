use serde::{Deserialize, Serialize};

use super::super::hsm::types::{
    DataHash, GroupId, HsmId, LogEntry, LogIndex, Partition, RealmId, RecordId,
};
use super::super::merkle::{agent::StoreDelta, proof::ReadProof, Dir};
use super::super::rpc::{Rpc, Service};
use reqwest::Url;

#[derive(Clone, Debug)]
pub struct StoreRpc();
impl Service for StoreRpc {}

impl Rpc for AppendRequest {
    const PATH: &'static str = "append";
    type Response = AppendResponse;
    type Family = StoreRpc;
}
#[derive(Debug, Deserialize, Serialize)]
pub struct AppendRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub entry: LogEntry,
    pub delta: Option<StoreDelta<DataHash>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum AppendResponse {
    Ok,
    PreconditionFailed,
}

impl Rpc for ReadEntryRequest {
    const PATH: &'static str = "read_entry";
    type Response = ReadEntryResponse;
    type Family = StoreRpc;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReadEntryRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub index: LogIndex,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ReadEntryResponse {
    Ok(LogEntry),
    Discarded { start: LogIndex },
    DoesNotExist { last: LogIndex },
}

impl Rpc for ReadLatestRequest {
    const PATH: &'static str = "read_latest";
    type Response = ReadLatestResponse;
    type Family = StoreRpc;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReadLatestRequest {
    pub realm: RealmId,
    pub group: GroupId,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ReadLatestResponse {
    Ok { entry: LogEntry },
    None,
}

impl Rpc for GetRecordProofRequest {
    const PATH: &'static str = "record_proof";
    type Response = GetRecordProofResponse;
    type Family = StoreRpc;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetRecordProofRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub record: RecordId,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum GetRecordProofResponse {
    Ok {
        proof: ReadProof<DataHash>,
        index: LogIndex,
    },
    UnknownGroup,
    NotOwner,
    StoreMissingNode,
}

impl Rpc for GetTreeEdgeProofRequest {
    const PATH: &'static str = "tree_proof";
    type Response = GetTreeEdgeProofResponse;
    type Family = StoreRpc;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetTreeEdgeProofRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub partition: Partition,
    pub dir: Dir,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum GetTreeEdgeProofResponse {
    Ok { proof: ReadProof<DataHash> },
    UnknownGroup,
    StoreMissingNode,
}

impl Rpc for SetAddressRequest {
    const PATH: &'static str = "set_address";
    type Response = SetAddressResponse;
    type Family = StoreRpc;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SetAddressRequest {
    pub hsm: HsmId,
    pub address: Url,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum SetAddressResponse {
    Ok,
}

impl Rpc for GetAddressesRequest {
    const PATH: &'static str = "address";
    type Response = GetAddressesResponse;
    type Family = StoreRpc;
}
#[derive(Debug, Deserialize, Serialize)]
pub struct GetAddressesRequest {}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetAddressesResponse(pub Vec<AddressEntry>);

#[derive(Debug, Deserialize, Serialize)]
pub struct AddressEntry {
    pub hsm: HsmId,
    pub address: Url,
}
