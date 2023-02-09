use actix::prelude::*;
use reqwest::Url;

use super::super::hsm::types::{DataHash, GroupId, HsmId, LogEntry, LogIndex, RealmId, RecordId};
use super::super::merkle::{agent::StoreDelta, proof::ReadProof};

#[derive(Debug, Message)]
#[rtype(result = "AppendResponse")]
pub struct AppendRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub entry: LogEntry,
    pub delta: Option<StoreDelta<DataHash>>,
}

#[derive(Debug, MessageResponse)]
pub enum AppendResponse {
    Ok,
    PreconditionFailed,
}

#[derive(Debug, Message)]
#[rtype(result = "ReadEntryResponse")]
pub struct ReadEntryRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub index: LogIndex,
}

#[derive(Debug, MessageResponse)]
#[allow(clippy::large_enum_variant)]
pub enum ReadEntryResponse {
    Ok(LogEntry),
    Discarded { start: LogIndex },
    DoesNotExist { last: LogIndex },
}

#[derive(Debug, Message)]
#[rtype(result = "ReadLatestResponse")]
pub struct ReadLatestRequest {
    pub realm: RealmId,
    pub group: GroupId,
}

#[derive(Debug, MessageResponse)]
#[allow(clippy::large_enum_variant)]
pub enum ReadLatestResponse {
    Ok { entry: LogEntry },
    None,
}

#[derive(Debug, Message)]
#[rtype(result = "GetRecordProofResponse")]
pub struct GetRecordProofRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub record: RecordId,
}
#[derive(Debug, MessageResponse)]
pub enum GetRecordProofResponse {
    Ok {
        proof: ReadProof<DataHash>,
        index: LogIndex,
    },
    UnknownGroup,
    NotOwner,
    StoreMissingNode,
}

#[derive(Debug, Message)]
#[rtype(result = "SetAddressResponse")]
pub struct SetAddressRequest {
    pub hsm: HsmId,
    pub address: Url,
}

#[derive(Debug, MessageResponse)]
pub enum SetAddressResponse {
    Ok,
}

#[derive(Debug, Message)]
#[rtype(result = "GetAddressesResponse")]
pub struct GetAddressesRequest {}

#[derive(Debug, MessageResponse)]
pub struct GetAddressesResponse(pub Vec<AddressEntry>);

#[derive(Debug)]
pub struct AddressEntry {
    pub hsm: HsmId,
    pub address: Url,
}
