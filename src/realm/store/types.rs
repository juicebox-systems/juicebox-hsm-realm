use actix::prelude::*;

use super::super::agent::Agent;
use super::super::hsm::types::{GroupId, HsmId, LogEntry, LogIndex, RealmId, RecordMap};

#[derive(Debug, Message)]
#[rtype(result = "AppendResponse")]
pub struct AppendRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub entry: LogEntry,
    pub data: RecordMap,
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
pub enum ReadLatestResponse {
    Ok { entry: LogEntry, data: RecordMap },
    None,
}

#[derive(Debug, Message)]
#[rtype(result = "SetAddressResponse")]
pub struct SetAddressRequest {
    pub hsm: HsmId,
    pub address: Addr<Agent>,
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
    pub address: Addr<Agent>,
}
