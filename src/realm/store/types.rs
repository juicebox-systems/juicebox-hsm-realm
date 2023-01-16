use actix::prelude::*;

use super::super::agent::Agent;
use super::super::hsm::types::{GroupId, HsmId, LogEntry, LogIndex, RealmId};

#[derive(Debug, Message)]
#[rtype(result = "AppendResponse")]
pub struct AppendRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub entry: LogEntry,
    pub data: Vec<u8>,
}

#[derive(Debug, MessageResponse)]
pub enum AppendResponse {
    Ok,
    PreconditionFailed,
}

#[derive(Debug, Message)]
#[rtype(result = "ReadResponse")]
pub struct ReadRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub index: LogIndex,
}

#[derive(Debug, MessageResponse)]
pub enum ReadResponse {
    Ok(LogEntry),
    Discarded { start: LogIndex },
    DoesNotExist { last: LogIndex },
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
