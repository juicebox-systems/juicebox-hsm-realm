use actix::prelude::*;

use super::super::hsm::types as hsm_types;
use hsm_types::{
    CapturedStatement, Configuration, EntryHmac, GroupConfigurationStatement, GroupId, HsmId,
    LogIndex, RealmId, SecretsRequest, SecretsResponse, UserId,
};

#[derive(Debug, Message)]
#[rtype(result = "StatusResponse")]
pub struct StatusRequest {}

#[derive(Debug, MessageResponse)]
pub struct StatusResponse {
    pub hsm: Option<hsm_types::StatusResponse>,
}

#[derive(Debug, Message)]
#[rtype(result = "NewRealmResponse")]
pub struct NewRealmRequest {
    pub configuration: Configuration,
}

#[derive(Debug, MessageResponse)]
pub enum NewRealmResponse {
    Ok {
        realm: RealmId,
        group: GroupId,
        statement: GroupConfigurationStatement,
    },
    HaveRealm,
    InvalidConfiguration,
    NoHsm,
    NoStore,
    StorePreconditionFailed,
}

#[derive(Debug, Message)]
#[rtype(result = "JoinRealmResponse")]
pub struct JoinRealmRequest {
    pub realm: RealmId,
}

#[derive(Debug, MessageResponse)]
pub enum JoinRealmResponse {
    Ok,
    HaveRealm,
    NoHsm,
}

#[derive(Debug, Message)]
#[rtype(result = "JoinGroupResponse")]
pub struct JoinGroupRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub configuration: Configuration,
    pub statement: GroupConfigurationStatement,
}

#[derive(Debug, MessageResponse)]
pub enum JoinGroupResponse {
    Ok,
    InvalidRealm,
    InvalidConfiguration,
    InvalidStatement,
    NoHsm,
}

#[derive(Debug, Message)]
#[rtype(result = "BecomeLeaderResponse")]
pub struct BecomeLeaderRequest {
    pub realm: RealmId,
    pub group: GroupId,
}

#[derive(Debug, MessageResponse)]
pub enum BecomeLeaderResponse {
    Ok,
    NoHsm,
    NoStore,
    InvalidRealm,
    InvalidGroup,
    NotCaptured { have: Option<LogIndex> },
}

#[derive(Debug, Message)]
#[rtype(result = "ReadCapturedResponse")]
pub struct ReadCapturedRequest {
    pub realm: RealmId,
    pub group: GroupId,
}

#[derive(Debug, MessageResponse)]
pub enum ReadCapturedResponse {
    Ok {
        hsm_id: HsmId,
        index: LogIndex,
        entry_hmac: EntryHmac,
        statement: CapturedStatement,
    },
    InvalidRealm,
    InvalidGroup,
    None,
    NoHsm,
}

#[derive(Debug, Message)]
#[rtype(result = "AppResponse")]
pub struct AppRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub uid: UserId,
    pub request: SecretsRequest,
}

#[derive(Debug, MessageResponse)]
pub enum AppResponse {
    Ok(SecretsResponse),
    NoHsm,
    NoStore,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
}
