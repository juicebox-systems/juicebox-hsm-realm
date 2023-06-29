use serde::{Deserialize, Serialize};
use std::time::Duration;

use hsm_types::{
    GroupConfigurationStatement, GroupId, HsmId, HsmRealmStatement, LogIndex, OwnedRange,
    Partition, RecordId, TransferNonce, TransferStatement,
};
use hsmcore::hsm::types as hsm_types;
use juicebox_sdk_core::{
    requests::{ClientRequestKind, NoiseRequest, NoiseResponse},
    types::{RealmId, SessionId},
};
use juicebox_sdk_networking::rpc::{Rpc, Service};

#[derive(Clone, Debug)]
pub struct AgentService();
impl Service for AgentService {}

impl Rpc<AgentService> for StatusRequest {
    const PATH: &'static str = "status";
    type Response = StatusResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StatusRequest {}

#[derive(Debug, Deserialize, Serialize)]
pub struct StatusResponse {
    pub uptime: Duration,
    pub hsm: Option<hsm_types::StatusResponse>,
}

impl Rpc<AgentService> for NewRealmRequest {
    const PATH: &'static str = "realm/new";
    type Response = NewRealmResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NewRealmRequest {}

#[derive(Debug, Deserialize, Serialize)]
pub enum NewRealmResponse {
    Ok { realm: RealmId, group: GroupId },
    HaveRealm,
    NoHsm,
    NoStore,
    StorePreconditionFailed,
}

impl Rpc<AgentService> for JoinRealmRequest {
    const PATH: &'static str = "realm/join";
    type Response = JoinRealmResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JoinRealmRequest {
    pub realm: RealmId,
    pub peer: HsmId,
    pub statement: HsmRealmStatement,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum JoinRealmResponse {
    Ok { hsm: HsmId },
    HaveOtherRealm,
    InvalidStatement,
    NoHsm,
}

impl Rpc<AgentService> for NewGroupRequest {
    const PATH: &'static str = "group/new";
    type Response = NewGroupResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NewGroupRequest {
    pub realm: RealmId,
    pub members: Vec<(HsmId, HsmRealmStatement)>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum NewGroupResponse {
    Ok {
        group: GroupId,
        statement: GroupConfigurationStatement,
    },
    InvalidRealm,
    InvalidConfiguration,
    InvalidStatement,
    TooManyGroups,
    NoHsm,
    NoStore,
    StorePreconditionFailed,
}

impl Rpc<AgentService> for JoinGroupRequest {
    const PATH: &'static str = "group/join";
    type Response = JoinGroupResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JoinGroupRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub configuration: Vec<HsmId>,
    pub statement: GroupConfigurationStatement,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum JoinGroupResponse {
    Ok,
    InvalidRealm,
    InvalidConfiguration,
    InvalidStatement,
    TooManyGroups,
    NoHsm,
}

impl Rpc<AgentService> for BecomeLeaderRequest {
    const PATH: &'static str = "become_leader";
    type Response = BecomeLeaderResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BecomeLeaderRequest {
    pub realm: RealmId,
    pub group: GroupId,
    // If known, the last log index written by the previous leader.
    pub last: Option<LogIndex>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum BecomeLeaderResponse {
    Ok,
    NoHsm,
    NoStore,
    InvalidRealm,
    InvalidGroup,
    StepdownInProgress,
    TimeoutWaitForLogIndex,
    NotCaptured { have: Option<LogIndex> },
}

impl Rpc<AgentService> for StepDownRequest {
    const PATH: &'static str = "stepdown";
    type Response = StepDownResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StepDownRequest {
    pub realm: RealmId,
    pub group: GroupId,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum StepDownResponse {
    Ok { last: LogIndex },
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    NoHsm,
}

impl Rpc<AgentService> for ReadCapturedRequest {
    const PATH: &'static str = "captured";
    type Response = ReadCapturedResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReadCapturedRequest {
    pub realm: RealmId,
    pub group: GroupId,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ReadCapturedResponse {
    Ok(Option<hsm_types::Captured>),
}

impl Rpc<AgentService> for TransferOutRequest {
    const PATH: &'static str = "transfer/out";
    type Response = TransferOutResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransferOutRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    /// The range to transfer out of the `source` group.
    ///
    /// The range may be exactly the source group's current partition to
    /// transfer everything, or a subset of the range that is connected to one
    /// side. (i.e. you can't transfer out something from the middle of the
    /// existing range)
    pub range: OwnedRange,
}

// Note: this returns before the log entry is committed, so the entry could
// still get rolled back. The caller won't be able to get a TransferStatement
// until the entry has committed, so not waiting here is OK.
#[derive(Debug, Deserialize, Serialize)]
pub enum TransferOutResponse {
    Ok { transferring: Partition },
    NoStore,
    NoHsm,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    NotOwner,
    InvalidProof,
}

impl Rpc<AgentService> for TransferNonceRequest {
    const PATH: &'static str = "transfer/nonce";
    type Response = TransferNonceResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransferNonceRequest {
    pub realm: RealmId,
    pub destination: GroupId,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum TransferNonceResponse {
    Ok(TransferNonce),
    NoHsm,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
}

impl Rpc<AgentService> for TransferStatementRequest {
    const PATH: &'static str = "transfer/statement";
    type Response = TransferStatementResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransferStatementRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    pub nonce: TransferNonce,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum TransferStatementResponse {
    Ok(TransferStatement),
    NoHsm,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    NotTransferring,
}

impl Rpc<AgentService> for TransferInRequest {
    const PATH: &'static str = "transfer/in";
    type Response = TransferInResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransferInRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    pub transferring: Partition,
    pub nonce: TransferNonce,
    pub statement: TransferStatement,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum TransferInResponse {
    Ok(LogIndex),
    NoHsm,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    UnacceptableRange,
    InvalidNonce,
    InvalidStatement,
    NoStore,
    NotOwner,
}

impl Rpc<AgentService> for CompleteTransferRequest {
    const PATH: &'static str = "transfer/complete";
    type Response = CompleteTransferResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CompleteTransferRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    pub range: OwnedRange,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum CompleteTransferResponse {
    Ok(LogIndex),
    NoHsm,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    NotTransferring,
}

impl Rpc<AgentService> for AppRequest {
    const PATH: &'static str = "app";
    type Response = AppResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AppRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub record_id: RecordId,
    pub session_id: SessionId,
    pub kind: ClientRequestKind,
    pub encrypted: NoiseRequest,
    pub tenant: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum AppResponse {
    Ok(NoiseResponse),
    NoHsm,
    NoStore,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    InvalidProof,
    MissingSession,
    SessionError,
    DecodingError,
}
