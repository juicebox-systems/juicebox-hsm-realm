pub mod merkle;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Display;
use std::time::Duration;

use hsm_api::{
    EntryMac, GroupConfigurationStatement, GroupId, HsmId, HsmRealmStatement, LogIndex, OwnedRange,
    Partition, PreparedTransferStatement, RecordId, RoleStatus, TransferNonce, TransferStatement,
};
use juicebox_marshalling::bytes;
use juicebox_networking::rpc::{Rpc, Service};
use juicebox_realm_api::requests::{ClientRequestKind, NoiseRequest, NoiseResponse};
use juicebox_realm_api::types::{RealmId, SessionId};

#[derive(Clone, Debug)]
pub struct AgentService;

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
    pub hsm: Option<hsm_api::StatusResponse>,
    pub agent: Option<AgentStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AgentStatus {
    pub name: String,
    pub build_hash: String,
    pub groups: Vec<AgentGroupStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AgentGroupStatus {
    pub realm: RealmId,
    pub group: GroupId,
    pub role: RoleStatus,
    pub leader: Option<AgentGroupLeaderStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AgentGroupLeaderStatus {
    pub num_waiting_clients: usize,
    pub last_appended: Option<(LogIndex, EntryMac)>,
    pub append_queue_len: usize,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BecomeLeaderRequest {
    pub realm: RealmId,
    pub group: GroupId,
    // If known, the last log index written by the previous leader.
    pub last: Option<LogIndex>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BecomeLeaderResponse {
    Ok,
    NoHsm,
    NoStore,
    InvalidRealm,
    InvalidGroup,
    StaleIndex,
    FutureIndex,
    StepdownInProgress,
    Timeout,
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
    Ok(Option<hsm_api::Captured>),
}

impl Rpc<AgentService> for PrepareTransferRequest {
    const PATH: &'static str = "transfer/prepare";
    type Response = PrepareTransferResponse;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrepareTransferRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    /// The range that is planned to be transferred out of the `source` group
    /// and into the 'destination' group.
    ///
    /// The range may be exactly the source group's current partition to
    /// transfer everything, or a subset of the range that is connected to one
    /// side. (i.e. you can't transfer out something from the middle of the
    /// existing range)
    pub range: OwnedRange,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum PrepareTransferResponse {
    Ok {
        nonce: TransferNonce,
        statement: PreparedTransferStatement,
    },
    InvalidRealm,
    InvalidGroup,
    UnacceptableRange,
    OtherTransferPending,
    NoStore,
    NoHsm,
    NotLeader,
    CommitTimeout,
}

impl Rpc<AgentService> for CancelPreparedTransferRequest {
    const PATH: &'static str = "transfer/cancel_prepare";
    type Response = CancelPreparedTransferResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CancelPreparedTransferRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    pub range: OwnedRange,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum CancelPreparedTransferResponse {
    Ok,
    InvalidRealm,
    InvalidGroup,
    NotPrepared,
    NoHsm,
    NotLeader,
    CommitTimeout,
}

impl Rpc<AgentService> for TransferOutRequest {
    const PATH: &'static str = "transfer/out";
    type Response = TransferOutResponse;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransferOutRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    /// The range to transfer out of the `source` group.
    ///
    /// The range may be exactly the source group's current partition to
    /// transfer everything, or a subset of the range that is connected to one
    /// side. (i.e. you can't transfer out something from the middle of the
    /// existing range).
    ///
    /// This must match the range that was specified when the
    /// PrepareTransferRequest was sent to the destination group.
    pub range: OwnedRange,
    /// A Nonce and Statement generated by the destination group leader as a
    /// result of executing a PrepareTransferRequest.
    pub nonce: TransferNonce,
    pub statement: PreparedTransferStatement,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum TransferOutResponse {
    Ok {
        transferring: Partition,
        statement: TransferStatement,
    },
    NoStore,
    NoHsm,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    NotOwner,
    InvalidProof,
    UnacceptableRange,
    OtherTransferPending,
    InvalidStatement,
    CommitTimeout,
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
    Ok,
    NoHsm,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    InvalidNonce,
    InvalidStatement,
    NotPrepared,
    NoStore,
    NotOwner,
    CommitTimeout,
}

impl Rpc<AgentService> for GroupOwnsRangeRequest {
    const PATH: &'static str = "transfer/owns";
    type Response = GroupOwnsRangeResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GroupOwnsRangeRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub range: OwnedRange,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum GroupOwnsRangeResponse {
    Ok,
    NotOwned { has: Option<OwnedRange> },
    NoHsm,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    TimedOut,
    TransferInProgress,
}

impl Rpc<AgentService> for CompleteTransferRequest {
    const PATH: &'static str = "transfer/complete";
    type Response = CompleteTransferResponse;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompleteTransferRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    pub range: OwnedRange,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum CompleteTransferResponse {
    Ok,
    NoHsm,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    NotTransferring,
    CommitTimeout,
}

impl Rpc<AgentService> for RateLimitStateRequest {
    const PATH: &'static str = "rate/state";
    type Response = RateLimitStateResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RateLimitStateRequest {}

#[derive(Debug, Deserialize, Serialize)]
pub enum RateLimitStateResponse {
    Ok(Vec<TenantRateLimitState>),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TenantRateLimitState {
    pub tenant: String,
    #[serde(with = "bytes")]
    pub state: Vec<u8>,
}

impl Rpc<AgentService> for ReloadTenantConfigurationRequest {
    const PATH: &'static str = "tenants/reload";
    type Response = ReloadTenantConfigurationResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReloadTenantConfigurationRequest {}

#[derive(Debug, Deserialize, Serialize)]
pub enum ReloadTenantConfigurationResponse {
    Ok { num_tenants: usize },
    NoStore,
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
    pub user: HashedUserId,
}

/// A hashed version of the user id that is used for the tenant recovery event
/// log. The tenant needs to be able to calculate the same hash to map back to
/// their users so this needs to be stable & published.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HashedUserId(String);

impl HashedUserId {
    pub fn new(tenant: &str, user: &str) -> Self {
        assert!(!tenant.contains(':'));
        let h = Sha256::new()
            .chain_update(tenant.as_bytes())
            .chain_update([b':'])
            .chain_update(user.as_bytes())
            .finalize();
        HashedUserId(hex::encode(h))
    }
}

impl Display for HashedUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum AppResponse {
    Ok(NoiseResponse),
    NoHsm,
    NoStore,
    NoPubSub,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    InvalidProof,
    MissingSession,
    SessionError,
    DecodingError,
    RateLimitExceeded,
}
