use bitvec::vec::BitVec;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

use super::super::hsm::types as hsm_types;
use hsm_types::{
    CapturedStatement, Configuration, EntryHmac, GroupConfigurationStatement, GroupId, HsmId,
    LogIndex, OwnedRange, Partition, RealmId, RecordId, SecretsRequest, SecretsResponse,
    TransferNonce, TransferStatement,
};

pub trait Rpc: fmt::Debug + DeserializeOwned + Serialize {
    const PATH: &'static str;
    type Response: fmt::Debug + DeserializeOwned + Serialize;
}

impl Rpc for StatusRequest {
    const PATH: &'static str = "status";
    type Response = StatusResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StatusRequest {}

#[derive(Debug, Deserialize, Serialize)]
pub struct StatusResponse {
    pub hsm: Option<hsm_types::StatusResponse>,
}

impl Rpc for NewRealmRequest {
    const PATH: &'static str = "realm/new";
    type Response = NewRealmResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NewRealmRequest {
    pub configuration: Configuration,
}

#[derive(Debug, Deserialize, Serialize)]
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

impl Rpc for JoinRealmRequest {
    const PATH: &'static str = "realm/join";
    type Response = JoinRealmResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JoinRealmRequest {
    pub realm: RealmId,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum JoinRealmResponse {
    Ok { hsm: HsmId },
    HaveOtherRealm,
    NoHsm,
}

impl Rpc for NewGroupRequest {
    const PATH: &'static str = "group/new";
    type Response = NewGroupResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NewGroupRequest {
    pub realm: RealmId,
    pub configuration: Configuration,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum NewGroupResponse {
    Ok {
        group: GroupId,
        statement: GroupConfigurationStatement,
    },
    InvalidRealm,
    InvalidConfiguration,
    NoHsm,
    NoStore,
    StorePreconditionFailed,
}

impl Rpc for JoinGroupRequest {
    const PATH: &'static str = "group/join";
    type Response = JoinGroupResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JoinGroupRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub configuration: Configuration,
    pub statement: GroupConfigurationStatement,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum JoinGroupResponse {
    Ok,
    InvalidRealm,
    InvalidConfiguration,
    InvalidStatement,
    NoHsm,
}

impl Rpc for BecomeLeaderRequest {
    const PATH: &'static str = "become_leader";
    type Response = BecomeLeaderResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BecomeLeaderRequest {
    pub realm: RealmId,
    pub group: GroupId,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum BecomeLeaderResponse {
    Ok,
    NoHsm,
    NoStore,
    InvalidRealm,
    InvalidGroup,
    NotCaptured { have: Option<LogIndex> },
}

impl Rpc for ReadCapturedRequest {
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

impl Rpc for TransferOutRequest {
    const PATH: &'static str = "transfer/out";
    type Response = TransferOutResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransferOutRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    // The range to transfer out of source. It may be exactly its current
    // partition to transfer everything, or a subset of the range that is
    // connected to one side. (i.e. you can't transfer out something from
    // the middle of the existing range)
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

impl Rpc for TransferNonceRequest {
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

impl Rpc for TransferStatementRequest {
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

impl Rpc for TransferInRequest {
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
    UnacceptablePrefix,
    InvalidNonce,
    InvalidStatement,
}

impl Rpc for CompleteTransferRequest {
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
    Ok,
    NoHsm,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
}

impl Rpc for AppRequest {
    const PATH: &'static str = "app";
    type Response = AppResponse;
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AppRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub rid: RecordId,
    pub request: SecretsRequest,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum AppResponse {
    Ok(SecretsResponse),
    NoHsm,
    NoStore,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    InvalidProof,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct UserId(pub BitVec);

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0b")?;
        for bit in &self.0 {
            if *bit {
                write!(f, "1")?;
            } else {
                write!(f, "0")?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct TenantId(pub BitVec);

impl fmt::Debug for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0b")?;
        for bit in &self.0 {
            if *bit {
                write!(f, "1")?;
            } else {
                write!(f, "0")?;
            }
        }
        Ok(())
    }
}

impl From<(TenantId, UserId)> for RecordId {
    fn from(value: (TenantId, UserId)) -> Self {
        let mut h = Sha256::new();
        for bit in &value.0 .0 {
            if *bit {
                h.update([1]);
            } else {
                h.update([0]);
            }
        }
        h.update([b'|']);
        for bit in &value.1 .0 {
            if *bit {
                h.update([1]);
            } else {
                h.update([0]);
            }
        }
        RecordId(h.finalize().into())
    }
}
