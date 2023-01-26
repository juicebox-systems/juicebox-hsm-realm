use std::fmt;

use actix::prelude::*;
use bitvec::vec::BitVec;
use sha2::{Digest, Sha256};

use super::super::hsm::types as hsm_types;
use hsm_types::{
    CapturedStatement, Configuration, EntryHmac, GroupConfigurationStatement, GroupId, HsmId,
    LogIndex, OwnedPrefix, Partition, RealmId, RecordId, SecretsRequest, SecretsResponse,
    TransferNonce, TransferStatement,
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
    Ok { hsm: HsmId },
    HaveOtherRealm,
    NoHsm,
}

#[derive(Debug, Message)]
#[rtype(result = "NewGroupResponse")]
pub struct NewGroupRequest {
    pub realm: RealmId,
    pub configuration: Configuration,
}

#[derive(Debug, MessageResponse)]
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
#[rtype(result = "TransferOutResponse")]
pub struct TransferOutRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    // The prefix to transfer out of source. It may be exactly its current
    // partition prefix to transfer everything, or an extension of its current
    // prefix to perform a split.
    pub prefix: OwnedPrefix,
}

// Note: this returns before the log entry is committed, so the entry could
// still get rolled back. The caller won't be able to get a TransferStatement
// until the entry has committed, so not waiting here is OK.
#[derive(Debug, MessageResponse)]
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

#[derive(Debug, Message)]
#[rtype(result = "TransferNonceResponse")]
pub struct TransferNonceRequest {
    pub realm: RealmId,
    pub destination: GroupId,
}

#[derive(Debug, MessageResponse)]
pub enum TransferNonceResponse {
    Ok(TransferNonce),
    NoHsm,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
}

#[derive(Debug, Message)]
#[rtype(result = "TransferStatementResponse")]
pub struct TransferStatementRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    pub nonce: TransferNonce,
}

#[derive(Debug, MessageResponse)]
pub enum TransferStatementResponse {
    Ok(TransferStatement),
    NoHsm,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    NotTransferring,
}

#[derive(Debug, Message)]
#[rtype(result = "TransferInResponse")]
pub struct TransferInRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    pub transfering: Partition,
    pub nonce: TransferNonce,
    pub statement: TransferStatement,
}

#[derive(Debug, MessageResponse)]
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

#[derive(Debug, Message)]
#[rtype(result = "CompleteTransferResponse")]
pub struct CompleteTransferRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    pub prefix: OwnedPrefix,
}

#[derive(Debug, MessageResponse)]
pub enum CompleteTransferResponse {
    Ok,
    NoHsm,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
}

#[derive(Debug, Message)]
#[rtype(result = "AppResponse")]
pub struct AppRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub rid: RecordId,
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
