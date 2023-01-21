use actix::prelude::*;
use bitvec::prelude::BitVec;
use hmac::Hmac;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;

use super::app::Record;

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct RealmId(pub [u8; 16]);

impl fmt::Debug for RealmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub struct GroupId(pub [u8; 16]);

impl fmt::Debug for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HsmId(pub [u8; 16]);

impl fmt::Debug for HsmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
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

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogIndex(pub u64);

impl LogIndex {
    pub fn next(&self) -> Self {
        Self(self.0.checked_add(1).unwrap())
    }
}

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub index: LogIndex,
    pub owned_prefix: Option<OwnedPrefix>,
    pub data_hash: DataHash,
    pub transferring_out: Option<TransferringOut>,
    pub prev_hmac: EntryHmac,
    pub entry_hmac: EntryHmac,
    // TODO:
    // pub committed: LogIndex,
    // pub committed_statement: CommittedStatement,
}

#[derive(Clone, Debug)]
pub struct TransferringOut {
    pub destination: GroupId,
    pub prefix: OwnedPrefix,
    pub data_hash: DataHash,
    /// This is the first log index when this struct was placed in the source
    /// group's log. It's used by the source group to determine whether
    /// transferring out has committed.
    pub at: LogIndex,
}

/// See [super::EntryHmacBuilder].
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct EntryHmac(pub digest::Output<Hmac<Sha256>>);

impl EntryHmac {
    pub fn zero() -> Self {
        Self(digest::Output::<Hmac<Sha256>>::default())
    }
}

impl fmt::Debug for EntryHmac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OwnedPrefix(pub BitVec);

impl OwnedPrefix {
    pub fn full() -> Self {
        Self(BitVec::new())
    }

    pub fn contains(&self, uid: &UserId) -> bool {
        uid.0.starts_with(&self.0)
    }
}

impl fmt::Debug for OwnedPrefix {
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

#[derive(Clone, Eq, PartialEq)]
pub struct DataHash(pub digest::Output<Sha256>);

impl fmt::Debug for DataHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct RecordMap(pub(super) BTreeMap<UserId, Record>);

/// Set of HSMs forming a group.
///
/// The vector must be sorted by HSM ID, must not contain duplicates, and must
/// contain at least 1 HSM.
#[derive(Clone, Debug)]
pub struct Configuration(pub Vec<HsmId>);

/// See [super::GroupConfigurationStatementBuilder].
#[derive(Clone)]
pub struct GroupConfigurationStatement(pub digest::Output<Hmac<Sha256>>);

impl fmt::Debug for GroupConfigurationStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// See [super::CapturedStatementBuilder].
#[derive(Clone)]
pub struct CapturedStatement(pub digest::Output<Hmac<Sha256>>);

impl fmt::Debug for CapturedStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransferNonce(pub [u8; 16]);

impl fmt::Debug for TransferNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// See [super::TransferStatementBuilder].
#[derive(Clone)]
pub struct TransferStatement(pub digest::Output<Hmac<Sha256>>);

impl fmt::Debug for TransferStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Message)]
#[rtype(result = "StatusResponse")]
pub struct StatusRequest {}

#[derive(Debug, MessageResponse)]
pub struct StatusResponse {
    pub id: HsmId,
    pub realm: Option<RealmStatus>,
}

#[derive(Debug)]
pub struct RealmStatus {
    pub id: RealmId,
    pub groups: Vec<GroupStatus>,
}

#[derive(Debug)]
pub struct GroupStatus {
    pub id: GroupId,
    pub configuration: Configuration,
    pub captured: Option<(LogIndex, EntryHmac)>,
    pub leader: Option<LeaderStatus>,
}

#[derive(Debug)]
pub struct LeaderStatus {
    pub committed: Option<LogIndex>,
    // Note: this might not be committed yet.
    pub owned_prefix: Option<OwnedPrefix>,
}

#[derive(Debug, Message)]
#[rtype(result = "NewRealmResponse")]
pub struct NewRealmRequest {
    pub configuration: Configuration,
}

#[derive(Debug, MessageResponse)]
pub enum NewRealmResponse {
    Ok(NewGroupInfo),
    HaveRealm,
    InvalidConfiguration,
}

#[derive(Debug)]
pub struct NewGroupInfo {
    pub realm: RealmId,
    pub group: GroupId,
    pub statement: GroupConfigurationStatement,
    pub entry: LogEntry,
    pub data: RecordMap,
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
}

#[derive(Debug, Message)]
#[rtype(result = "NewGroupResponse")]
pub struct NewGroupRequest {
    pub realm: RealmId,
    pub configuration: Configuration,
}

#[derive(Debug, MessageResponse)]
pub enum NewGroupResponse {
    Ok(NewGroupInfo),
    InvalidRealm,
    InvalidConfiguration,
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
}

#[derive(Debug, Message)]
#[rtype(result = "CaptureNextResponse")]
pub struct CaptureNextRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub entry: LogEntry,
}

#[derive(Debug, MessageResponse)]
pub enum CaptureNextResponse {
    Ok {
        hsm_id: HsmId,
        captured: CapturedStatement,
    },
    InvalidRealm,
    InvalidGroup,
    InvalidHmac,
    InvalidChain,
    MissingPrev,
}

#[derive(Debug, Message)]
#[rtype(result = "BecomeLeaderResponse")]
pub struct BecomeLeaderRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub last_entry: LogEntry,
}

#[derive(Debug, MessageResponse)]
pub enum BecomeLeaderResponse {
    Ok,
    InvalidRealm,
    InvalidGroup,
    InvalidHmac,
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
}

#[derive(Debug, Message)]
#[rtype(result = "CommitResponse")]
pub struct CommitRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub index: LogIndex,
    pub entry_hmac: EntryHmac,
    pub captures: Vec<(HsmId, CapturedStatement)>,
}

#[derive(Debug, MessageResponse)]
pub enum CommitResponse {
    Ok {
        committed: Option<LogIndex>,
        responses: Vec<(EntryHmac, SecretsResponse)>,
    },
    AlreadyCommitted {
        committed: LogIndex,
    },
    NoQuorum,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
}

#[derive(Debug, Message)]
#[rtype(result = "TransferOutResponse")]
pub struct TransferOutRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    pub prefix: OwnedPrefix,
    pub index: LogIndex,
    pub data: RecordMap,
}

#[derive(Debug, MessageResponse)]
#[allow(clippy::large_enum_variant)]
pub enum TransferOutResponse {
    Ok {
        entry: LogEntry,
        keeping: RecordMap,
        transferring: RecordMap,
    },
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    /// This is also returned when asking for a split that's more than one more
    /// bit beyond the currently owned prefix.
    NotOwner,
    StaleIndex,
    InvalidData,
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
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    NotTransferring,
    Busy,
}

#[derive(Debug, Message)]
#[rtype(result = "TransferInResponse")]
pub struct TransferInRequest {
    pub realm: RealmId,
    pub destination: GroupId,
    pub data: RecordMap,
    pub data_hash: DataHash,
    pub prefix: OwnedPrefix,
    pub nonce: TransferNonce,
    pub statement: TransferStatement,
}

#[derive(Debug, MessageResponse)]
#[allow(clippy::large_enum_variant)]
pub enum TransferInResponse {
    Ok { entry: LogEntry, data: RecordMap },
    InvalidRealm,
    InvalidGroup,
    NotLeader,
    UnacceptablePrefix,
    InvalidNonce,
    InvalidStatement,
    InvalidData,
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
#[allow(clippy::large_enum_variant)]
pub enum CompleteTransferResponse {
    Ok(LogEntry),
    NotTransferring,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
}

#[derive(Debug, Message)]
#[rtype(result = "AppResponse")]
pub struct AppRequest {
    pub realm: RealmId,
    pub group: GroupId,
    pub uid: UserId,
    pub request: SecretsRequest,
    pub index: LogIndex,
    // TODO: With a Merkle tree, this would be a record and a proof.
    pub data: RecordMap,
}

#[derive(Debug, MessageResponse)]
#[allow(clippy::large_enum_variant)]
pub enum AppResponse {
    Ok {
        entry: LogEntry,
        // TODO: With a Merkle tree, this would be a record and a proof.
        data: RecordMap,
    },
    InvalidRealm,
    InvalidGroup,
    StaleIndex,
    Busy,
    NotOwner,
    NotLeader,
    InvalidData,
}

#[derive(Clone, Debug)]
pub enum SecretsRequest {
    Increment,
}

#[derive(Debug)]
pub enum SecretsResponse {
    Increment(u64),
}
