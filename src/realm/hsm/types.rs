use actix::prelude::*;
use hmac::Hmac;
use sha2::Sha256;
use std::fmt;

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

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LogIndex(pub u64);

#[derive(Clone, Debug)]
pub struct LogEntry {
    pub index: LogIndex,
    pub owned_prefix: OwnedPrefix,
    pub data_hash: DataHash,
    pub prev_hmac: EntryHmac,
    pub entry_hmac: EntryHmac,
    // TODO:
    // migrating out
    // pub committed: LogIndex,
    // pub committed_statement: CommittedStatement,
}

/// See [super::EntryHmacBuilder].
#[derive(Clone, Eq, PartialEq)]
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

#[derive(Clone, Debug)]
pub struct OwnedPrefix {
    pub bits: u16,
    pub mask: u8,
}

#[derive(Clone)]
pub struct DataHash(pub digest::Output<Sha256>);

impl fmt::Debug for DataHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

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
    pub is_leader: bool,
    pub captured: Option<(LogIndex, EntryHmac)>,
    pub committed: Option<LogIndex>,
}

#[derive(Debug, Message)]
#[rtype(result = "NewRealmResponse")]
pub struct NewRealmRequest {
    pub configuration: Configuration,
}

#[derive(Debug, MessageResponse)]
pub enum NewRealmResponse {
    Ok(NewRealmResponseOk),
    HaveRealm,
    InvalidConfiguration,
}

#[derive(Debug)]
pub struct NewRealmResponseOk {
    pub realm: RealmId,
    pub group: GroupId,
    pub statement: GroupConfigurationStatement,
    pub entry: LogEntry,
    pub data: Vec<u8>,
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
    pub index: LogIndex,
    pub owned_prefix: OwnedPrefix,
    pub data_hash: DataHash,
    pub prev_hmac: EntryHmac,
    pub entry_hmac: EntryHmac,
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
    pub index: LogIndex,
}

#[derive(Debug, MessageResponse)]
pub enum BecomeLeaderResponse {
    Ok,
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
    Ok { committed: Option<LogIndex> },
    NoQuorum,
    InvalidRealm,
    InvalidGroup,
    NotLeader,
}
