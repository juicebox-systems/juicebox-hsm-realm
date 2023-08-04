#![no_std]

pub mod merkle;
pub mod rpc;

extern crate alloc;

use alloc::vec::Vec;
use blake2::Blake2sMac256;
use core::fmt::{self, Display};
use core::ops::Deref;
use core::time::Duration;
use digest::CtOutput;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

use bitvec::{BitVec, Bits};
use juicebox_marshalling::bytes;
use juicebox_noise::server as noise;
use juicebox_realm_api::{
    requests::{NoiseRequest, NoiseResponse},
    types::{RealmId, SessionId},
};
use merkle::{HashOutput, ReadProof, StoreDelta};

/// A unique identifier for a replication group.
///
/// Group IDs are generated randomly by the first HSM to create the group.
#[derive(Copy, Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct GroupId(#[serde(with = "bytes")] pub [u8; 16]);

impl fmt::Debug for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A unique identifier for an HSM.
///
/// HSM IDs are generated randomly within an HSM when the HSM software is
/// initialized. The HSM persists its ID along with its other non-volatile
/// state.
#[derive(Copy, Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct HsmId(#[serde(with = "bytes")] pub [u8; 16]);

impl fmt::Debug for HsmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for HsmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A public key used by clients for encrypted communication (over Noise)
/// to the HSMs in a realm.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicKey(#[serde(with = "bytes")] pub Vec<u8>);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Identifies a tenant and user in the context of a particular realm.
///
/// Each replication group can be assigned up to one range of record IDs to
/// manage; see [`OwnedRange`]. The record IDs are also used as the lookup keys
/// into the Merkle trees.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RecordId(#[serde(with = "bytes")] pub [u8; Self::NUM_BYTES]);

impl RecordId {
    pub const NUM_BYTES: usize = 32;
    pub const NUM_BITS: usize = Self::NUM_BYTES * 8;

    pub fn min_id() -> Self {
        RecordId([0; Self::NUM_BYTES])
    }

    pub fn max_id() -> Self {
        RecordId([255; Self::NUM_BYTES])
    }

    pub fn next(&self) -> Option<RecordId> {
        let mut r = RecordId(self.0);
        for i in (0..r.0.len()).rev() {
            if r.0[i] < 255 {
                r.0[i] += 1;
                return Some(r);
            } else {
                r.0[i] = 0;
            }
        }
        None
    }

    pub fn prev(&self) -> Option<RecordId> {
        let mut r = RecordId(self.0);
        for i in (0..r.0.len()).rev() {
            if r.0[i] > 0 {
                r.0[i] -= 1;
                return Some(r);
            } else {
                r.0[i] = 255;
            }
        }
        None
    }

    pub fn to_bitvec(&self) -> BitVec {
        BitVec::from_bytes(&self.0)
    }

    pub fn from_bitvec(bits: &BitVec) -> RecordId {
        assert_eq!(bits.len(), RecordId::NUM_BITS);
        let mut r = RecordId([0; Self::NUM_BYTES]);
        r.0.copy_from_slice(bits.as_bytes());
        r
    }
}

impl fmt::Debug for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A sequential number for an entry in a log (see [`LogEntry`]).
#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LogIndex(pub u64);

impl LogIndex {
    /// The index of the first entry in a log.
    ///
    /// # Historical Context
    ///
    /// Diego started log entries at 1 because that's what Raft does. Raft uses
    /// log index 0 to conveniently indicate "no entry" or "no entries". In
    /// this Rust project, we instead use `Option<LogIndex>` when it's possible
    /// there is no such entry, but we still skip index 0 as a reserved value.
    pub const FIRST: Self = Self(1);

    pub fn prev(&self) -> Option<Self> {
        if self.0 <= 1 {
            None
        } else {
            self.0.checked_sub(1).map(Self)
        }
    }

    pub fn next(&self) -> Self {
        Self(self.0.checked_add(1).unwrap())
    }
}

impl fmt::Display for LogIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A partition describes the data that a replication group owns.
///
/// It also identifies a snapshot of a Merkle tree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Partition {
    pub range: OwnedRange,
    pub root_hash: DataHash,
}

/// An atomic unit in a log, which describes a new state for a replication
/// group.
///
/// Each replication group has a log. The log is used to drive replication and
/// commitment across the HSMs in the group. The HSMs generate and authenticate
/// log entries, but they do not directly persist log entries; the agents do
/// this externally on commodity hardware.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogEntry {
    /// Each log contains entries numbered sequentially.
    ///
    /// Note that different leaders in the same replication group may compete
    /// to assign the same log index number to different entries. Only one such
    /// entry can successfully commit.
    pub index: LogIndex,
    /// If this group owns any data, this contains the range of records it is
    /// responsible for and the current root hash of the Merkle tree storing
    /// that data. Otherwise, this is `None`.
    pub partition: Option<Partition>,
    /// If this group is currently transferring ownership of records to another
    /// group, this field includes some metadata about that. This metadata is
    /// copied to all subsequent log entries until the transfer completes.
    pub transferring_out: Option<TransferringOut>,
    /// A copy of the `entry_mac` field of the entry preceding this one.
    ///
    /// For the first entry in the log, this is [`EntryMac::zero`].
    pub prev_mac: EntryMac,
    /// Allows HSMs to check the authenticity of the entry.
    pub entry_mac: EntryMac,
    /// The Id of the HSM that generated this entry. This ensures that log
    /// entries/mac's differ even if 2 HSM generate an otherwise identical
    /// entry. This can happen if a log entry is generated but the tree did not
    /// change.
    pub hsm: HsmId,
    // TODO: these may be needed for log compaction:
    // pub committed: LogIndex,
    // pub committed_statement: CommittedStatement,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransferringOut {
    pub destination: GroupId,
    pub partition: Partition,
    /// This is the first log index when this struct was placed in the source
    /// group's log. It's used by the source group to determine whether
    /// transferring out has committed.
    pub at: LogIndex,
}

/// A Fixed size array of bytes that are compared in constant time.
#[derive(Clone, Deserialize, Eq, Serialize)]
pub struct CtBytes<const N: usize>(#[serde(with = "bytes")] [u8; N]);

impl<const N: usize> CtBytes<N> {
    pub fn zero() -> Self {
        CtBytes([0; N])
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl From<CtOutput<Blake2sMac256>> for CtBytes<32> {
    fn from(value: CtOutput<Blake2sMac256>) -> Self {
        CtBytes(value.into_bytes().into())
    }
}

impl<const N: usize> From<[u8; N]> for CtBytes<N> {
    fn from(value: [u8; N]) -> Self {
        CtBytes(value)
    }
}

impl<const N: usize> ConstantTimeEq for CtBytes<N> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<const N: usize> PartialEq for CtBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl<const N: usize> fmt::Debug for CtBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A MAC over a log entry, allowing HSMs to check the authenticity of the
/// entry.
///
/// The MAC is over the following fields:
/// - realm ID
/// - group ID
/// - entry's `index`,
/// - entry's `partition`,
/// - entry's `transferring_out`, and
/// - entry's `prev_mac`.
///
/// See [super::mac::EntryMacMessage].
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct EntryMac(CtBytes<32>);

impl EntryMac {
    pub fn zero() -> Self {
        Self(CtBytes::zero())
    }
}

impl Deref for EntryMac {
    type Target = CtBytes<32>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for EntryMac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<CtBytes<32>> for EntryMac {
    fn from(value: CtBytes<32>) -> Self {
        Self(value)
    }
}

impl From<[u8; 32]> for EntryMac {
    fn from(value: [u8; 32]) -> Self {
        Self(value.into())
    }
}

/// A contiguous range of record IDs.
///
/// Each replication group may own zero or one such ranges.
///
/// See also [`Partition`].
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct OwnedRange {
    /// Inclusive.
    pub start: RecordId,
    /// Inclusive.
    pub end: RecordId,
}

impl fmt::Debug for OwnedRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:?}-{:?}]", &self.start, &self.end)
    }
}

impl OwnedRange {
    pub fn full() -> OwnedRange {
        OwnedRange {
            start: RecordId::min_id(),
            end: RecordId::max_id(),
        }
    }

    pub fn contains(&self, record_id: &RecordId) -> bool {
        record_id >= &self.start && record_id <= &self.end
    }

    /// Returns the single range resulting from merging `self` and `other`, or
    /// returns `None` if the two are not adjacent.
    pub fn join(&self, other: &OwnedRange) -> Option<Self> {
        match self.end.next() {
            Some(r) if r == other.start => Some(OwnedRange {
                start: self.start.clone(),
                end: other.end.clone(),
            }),
            None | Some(_) => match other.end.next() {
                Some(r) if r == self.start => Some(OwnedRange {
                    start: other.start.clone(),
                    end: self.end.clone(),
                }),
                None | Some(_) => None,
            },
        }
    }

    /// Determines the split point when splitting `other` out of `self`.
    ///
    /// If `other` can be split out of `self`, returns the starting record ID
    /// in the resulting right-side range. Otherwise, returns None.
    pub fn split_at(&self, other: &OwnedRange) -> Option<RecordId> {
        if self.start == other.start && other.end < self.end {
            Some(other.end.next().unwrap())
        } else if self.end == other.end && other.start > self.start {
            Some(other.start.clone())
        } else {
            None
        }
    }
}

/// The hash of a node in the Merkle tree.
///
/// The hash is determined by the node's contents and that of all nodes below
/// it.
///
/// The hash of the root node serves as the hash of the tree.
#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DataHash(#[serde(with = "bytes")] pub [u8; 32]);

impl fmt::Debug for DataHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
impl HashOutput for DataHash {
    fn zero() -> DataHash {
        DataHash([0; 32])
    }
    fn from_slice(bytes: &[u8]) -> Option<DataHash> {
        let mut out = DataHash(Default::default());
        if bytes.len() == out.0.len() {
            out.0.copy_from_slice(bytes);
            Some(out)
        } else {
            None
        }
    }
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// The maximum number of HSMs permitted in a replication group.
///
/// This is restricted to avoid filling up HSM NVRAM. It's also not practically
/// very useful to support larger groups, since a group of 9 can tolerate 4 HSM
/// failures, and by then, you're in significant trouble.
pub const CONFIGURATION_LIMIT: u8 = 9;

/// The maximum number of replication groups permitted per HSM.
///
/// This is restricted to avoid filling up HSM NVRAM.
pub const GROUPS_LIMIT: u8 = 16;

/// A MAC over a realm ID, group ID, and group configuration.
///
/// See [super::mac::GroupConfigurationStatementMessage].
#[derive(Clone, Deserialize, Serialize)]
pub struct GroupConfigurationStatement(CtBytes<32>);

impl Deref for GroupConfigurationStatement {
    type Target = CtBytes<32>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for GroupConfigurationStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<CtBytes<32>> for GroupConfigurationStatement {
    fn from(value: CtBytes<32>) -> Self {
        Self(value)
    }
}

/// A MAC over an HSM ID, a realm ID, and the realm's keys.
///
/// See [super::mac::HsmRealmStatementMessage].
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct HsmRealmStatement(CtBytes<32>);

impl Deref for HsmRealmStatement {
    type Target = CtBytes<32>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for HsmRealmStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<CtBytes<32>> for HsmRealmStatement {
    fn from(value: CtBytes<32>) -> Self {
        Self(value)
    }
}

impl From<[u8; 32]> for HsmRealmStatement {
    fn from(value: [u8; 32]) -> Self {
        Self(value.into())
    }
}

/// A MAC over an assertion that a particular HSM has captured a particular log
/// entry.
///
/// The MAC is over the following fields:
/// - the ID of the HSM that captured the entry,
/// - realm ID,
/// - group ID,
/// - log index, and
/// - entry MAC.
///
/// See [super::mac::CapturedStatementMessage].
#[derive(Clone, Deserialize, Serialize)]
pub struct CapturedStatement(CtBytes<32>);

impl Deref for CapturedStatement {
    type Target = CtBytes<32>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for CapturedStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<CtBytes<32>> for CapturedStatement {
    fn from(value: CtBytes<32>) -> Self {
        Self(value)
    }
}

/// A random value generated by the destination group of an ownership transfer.
///
/// This is used for the destination group to check that a
/// [`TransferStatement`], which is generated by the source group, is not
/// stale.
#[derive(Copy, Clone, Deserialize, Eq, Serialize)]
pub struct TransferNonce(#[serde(with = "bytes")] pub [u8; 16]);

impl fmt::Debug for TransferNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl PartialEq for TransferNonce {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

/// A MAC over a description of an ownership transfer, generated by the leader
/// of the source group.
///
/// The MAC is over the following fields:
/// - realm ID,
/// - destination group ID,
/// - partition (range of record IDs and hash of root node to transfer), and
/// - transfer nonce from the destination group.
///
/// See [super::mac::TransferStatementMessage].
#[derive(Clone, Deserialize, Serialize)]
pub struct TransferStatement(CtBytes<32>);

impl Deref for TransferStatement {
    type Target = CtBytes<32>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for TransferStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<CtBytes<32>> for TransferStatement {
    fn from(value: CtBytes<32>) -> Self {
        Self(value)
    }
}

/// Request type for the HSM Status RPC (see [`StatusResponse`]). Returns
/// information about the HSM's current state.
///
/// This is used for a variety of reasons, including diagnostics, the
/// replication protocol, and administrative protocols.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StatusRequest {}

/// Response type for the HSM Status RPC (see [`StatusRequest`]).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StatusResponse {
    /// The HSM's unique ID.
    pub id: HsmId,
    /// Each HSM can join up to one realm (for simplicity). This field is
    /// `Some` if the HSM has joined a realm and `None` otherwise.
    pub realm: Option<RealmStatus>,
    /// The public key used by clients for encrypted communication (over Noise)
    /// to the HSM.
    pub public_key: PublicKey,
}

/// Part of [`StatusResponse`]. Contains information about the HSM's
/// participation in the realm that it has joined.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RealmStatus {
    /// The unique identifier for the realm.
    ///
    /// Realm IDs are generated randomly by the first HSM to create the realm.
    pub id: RealmId,
    /// A MAC that can prove to other HSMs that this HSM has joined the realm
    /// and has possession of the realm's secret keys.
    ///
    /// Other HSMs will want to verify this before joining the realm or before
    /// creating a group with this HSM.
    pub statement: HsmRealmStatement,
    /// Information about the HSM's participation in replication groups within
    /// this realm.
    ///
    /// Each HSM is a member of 0 or more groups. Each group is represented
    /// exactly once in the `Vec`, in no particular order.
    pub groups: Vec<GroupStatus>,
}

/// Part of [`StatusResponse`]. Contains information about the HSM's
/// participation in a particular replication group (in a particular realm).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GroupStatus {
    /// The group's unique ID.
    pub id: GroupId,
    /// The group's fixed set of members, including this HSM, in sorted order.
    pub configuration: Vec<HsmId>,
    /// Information the HSM has "captured" persistently about the last log
    /// entry for the group that it has seen, if any.
    ///
    /// This is guaranteed to advance monotonically, even across power outages.
    /// The HSM guarantees that the entry MAC was valid and chained back to the
    /// previous log entries it had seen.
    pub captured: Option<(LogIndex, EntryMac)>,
    /// If the HSM is acting as leader for the group, this provides more
    /// information.
    ///
    /// ## Warning
    ///
    /// Although normally a group should have a single leader, it's possible
    /// for a group to have no leader (an availability gap), and it's possible
    /// for multiple HSMs to be acting as leader of a group simultaneously
    /// (though only one will be able to commit its log entries successfully).
    pub leader: Option<LeaderStatus>,
    /// The HSM's current role in this group.
    pub role: GroupMemberRole,
}

/// An HSM's current role in a particular replication group.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GroupMemberRole {
    /// The HSM accepts new requests from clients and executes them. It also
    /// acts as a witness.
    Leader,
    /// The HSM is finishing up client requests that it received as leader, but
    /// it is not accepting new requests. It also acts as a witness.
    ///
    /// Once this HSM commits the existing client requests, it will become a
    /// witness only.
    SteppingDown,
    /// The HSM is not accepting requests from clients. It "captures" log
    /// entries after they have been persisted to an external storage system.
    Witness,
}

impl Display for GroupMemberRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GroupMemberRole::Leader => f.write_str("Leader"),
            GroupMemberRole::SteppingDown => f.write_str("Stepping Down"),
            GroupMemberRole::Witness => f.write_str("Witness"),
        }
    }
}

/// Part of [`StatusResponse`]. Contains information about the HSM's leadership
/// of a particular replication group (in a particular realm).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LeaderStatus {
    /// The index of the last log entry that the HSM has marked as committed
    /// during its leadership, if any.
    ///
    /// A leader will mark log entries committed when processing
    /// [`CommitRequest`], once a strict majority of the group configuration
    /// has persistently captured the entries.
    ///
    /// This index grows monotonically while an HSM is leader, but it will be
    /// reset to `None` upon restarting or stepping down and becoming leader
    /// again.
    ///
    /// ## Warning
    ///
    /// The value returned is just a log index without an entry MAC. Don't
    /// assume this refers to some other log entry just because they happen to
    /// have the same index. Multiple uncommitted log entries may compete to be
    /// committed at a particular log index.
    pub committed: Option<LogIndex>,

    /// A partition of users that this HSM believes this group is responsible
    /// for.
    ///
    /// ## Warning
    ///
    /// Generally, this value changes very infrequently as the cluster's load
    /// is rebalanced across groups. However, the value returned here might not
    /// be committed yet, and it may never become committed. It may also be out
    /// of date.
    pub owned_range: Option<OwnedRange>,
}

/// Request type for the HSM NewRealm RPC (see [`NewRealmResponse`]). Creates a
/// new realm with a single new replication group consisting of a single HSM.
///
/// The HSM serving this request will automatically join the new realm and
/// group.
///
/// Initially, the new group will own the entire user partition (it will be
/// responsible for all record IDs). After the realm is created, additional
/// groups can be created, and the data can be repartitioned and transferred.
///
/// For development and testing, it's common to create new realms frequently.
/// For production, NewRealm is used just once, probably during a key ceremony,
/// when launching a new HSM-backed realm.
#[derive(Debug, Deserialize, Serialize)]
pub struct NewRealmRequest {}

/// Response type for the HSM NewRealm RPC (see [`NewRealmRequest`]).
#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum NewRealmResponse {
    /// The realm was created successfully on this HSM.
    Ok {
        /// The newly generated ID of the new realm.
        realm: RealmId,
        /// The newly generated ID for the new group.
        group: GroupId,
        /// The first log entry for the new group.
        ///
        /// This entry should be persisted. If it somehow fails to persist, the
        /// new realm/group should be discarded by clearing the HSM.
        entry: LogEntry,
        /// Merkle tree data to be persisted.
        ///
        /// The new group owns a new Merkle tree, and this contains its root
        /// node.
        delta: StoreDelta<DataHash>,
    },
    /// This HSM is already a member of a realm, so it can't create a new
    /// realm.
    HaveRealm,
}

/// Request type for the HSM JoinRealm RPC (see [`JoinRealmResponse`]). The HSM
/// persists the realm ID and refuses to join any other realm in the future.
///
/// For production, HSMs are typically joined to a realm once when they are
/// deployed.
///
/// HSMs are limited to participating in one realm for simplicity. The only way
/// to undo the JoinRealm operation is to reinitialize the HSM with a new
/// identity.
#[derive(Debug, Deserialize, Serialize)]
pub struct JoinRealmRequest {
    /// The ID of the realm to join.
    pub realm: RealmId,
    /// The ID of another HSM that has already joined the realm.
    ///
    /// This is used to validate the provided `statement`.
    pub peer: HsmId,
    /// A MAC proving that `peer` has joined the realm and has possession of
    /// the realm's secret keys.
    ///
    /// By verifying this MAC, this HSM confirms that it has the same keys,
    /// which is useful in preventing operator errors.
    pub statement: HsmRealmStatement,
}

/// Response type for the HSM JoinRealm RPC (see [`JoinRealmRequest`]).
#[derive(Debug, Deserialize, Serialize)]
pub enum JoinRealmResponse {
    /// The HSM successfully and persistently joined the realm (or it had
    /// already done so).
    Ok {
        /// The ID of this HSM, for convenience.
        hsm: HsmId,
    },
    /// This HSM is already a member of a different realm, so it can't join
    /// this realm.
    HaveOtherRealm,
    /// This HSM could not verify the provided statement.
    ///
    /// Check that it and `peer` have been initialized with the same secret
    /// keys.
    InvalidStatement,
}

/// Request type for the HSM NewGroup RPC (see [`NewGroupResponse`]). Creates a
/// new replication group within an existing realm.
///
/// The HSM serving this request should have already joined the realm. It will
/// automatically join the new group.
///
/// Initially, the new group will not own a user partition (it will be
/// responsible for no record IDs). After the group is created, data can be
/// repartitioned and transferred from another group.
///
/// Groups may be created when rebalancing load across a cluster. Each HSM has
/// to persist information about each group that it's a member of. To prevent
/// rollback attacks, an HSM cannot forget this information (unless it's
/// reinitialized with a new identity). Therefore, you should not accumulate
/// too many unnecessary groups. Each HSM can join up to [`GROUPS_LIMIT`]
/// groups.
#[derive(Debug, Deserialize, Serialize)]
pub struct NewGroupRequest {
    /// The ID of the realm that every new group member should have already
    /// joined.
    pub realm: RealmId,
    /// The set of HSM members for the new group, including this HSM, as well
    /// as MACs proving that each HSM has joined the realm and possesses the
    /// same secret keys.
    ///
    /// The vector should be sorted by HSM ID and should not exceed
    /// [`CONFIGURATION_LIMIT`] in length.
    pub members: Vec<(HsmId, HsmRealmStatement)>,
}

/// Response type for the HSM NewGroup RPC (see [`NewGroupRequest`]).
#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum NewGroupResponse {
    /// The group was created successfully on this HSM.
    Ok {
        /// The newly generated ID for the new group.
        group: GroupId,
        /// This MAC should be given to other members of the group with
        /// [`JoinGroupRequest`] after persisting `entry`.
        statement: GroupConfigurationStatement,
        /// The first log entry for the new group.
        ///
        /// This entry should be persisted. If it somehow fails to persist, the
        /// new group should be abandoned.
        entry: LogEntry,
    },
    /// This HSM is not a member of this realm (it's either not a member of any
    /// realm or is already a member of a different realm), so it can't create
    /// the new group.
    InvalidRealm,
    /// The given `members` does not contain this HSM, is not sorted by HSM ID,
    /// contains duplicate HSM IDs, or exceeds [`CONFIGURATION_LIMIT`] in
    /// length.
    InvalidConfiguration,
    /// This HSM could not verify one of the provided [`HsmRealmStatement`]s.
    ///
    /// Check that it and the other members have been initialized with the same
    /// secret keys.
    InvalidStatement,
    /// This HSM cannot join any more groups, since it is already a member of
    /// [`GROUPS_LIMIT`].
    TooManyGroups,
}

/// Request type for the HSM JoinGroup RPC (see [`JoinGroupResponse`]). The HSM
/// persistently becomes a member of a replication group.
///
/// When the group is created with the NewGroup RPC at the first HSM, it's
/// created with its fixed set of members. This RPC is used to inform the
/// remaining members of the group.
///
/// The HSM serving this request should have already joined the realm. The
/// group should have already been created on another HSM using the NewGroup
/// RPC.
///
/// Each HSM has to persist information about each group that it's a member of.
/// To prevent rollback attacks, an HSM cannot forget this information (unless
/// it's reinitialized with a new identity). Each HSM can join up to
/// [`GROUPS_LIMIT`] groups.
#[derive(Debug, Deserialize, Serialize)]
pub struct JoinGroupRequest {
    /// The ID of the realm that this HSM should have already joined.
    pub realm: RealmId,
    /// The ID of the group to join.
    pub group: GroupId,
    /// The fixed set of HSM members for the group, including this HSM.
    ///
    /// The vector should be sorted by HSM ID.
    pub configuration: Vec<HsmId>,
    /// A MAC created by the HSM that created the group, used to check the
    /// authenticity of the group information.
    pub statement: GroupConfigurationStatement,
}

/// Response type for the HSM JoinGroup RPC (see [`JoinGroupRequest`]).
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum JoinGroupResponse {
    /// The HSM successfully and persistently joined the group (or it had
    /// already done so).
    Ok,
    /// This HSM is not a member of this realm (it's either not a member of any
    /// realm or is already a member of a different realm), so it can't join
    /// the new group.
    InvalidRealm,
    /// The given `configuration` does not contain this HSM, is not sorted by
    /// HSM ID, contains duplicate HSM IDs, or exceeds [`CONFIGURATION_LIMIT`]
    /// in length.
    InvalidConfiguration,
    /// The `statement` MAC was invalid.
    InvalidStatement,
    /// This HSM cannot join any more groups, since it is already a member of
    /// [`GROUPS_LIMIT`].
    TooManyGroups,
}

/// Request type for the HSM CaptureNext RPC (see [`CaptureNextResponse`]). The
/// HSM checks the authenticity of the given sequence of log entries and stores
/// information about the last entry.
///
/// This RPC prepares the HSM to persist such information later, during the
/// PersistState RPC. It's part of the replication protocol.
///
/// The HSM checks that the first entry chains back to the last one it had
/// captured, and it validates the authenticity of the entries. It queues up
/// the final entry's index and MAC to be persisted in the next PersistState
/// RPC.
#[derive(Debug, Deserialize, Serialize)]
pub struct CaptureNextRequest {
    /// The ID of the realm containing the group.
    pub realm: RealmId,
    /// The ID of the group (which also identifies the log).
    pub group: GroupId,
    /// A consecutive sequence of log entries to capture.
    ///
    /// The first entry should have an index one greater than the last entry in
    /// the last call to CaptureNext and should chain back to it (with its
    /// `prev_mac` field).
    pub entries: Vec<LogEntry>,
}

/// Response type for the HSM CaptureNext RPC (see [`CaptureNextRequest`]).
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CaptureNextResponse {
    /// The HSM successfully processed the log entries.
    ///
    /// The role of this HSM in the group is returned. The HSM may have used the
    /// data captured to detect that it's no longer leader and transition out of
    /// the leader state.
    Ok(GroupMemberRole),
    /// This HSM is not a member of this realm.
    InvalidRealm,
    /// This HSM is not a member of this group.
    InvalidGroup,
    /// Some provided log entry's `entry_mac` MAC was invalid.
    InvalidMac,
    /// Either the last log entry the HSM had captured did not match the
    /// `prev_mac` field of the first entry given, or the `prev_mac` field of
    /// one of the entries given did not match its predecessor.
    InvalidChain,
    /// Either the last log entry the HSM had captured did not have an index
    /// immediately preceding the first entry given, or the entries given were
    /// not sequential.
    MissingPrev,
    /// The given `entries` was empty, so the HSM did nothing.
    MissingEntries,
}

/// Request type for the HSM BecomeLeader RPC (see [`BecomeLeaderResponse`]).
/// The HSM begins acting as leader for a particular replication group.
///
/// The HSM should have already joined the realm and the group, and the
/// largest-indexed log entry it has captured for this group (as a witness)
/// should be `last_entry`.
///
/// This RPC should be used when the replication group has no leader, so that
/// it can become available for client requests again. The operator should try
/// to avoid having multiple leaders at one time, as only one of those will be
/// able to successfully commit new log entries.
#[derive(Debug, Deserialize, Serialize)]
pub struct BecomeLeaderRequest {
    /// The ID of the realm containing the group.
    pub realm: RealmId,
    /// The ID of the group to lead.
    pub group: GroupId,
    /// The last log entry the HSM has captured.
    ///
    /// This is given to the HSM again because, as witnesses, the HSMs don't
    /// retain the complete log entries. The HSM verifies that it's the same
    /// entry using the entry's MAC.
    pub last_entry: LogEntry,
}

/// Response type for the HSM BecomeLeader RPC (see [`BecomeLeaderRequest`]).
#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum BecomeLeaderResponse {
    /// The HSM successfully became leader of the group (or it was already
    /// leader).
    Ok {
        /// The fixed set of HSM members of the group, including this one, in
        /// sorted order.
        ///
        /// This is provided for convenience so that the caller (the agent) can
        /// run the replication protocol with the other members.
        configuration: Vec<HsmId>,
    },
    /// This HSM is not a member of this realm.
    InvalidRealm,
    /// This HSM is not a member of this group.
    InvalidGroup,
    /// The `last_entry.entry_mac` MAC was invalid.
    InvalidMac,
    /// The log entry in `last_entry` was not the last one this HSM has
    /// captured, so this HSM could not accept it.
    NotCaptured {
        /// The largest index corresponding to the latest log entry this HSM
        /// has captured, if any.
        have: Option<LogIndex>,
    },
    /// This HSM is in the middle of stepping down from a prior leadership
    /// role, and, for simplicity, it refuses to become leader again until it's
    /// done.
    StepdownInProgress,
}

/// Request type for the HSM StepDown RPC (see [`StepDownResponse`]). The HSM
/// transitions out of the leader role for a particular replication group.
///
/// It stops accepting client requests immediately. Typically, it transitions
/// into the stepping down role, where it continues to commit its existing
/// client requests. Or, if there were no uncommitted client requests, it
/// becomes only a witness right away.
///
/// This RPC should be used when an HSM acting as leader is to go offline
/// temporarily, to avoid abruptly failing client requests. If the leader is to
/// go offline permanently, it's better to transfer the partition to another
/// group or groups.
#[derive(Debug, Deserialize, Serialize)]
pub struct StepDownRequest {
    /// The ID of the realm containing the group.
    pub realm: RealmId,
    /// The group that this HSM should no longer lead.
    pub group: GroupId,
}

/// Response type for the HSM StepDown RPC (see [`StepDownRequest`]).
#[derive(Debug, Deserialize, Serialize)]
pub enum StepDownResponse {
    /// The HSM transitioned into the stepping down role.
    InProgress {
        /// The last log index generated (or inherited) as leader. The HSM will
        /// stay in the stepping down role until it is able to commit the log
        /// entry with index 'last'.
        ///
        /// The caller (the agent) should continue to issue commit requests to
        /// the HSM until it reaches at least this index. This will ensure that
        /// all the pending client responses are released.
        last: LogIndex,
    },
    /// The HSM transitioned directly into the witness-only role. It is done
    /// stepping down.
    Complete {
        /// The last log index generated (or inherited) and committed as
        /// leader.
        last: LogIndex,
    },
    /// This HSM is not a member of this realm.
    InvalidRealm,
    /// This HSM is not a member of this group.
    InvalidGroup,
    /// The HSM wasn't acting as leader of the group. It might have only been a
    /// witness or it might have already been stepping down.
    NotLeader(GroupMemberRole),
}

/// Request type for the HSM PersistState RPC (see [`PersistStateResponse`]).
/// The HSM writes its group membership information and its captures to its
/// persistent memory.
///
/// Once written, this information should survive reboots and power outages.
///
/// This RPC is needed to make progress on client requests, but depending on
/// the HSM, it may not be something you can invoke too frequently. Writing to
/// persistent memory can be time-consuming and can also have wear limits (as
/// with flash memory).
///
/// Note that the HSM may also persist its state at other times or in response
/// to other requests.
#[derive(Debug, Deserialize, Serialize)]
pub struct PersistStateRequest {}

/// Response type for the HSM PersistState RPC (see [`PersistStateRequest`]).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PersistStateResponse {
    /// The HSM successfully persisted its current state (or the state hadn't
    /// changed since it was last persisted).
    Ok {
        /// The latest log entry that this HSM has captured for each of its
        /// groups.
        ///
        /// Each group for which this HSM has captured at least one log entry
        /// is represented exactly once in the `Vec`, in no particular order.
        captured: Vec<Captured>,
    },
}

/// An assertion that a particular HSM has captured a particular log entry.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Captured {
    /// The HSM ID.
    pub hsm: HsmId,
    /// The ID of the realm containing the group.
    pub realm: RealmId,
    /// The ID of the group (which also identifies the log).
    pub group: GroupId,
    /// The index of the captured log entry.
    pub index: LogIndex,
    /// The `entry_mac` field of the captured log entry.
    pub mac: EntryMac,
    /// A MAC over all the fields above.
    ///
    /// This is given to the group's leader as proof that a majority of the
    /// group has captured the log entry, so that it can be marked committed.
    pub statement: CapturedStatement,
}

/// Request type for the HSM Commit RPC (see [`CommitResponse`]). The HSM marks
/// recent log entries as committed according to the captures given, and it
/// returns responses for clients for newly committed entries.
#[derive(Debug, Deserialize, Serialize)]
pub struct CommitRequest {
    /// The ID of the realm containing the group.
    pub realm: RealmId,
    /// The ID of the group (which also identifies the log).
    pub group: GroupId,
    /// A set of assertions of what HSMs in this group have captured.
    ///
    /// This should include capture information from a majority of the group's
    /// members.
    pub captures: Vec<Captured>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommitState {
    /// The index of the latest log entry the HSM has marked as committed.
    pub committed: LogIndex,
    /// A set of responses corresponding to newly committed log entries.
    ///
    /// These responses may now be returned to the respective clients whose
    /// requests caused the log entries to be created.
    pub responses: Vec<(EntryMac, NoiseResponse)>,
    /// A set of responses that will never commit. If there are multiple
    /// leaders then it's possible for the persisted log to diverge from a
    /// leaders in memory log. In this event there are clients waiting for a
    /// response that will never commit. These are included here so that the
    /// agent can signal a failure to those client requests.
    pub abandoned: Vec<EntryMac>,
    /// The HSM's latest role in this group.
    ///
    /// This is normally the leader role. However, if the HSM was stepping
    /// down, then this request may have caused the role to complete its
    /// responsibilities and return to the witness-only role (or it may
    /// have more to commit and remain in the stepping down role).
    pub role: GroupMemberRole,
}

/// Response type for the HSM Commit RPC (see [`CommitRequest`]).
#[derive(Debug, Deserialize, Serialize)]
pub enum CommitResponse {
    /// The HSM successfully committed. The commit index may be the same or
    /// larger than the previous commit response.
    Ok(CommitState),
    /// With its current state and the given [`Captured`] assertions, this HSM
    /// could not find an index that a majority of members had captured.
    ///
    /// Either not enough [`Captured`] assertions from the group were provided,
    /// they were invalid (such as having `CapturedStatements` that did not
    /// authenticate correctly), or this leader did not have the log entries
    /// referenced by the assertions.
    NoQuorum,
    /// This HSM is not a member of this realm.
    InvalidRealm,
    /// This HSM is not a member of this group.
    InvalidGroup,
    /// This HSM is not a leader of this group, nor is it in the stepping down
    /// role as a recent leader. It has no business committing log entries, and
    /// it does not have any client responses. GroupMemberRole is returned for
    /// consistency but will always be Witness in this case.
    NotLeader(GroupMemberRole),
}

/// The HSMs transfer ownership of a range of record IDs from one replication
/// group to another using a 5-step protocol.
///
/// 1. source group leader ← [`TransferOutRequest`]
/// 2. [`TransferNonceRequest`] → destination group leader
/// 3. source group leader ← [`TransferStatementRequest`]
/// 4. [`TransferInRequest`] → destination group leader
/// 5. source group leader ← [`CompleteTransferRequest`]
///
/// The transfer of ownership does not involve any heavy-weight data transfer.
/// The records are stored in Merkle tree nodes in a storage system outside the
/// HSMs. The storage system is shared by all groups in the same realm.
///
/// Each group is responsible for up to one contiguous range of record IDs.
/// Therefore, the source group can transfer out either its entire existing
/// range, or the beginning or end of its existing range (with a Merkle tree
/// split operation). If the destination group owns no range, it can tranfer in
/// any range. If it does own a range, it can only transfer in an adjacent
/// range (with a Merkle tree merge operation).
pub const TRANSFER_PROTOCOL_DESCRIPTION: (/* doc only */) = ();

/// Request type for the HSM TransferOut RPC (see [`TransferOutResponse`]). The
/// leader of the source group stops processing requests for the range and
/// marks it as transferring out.
///
/// This is part of a multi-step ownership transfer protocol. See
/// [`TRANSFER_PROTOCOL_DESCRIPTION`] for an overview.
#[derive(Debug, Deserialize, Serialize)]
pub struct TransferOutRequest {
    /// The ID of the realm containing the groups `source` and `destination`.
    pub realm: RealmId,
    /// The ID of the group that previously owned the range.
    pub source: GroupId,
    /// The ID of the group that will soon own the range.
    pub destination: GroupId,
    /// The range of record IDs to transfer out of the `source` group and,
    /// soon, into the `destination` group.
    pub range: OwnedRange,
    /// The last entry that the HSM has created and also the entry that
    /// corresponds to the proof.
    ///
    /// As already captured by a TODO, this makes it hard to execute other
    /// requests while doing a transfer, and it's probably no longer needed.
    pub index: LogIndex,
    /// A Merkle proof used in splitting the existing Merkle tree.
    ///
    /// If the source group's partition is splitting to transfer a portion
    /// over, then this should be a Merkle proof for the "split point". The
    /// split point is the record ID that starts the resulting right-side
    /// range.
    ///
    /// If the source group's entire partition is being transferred, then this
    /// should be `None`.
    pub proof: Option<ReadProof<DataHash>>,
}

/// Response type for the HSM TransferOut RPC (see [`TransferOutRequest`]).
#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum TransferOutResponse {
    /// The HSM successfully stopped processing requests for the range and
    /// marked it as transferring out.
    ///
    /// The caller should write the new nodes to the Merkle tree storage,
    /// conditionally append the entry to the destination group's log, have the
    /// destination group commit the entry, and then delete the old nodes from
    /// the Merkle tree storage.
    Ok {
        /// A new log entry with updated metadata about the transfer and
        /// an updated partition and Merkle tree.
        entry: LogEntry,
        /// If this transfer required a split, this contains changes to apply
        /// to the source group's Merkle tree to produce two separate trees.
        delta: StoreDelta<DataHash>,
    },
    /// This HSM is not a member of this realm.
    InvalidRealm,
    /// Either this HSM is not a member of the source group, or `source` and
    /// `destination` refer to the same group (which is disallowed to avoid
    /// potential bugs).
    InvalidGroup,
    /// This HSM is not a leader of the source group, so it can't participate
    /// in ownership transfers.
    NotLeader,
    /// Either this HSM does not believe that this group manages some record ID
    /// in the range to transfer, or removing this range would leave the
    /// `source` group with a hole in its range, which is not allowed.
    NotOwner,
    /// The given index is not the latest that the leader inherited or created.
    StaleIndex,
    /// The HSM did not have previous knowledge about this proof's root hash.
    ///
    /// The caller should retry with a proof from a more recent snapshot of the
    /// Merkle tree.
    StaleProof,
    /// Either the proof was not internally consistent, or the proof was not
    /// conclusive with respect to the split point.
    InvalidProof,
    /// The proof given did not correspond to the split point that the HSM
    /// computed.
    MissingProof,
}

/// Request type for the HSM TransferNonce RPC (see [`TransferNonceResponse`]).
/// The leader of the destination group generates and returns a random nonce.
///
/// The leader will make a best effort to remember this nonce, as it will need
/// the nonce for a successful [`TransferInRequest`].
///
/// It is safe for the caller to lose this nonce, as they can safely request a
/// new one. Requesting a new nonce will invalidate old nonces.
///
/// This is part of a multi-step ownership transfer protocol. See
/// [`TRANSFER_PROTOCOL_DESCRIPTION`] for an overview.
#[derive(Debug, Deserialize, Serialize)]
pub struct TransferNonceRequest {
    /// The ID of the realm containing the `destination` group.
    pub realm: RealmId,
    /// The ID of the group that this HSM leads, which will receive an incoming
    /// transfer soon.
    pub destination: GroupId,
}

/// Response type for the HSM TransferNonce RPC (see [`TransferNonceRequest`]).
#[derive(Debug, Deserialize, Serialize)]
pub enum TransferNonceResponse {
    /// The HSM successfully generated a new transfer nonce.
    Ok(TransferNonce),
    /// This HSM is not a member of this realm.
    InvalidRealm,
    /// This HSM is not a member of the destination group.
    InvalidGroup,
    /// This HSM is not a leader of the destination group, so it can't
    /// participate in ownership transfers.
    NotLeader,
}

/// Request type for the HSM TransferStatement RPC (see
/// [`TransferStatementResponse`]). The leader of the source group returns a
/// signed description of the transfer.
///
/// This is part of a multi-step ownership transfer protocol. See
/// [`TRANSFER_PROTOCOL_DESCRIPTION`] for an overview.
#[derive(Debug, Deserialize, Serialize)]
pub struct TransferStatementRequest {
    /// The ID of the realm containing the groups `source` and `destination`.
    pub realm: RealmId,
    /// The ID of the group that previously owned the range.
    pub source: GroupId,
    /// The ID of the group that will soon own the range.
    pub destination: GroupId,
    /// The latest transfer nonce generated by the leader of the destination
    /// group.
    pub nonce: TransferNonce,
}

/// Response type for the HSM TransferStatement RPC (see
/// [`TransferStatementRequest`]).
#[derive(Debug, Deserialize, Serialize)]
pub enum TransferStatementResponse {
    /// This HSM has successfully generated and returned a transfer statement.
    ///
    /// This should be sent to the destination group in a
    /// [`TransferInRequest`].
    Ok(TransferStatement),
    /// This HSM is not a member of this realm.
    InvalidRealm,
    /// Either this HSM is not a member of the source group, or `source` and
    /// `destination` refer to the same group (which is disallowed to avoid
    /// potential bugs).
    InvalidGroup,
    /// This HSM is not a leader of the source group, so it can't participate
    /// in ownership transfers.
    NotLeader,
    /// This HSM does not believe it's in the middle of a transfer.
    ///
    /// Either the TransferOut RPC did not complete or it did not complete for
    /// this destination.
    NotTransferring,
    /// The log entry that this group generated in the [`TransferOutRequest`]
    /// has not yet been marked committed. The transfer cannot continue yet, as
    /// that would risk allowing two groups to own the same partition (which
    /// would be a loss in consitency and a fork attack).
    Busy,
}

/// Used in [`TransferInRequest`] for transfers that involve merging Merkle
/// trees.
#[derive(Debug, Deserialize, Serialize)]
pub struct TransferInProofs {
    /// A proof about the merging edge of the destination group's existing
    /// Merkle tree.
    ///
    /// If the incoming tree is to the left of the existing tree, this proof
    /// should be for the left-most path in the existing tree. If the incoming
    /// tree is to the right of the existing tree, this proof should be for the
    /// right-most path in the existing tree.
    pub owned: ReadProof<DataHash>,
    /// A proof about the merging edge of the incoming Merkle tree.
    ///
    /// If the incoming tree is to the left of the existing tree, this proof
    /// should be for the right-most path in the incoming tree. If the incoming
    /// tree is to the right of the existing tree, this proof should be for the
    /// left-most path in the incoming tree.
    pub transferring: ReadProof<DataHash>,
}

/// Request type for the HSM TransferIn RPC (see [`TransferInResponse`]). The
/// leader of the destination group takes ownership of the range and begins
/// accepting requests for it.
///
/// This is part of a multi-step ownership transfer protocol. See
/// [`TRANSFER_PROTOCOL_DESCRIPTION`] for an overview.
#[derive(Debug, Deserialize, Serialize)]
pub struct TransferInRequest {
    /// The ID of the realm containing the `destination` group.
    pub realm: RealmId,
    /// The ID of the group that will now own the range.
    pub destination: GroupId,
    /// The range of record IDs and the root hash of the Merkle tree that the
    /// destination group will now own.
    pub transferring: Partition,
    /// Merkle proofs needed for the destination group to complete the tree
    /// merge operation.
    ///
    /// If the destination group will need to merge the incoming range with its
    /// existing partition, this is required. If the destination group does not
    /// already own a partition, pass `None`.
    pub proofs: Option<TransferInProofs>,
    /// A nonce that the destination group had previously generated.
    ///
    /// The destination group should already have this nonce, but passing this
    /// in helps distinguish the error cases of a stale nonce vs an invalid
    /// transfer statement.
    pub nonce: TransferNonce,
    /// A MAC from the source group about the ownership transfer.
    pub statement: TransferStatement,
}

/// Response type for the HSM TransferIn RPC (see [`TransferInRequest`]).
#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum TransferInResponse {
    /// The HSM successfully accepted ownership of the range.
    ///
    /// The caller should write the new nodes to the Merkle tree storage,
    /// conditionally append the entry to the destination group's log, have the
    /// destination group commit the entry, and then delete the old nodes from
    /// the Merkle tree storage.
    Ok {
        /// A new log entry with an updated partition and Merkle tree.
        entry: LogEntry,
        /// If this transfer required a merge, this contains changes to apply
        /// to the existing and incoming Merkle trees to produce a single
        /// merged tree.
        delta: StoreDelta<DataHash>,
    },
    /// This HSM is not a member of this realm.
    InvalidRealm,
    /// This HSM is not a member of the destination group.
    InvalidGroup,
    /// This HSM is not a leader of the destination group, so it can't
    /// participate in ownership transfers.
    NotLeader,
    /// The transfer requires merging Merkle trees because the destination
    /// group already owns a range, but that range and the incoming range are
    /// not adjacent.
    UnacceptableRange,
    /// The given nonce is not the latest one that this leader had generated.
    ///
    /// This can happen if the HSM restarted or as a result of concurrent
    /// transfer attempts. The caller should request a fresh transfer nonce,
    /// get a new transfer statement, and try again.
    InvalidNonce,
    /// The `statement` MAC was invalid.
    InvalidStatement,
    /// The HSM did not have previous knowledge about the root hash used in the
    /// existing range's proof.
    ///
    /// The caller should retry with a proof from a more recent snapshot of the
    /// destination group's existing Merkle tree.
    StaleProof,
    /// Either the provided `transferring` proof's partition did not match the
    /// `transferring` partition in the request, or at least one of the proofs
    /// was not internally consistent, or at least one of the proofs was not
    /// conclusive with respect to the necessary path on the edge of the tree.
    InvalidProof,
    /// The transfer requires merging Merkle trees because the destination
    /// group already owns a range, but the `proofs` field in the request was
    /// `None`.
    MissingProofs,
}

/// Request type for the HSM CompleteTransfer RPC (see
/// [`CompleteTransferResponse`]). The leader of the source group discards its
/// metadata about the transfer.
///
/// This should only be called once the [`TransferInRequest`] has completed
/// successfully and its resulting log entry has committed in the destination
/// group. Otherwise, the partition may be permanently lost.
///
/// This is part of a multi-step ownership transfer protocol. See
/// [`TRANSFER_PROTOCOL_DESCRIPTION`] for an overview.
#[derive(Debug, Deserialize, Serialize)]
pub struct CompleteTransferRequest {
    /// The ID of the realm containing the groups `source` and `destination`.
    pub realm: RealmId,
    /// The ID of the group that previously owned the range.
    pub source: GroupId,
    /// The ID of the group that now owns the range.
    pub destination: GroupId,
    /// The range of record IDs that were transferred out of the `source` group
    /// and into the `destination` group.
    pub range: OwnedRange,
}

/// Response type for the HSM CompleteTransfer RPC (see
/// [`CompleteTransferRequest`]).
#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum CompleteTransferResponse {
    /// The HSM successfully discarded its metadata about the transfer, as
    /// recorded in the returned log entry.
    ///
    /// The caller should conditionally append the returned entry to the source
    /// group's log and have the source group commit the entry. If the log
    /// entry is never committed, the [`CompleteTransferRequest`] will need to
    /// be repeated.
    Ok(LogEntry),
    /// This HSM could not find an active transfer to this destination group
    /// for this range.
    NotTransferring,
    /// This HSM is not a member of this realm.
    InvalidRealm,
    /// Either this HSM is not a member of the source group, or `source` and
    /// `destination` refer to the same group (which is disallowed to avoid
    /// potential bugs).
    InvalidGroup,
    /// This HSM is not a leader of the source group, so it can't participate
    /// in ownership transfers.
    NotLeader,
}

/// Request type for the HSM Handshake RPC (see [`HandshakeResponse`]). The HSM
/// initializes a new Noise session for encrypted communication with a client.
///
/// This RPC is as an optimization that's used when clients need to open a
/// Noise session with a replication group leader, but they don't need the
/// leader accessing their user record yet. This saves the HSM from validating
/// a Merkle proof and generating and committing a log entry.
///
/// For example, this can be used when a client has a sensitive request to
/// send, but it has no active Noise session (perhaps the session expired or
/// leadership changed). The client can send a Handshake RPC with an empty
/// payload, followed by an App RPC with an encrypted request.
#[derive(Debug, Deserialize, Serialize)]
pub struct HandshakeRequest {
    /// The ID of the realm containing the group.
    pub realm: RealmId,
    /// The ID of the group, which should be responsible for the partition
    /// containing the record ID.
    pub group: GroupId,
    /// The record ID that identifies the user within this realm.
    pub record_id: RecordId,
    /// Used to identify this Noise communication channel in future requests.
    ///
    /// The client should choose this randomly so that it is unlikely to
    /// collide with any other concurrent sessions by the same user.
    pub session_id: SessionId,
    /// A handshake request from a client, which must have an empty payload.
    pub handshake: noise::HandshakeRequest,
}

/// Response type for the HSM Handshake RPC (see [`HandshakeRequest`]).
#[derive(Debug, Deserialize, Serialize)]
pub enum HandshakeResponse {
    /// This HSM successfully started a new Noise session.
    Ok {
        /// The handshake response for the client, which includes an empty
        /// payload.
        noise: noise::HandshakeResponse,
        /// A hint to the client of how long it should reuse an inactive
        /// session. Once the session becomes inactive for this long, the
        /// client should discard the session.
        ///
        /// The agent or load balancer could override this default with a more
        /// sophisticated estimate. The HSM keeps sessions in an LRU cache but
        /// currently provides a fixed constant duration here.
        session_lifetime: Duration,
    },
    /// This HSM is not a member of this realm.
    InvalidRealm,
    /// This HSM is not a member of this group.
    InvalidGroup,
    /// This HSM does not believe that this group manages the partition to
    /// which this record ID is assigned, so this client has no business
    /// connecting to it.
    NotOwner,
    /// This HSM is not a leader of this group, so clients have no business
    /// connecting to it.
    NotLeader,
    /// Either the handshake payload was not empty, the Noise message could not
    /// be decrypted/processed successfully, or (unlikely) the response message
    /// could not be encrypted successfully.
    SessionError,
}

/// Request type for the HSM App RPC (see [`AppResponse`]). The HSM processes a
/// client request against the user's record.
///
/// The HSM is given a Merkle proof with the user's record in this request. It
/// produces changes to the Merkle tree and a log entry to be persisted to an
/// external storage system.
///
/// After it's persisted, the log entry should be "captured" by other members
/// of the replication group. It is not until this HSM processes the Commit RPC
/// for this entry that the result for the client will be returned. This
/// prevents an adversary from learning whether its PIN guess was correct (for
/// example) without committing the changes first.
#[derive(Debug, Deserialize, Serialize)]
pub struct AppRequest {
    /// The ID of the realm containing the group.
    pub realm: RealmId,
    /// The ID of the group, which should be responsible for the partition
    /// containing the record ID.
    pub group: GroupId,
    /// The record ID that identifies the user within this realm.
    pub record_id: RecordId,
    /// Identifies this Noise session.
    ///
    /// For a new session, `encrypted` should contain a handshake request, and
    /// this should be a randomly generated identifier. The client should
    /// choose this randomly so that it is unlikely to collide with any other
    /// concurrent sessions by the same user.
    ///
    /// For an existing session, `encrypted` should contain a transport
    /// request, and this should be the identifier used during the handshake
    /// request.
    pub session_id: SessionId,
    /// A Noise handshake or transport request from a client.
    ///
    /// If the request type requires forward secrecy, it must not be sent in a
    /// handshake request and may only be sent in a transport request. Which
    /// request types require forward secrecy are defined by
    /// [`juicebox_realm_api::requests::SecretsRequest::needs_forward_secrecy`].
    ///
    /// The size of the payload must not exceed
    /// [`juicebox_realm_api::requests::BODY_SIZE_LIMIT`]; otherwise, the HSM
    /// will panic.
    pub encrypted: NoiseRequest,
    /// A recent Merkle proof leading to the record, if any.
    ///
    /// This includes identifiers for the tree, the root hash of the tree, the
    /// path from the root towards where the record should be, and the record,
    /// if it exists.
    ///
    /// The proof should use a recent snapshot of the tree, but to allow for
    /// concurrent operations, it does not need to use the absolute latest
    /// version of the tree.
    pub proof: ReadProof<DataHash>,
    /// The log index that `proof` was generated from.
    pub index: LogIndex,
}

/// Response type for the HSM App RPC (see [`AppRequest`]).
#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum AppResponse {
    /// The HSM successfully processed the request and determined its effects.
    ///
    /// The caller (the agent) should:
    /// 1. Persist the new Merkle tree nodes,
    /// 2. Append the new log entry to an external storage, conditioned on this
    ///    entry following its predecessor in the log.
    /// 3. Have the new entry "captured" by the other members of the
    ///    replication group.
    /// 4. Request that this HSM commit the entry using the Commit RPC.
    /// 5. Return the encrypted result from the [`CommitResponse`] to the
    ///    client.
    /// 6. Delete old Merkle tree nodes.
    Ok {
        /// A new log entry produced as a result of the request.
        ///
        /// The log entry contains a reference to the Merkle tree's root
        /// hash, which may have changed.
        entry: LogEntry,
        /// Zero or more changes to the Merkle tree as a result of this
        /// request, including the encrypted user record.
        delta: StoreDelta<DataHash>,
        /// The type of [`AppRequest`] that was processed. This is exposed
        /// to the Agent for accounting purposes.
        request_type: AppRequestType,
    },
    /// This HSM is not a member of this realm.
    InvalidRealm,
    /// This HSM is not a member of this group.
    InvalidGroup,
    /// The HSM did not have previous knowledge about this proof's root hash.
    ///
    /// The caller should retry with a proof from a more recent snapshot of the
    /// Merkle tree.
    StaleProof,
    /// Either the request's record ID did not match the one in the Merkle
    /// proof, the proof was not internally consistent, or the proof was not
    /// conclusive with respect to this record ID.
    InvalidProof,
    /// This HSM does not believe that this group manages the partition to
    /// which this record ID is assigned, so this client has no business
    /// connecting to it.
    NotOwner,
    /// This HSM is not a leader of this group, so clients have no business
    /// connecting to it.
    NotLeader(GroupMemberRole),
    /// The Merkle leaf node could not be decrypted into a user record.
    InvalidRecordData,
    /// The HSM could not locate an active session for the given record ID and
    /// session ID.
    ///
    /// This can happen in various cases:
    /// - The HSM already expired this session from its session cache,
    /// - The HSM restarted (thereby expiring all of its open sessions),
    /// - Leadership changed, so the client opened a session with a different
    ///   HSM and has now been routed to this HSM, or
    /// - The client is malicious or buggy.
    MissingSession,
    /// Either the Noise message could not be decrypted/processed successfully,
    /// or the request type required forward secrecy but was sent as the
    /// payload of a handshake message.
    SessionError,
    /// The Noise payload's plaintext could not be deserialized.
    DecodingError,
}

/// The different types of AppRequests that the client may make.
#[derive(Debug, Deserialize, Serialize)]
pub enum AppRequestType {
    Register1,
    Register2,
    Recover1,
    Recover2,
    Recover3,
    Delete,
}

#[cfg(test)]
mod tests {
    use subtle::ConstantTimeEq;

    use super::{DataHash, RecordId};
    use crate::merkle::HashOutput;
    use crate::{CtBytes, LogIndex, OwnedRange};
    use bitvec::Bits;
    use juicebox_marshalling as marshalling;

    #[test]
    fn log_index() {
        assert!(LogIndex::FIRST.prev().is_none());
        assert!(LogIndex(0).prev().is_none());
        assert!(LogIndex(1).prev().is_none());
        assert_eq!(LogIndex::FIRST, LogIndex::FIRST.next().prev().unwrap());
        assert_eq!(LogIndex(1234), LogIndex(1233).next());
        assert_eq!(LogIndex(1232), LogIndex(1233).prev().unwrap());
    }

    #[test]
    #[should_panic]
    fn log_index_overflow() {
        LogIndex(u64::MAX).next();
    }

    #[test]
    fn record_id_prev() {
        assert!(RecordId::min_id().prev().is_none());
        let mut id = RecordId([255; RecordId::NUM_BYTES]);
        *id.0.last_mut().unwrap() = 254;
        assert_eq!(id, RecordId::max_id().prev().unwrap());
    }

    #[test]
    fn record_id_next() {
        assert!(RecordId::max_id().next().is_none());
        let mut id = RecordId([42; RecordId::NUM_BYTES]);
        *id.0.last_mut().unwrap() = 255;
        let mut exp = RecordId([42; RecordId::NUM_BYTES]);
        exp.0[RecordId::NUM_BYTES - 1] = 0;
        exp.0[RecordId::NUM_BYTES - 2] = 43;
        assert_eq!(exp, id.next().unwrap());
    }

    #[test]
    fn record_id_bitvec() {
        let rec = RecordId([42u8; RecordId::NUM_BYTES]);
        let v = rec.to_bitvec();
        assert_eq!(256, v.len());
        assert_eq!(&rec.0, v.as_bytes());
        let rec2 = RecordId::from_bitvec(&v);
        assert_eq!(rec, rec2);
    }

    #[test]
    fn data_hash_marshalling() {
        let h = DataHash::from_slice(&[200u8; 32]).unwrap();
        let m = marshalling::to_vec(&h).unwrap();
        assert_eq!(34, m.len()); // 32 bytes + 2 bytes to say its 32 bytes.
        let h2 = marshalling::from_slice(&m).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn data_hash_from_slice() {
        let s = [42u8; 40];
        let exp = DataHash([42u8; 32]);
        assert_eq!(Some(exp), DataHash::from_slice(&s[..32]));
        assert!(DataHash::from_slice(&s).is_none());
        assert!(DataHash::from_slice(&s[..31]).is_none());
        assert!(DataHash::from_slice(&s[..33]).is_none());
        assert!(DataHash::from_slice(&s[..0]).is_none());
    }

    #[test]
    fn ctbytes_zero() {
        let z = CtBytes::<8>::zero();
        assert_eq!([0u8; 8], z.0);
        assert_eq!(&[0u8; 8], z.as_bytes());
        assert!(bool::from(z.ct_eq(&z)));
        let notz = CtBytes([42; 8]);
        assert!(!bool::from(z.ct_eq(&notz)));
    }

    #[test]
    fn owned_range_contains() {
        let mut start = RecordId::min_id();
        start.0[0] = 10;
        let mut end = RecordId::min_id();
        end.0[0] = 20;
        let r = OwnedRange {
            start: start.clone(),
            end: end.clone(),
        };
        assert!(r.contains(&start));
        assert!(r.contains(&end));
        assert!(r.contains(&start.next().unwrap()));
        assert!(r.contains(&end.prev().unwrap()));
        assert!(r.contains(&RecordId([10; RecordId::NUM_BYTES])));
        assert!(r.contains(&RecordId([19; RecordId::NUM_BYTES])));
        assert!(!r.contains(&RecordId([9; RecordId::NUM_BYTES])));
        assert!(!r.contains(&RecordId([20; RecordId::NUM_BYTES])));
        assert!(!r.contains(&start.prev().unwrap()));
        assert!(!r.contains(&end.next().unwrap()));
        assert!(!r.contains(&RecordId::min_id()));
        assert!(!r.contains(&RecordId::max_id()));
    }

    #[test]
    fn owned_range_join_split() {
        let a = OwnedRange {
            start: RecordId([33; RecordId::NUM_BYTES]),
            end: RecordId([55; RecordId::NUM_BYTES]),
        };
        let b = OwnedRange {
            start: a.end.next().unwrap(),
            end: RecordId([99; RecordId::NUM_BYTES]),
        };
        let joined = OwnedRange {
            start: a.start.clone(),
            end: b.end.clone(),
        };
        assert_eq!(Some(joined.clone()), a.join(&b));
        assert_eq!(Some(joined.clone()), b.join(&a));

        let c = OwnedRange {
            start: RecordId::min_id(),
            end: RecordId([30; RecordId::NUM_BYTES]),
        };
        assert!(a.join(&c).is_none());
        assert!(c.join(&a).is_none());
        assert!(a.join(&OwnedRange::full()).is_none());
        assert!(OwnedRange::full().join(&a).is_none());

        assert_eq!(Some(b.start.clone()), joined.split_at(&b));
        assert_eq!(Some(b.start.clone()), joined.split_at(&a));
        assert!(joined.split_at(&c).is_none());
        assert!(joined
            .split_at(&OwnedRange {
                start: b.start,
                end: b.end.prev().unwrap()
            })
            .is_none());
    }
}
