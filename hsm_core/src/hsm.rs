extern crate alloc;

use alloc::borrow::Cow;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use blake2::Blake2s256;
use chacha20poly1305::aead::Aead;
use core::fmt::Debug;
use core::time::Duration;
use digest::Digest;
use hsm_api::merkle::StoreDelta;
use serde::ser::SerializeTuple;
use serde::{Deserialize, Serialize};
use tracing::{info, trace, warn};
use x25519_dalek as x25519;

mod app;
pub mod commit;
mod configuration;
pub mod mac;
#[cfg(test)]
mod tests;
mod transfer;

use self::mac::{
    CapturedStatementMessage, CtMac, EntryMacMessage, GroupConfigurationStatementMessage,
    HsmRealmStatementMessage, MacKey,
};
use super::hal::{Clock, CryptoRng, IOError, NVRam, Platform};
use super::merkle::{
    proof::{ProofError, VerifiedProof},
    NodeHasher, Tree,
};
use super::mutation::{MutationTracker, OnMutationFinished};
use crate::hash::{HashExt, HashMap};
use app::RecordChange;
use configuration::GroupConfiguration;
use hsm_api::merkle::ReadProof;
use hsm_api::rpc::{
    HsmRequest, HsmRequestContainer, HsmResponseContainer, HsmRpc, MetricsAction, Nanos,
};
use hsm_api::{
    AppRequest, AppRequestType, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse, Captured,
    DataHash, EntryMac, GroupId, GroupMemberRole, GroupStatus, HandshakeRequest, HandshakeResponse,
    HsmId, HsmRealmStatement, JoinGroupRequest, JoinGroupResponse, JoinRealmRequest,
    JoinRealmResponse, LeaderStatus, LogEntry, LogIndex, NewGroupRequest, NewGroupResponse,
    NewRealmRequest, NewRealmResponse, OwnedRange, Partition, PersistStateRequest,
    PersistStateResponse, PublicKey, RealmStatus, RecordId, StatusRequest, StatusResponse,
    StepDownRequest, StepDownResponse, TransferNonce, TransferringOut, CONFIGURATION_LIMIT,
    GROUPS_LIMIT,
};
use juicebox_marshalling::{self as marshalling, bytes, DeserializationError};
use juicebox_noise::server as noise;
use juicebox_realm_api::{
    requests::{NoiseRequest, NoiseResponse, SecretsRequest, SecretsResponse, BODY_SIZE_LIMIT},
    types::{RealmId, SessionId},
};

// TODO: This is susceptible to DoS attacks. One user could create many
// sessions to evict all other users' Noise connections, or one attacker could
// collect many (currently 511) user accounts to evict all other connections.
type SessionCache = lru_cache::Cache<
    (RecordId, SessionId),
    noise::Transport,
    lru_cache::LogicalClock,
    crate::hash::RandomState,
>;

/// Returned in Noise handshake requests as a hint to the client of how long it
/// should reuse an inactive session.
///
/// The agent or load balancer could override this default with a more
/// sophisticated estimate, so it's OK for this to be a constant here.
const SESSION_LIFETIME: Duration = Duration::from_secs(5);

fn create_random_group_id(rng: &mut impl CryptoRng) -> GroupId {
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    GroupId(id)
}

fn create_random_hsm_id(rng: &mut impl CryptoRng) -> HsmId {
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    HsmId(id)
}

fn create_random_realm_id(rng: &mut impl CryptoRng) -> RealmId {
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    RealmId(id)
}

struct LogEntryBuilder {
    hsm: HsmId,
    realm: RealmId,
    group: GroupId,
    index: LogIndex,
    partition: Option<Partition>,
    transferring_out: Option<TransferringOut>,
    prev_mac: EntryMac,
}

impl LogEntryBuilder {
    fn build(self, key: &MacKey) -> LogEntry {
        let entry_mac = key.log_entry_mac(&EntryMacMessage {
            hsm: self.hsm,
            realm: self.realm,
            group: self.group,
            index: self.index,
            partition: &self.partition,
            transferring_out: &self.transferring_out,
            prev_mac: &self.prev_mac,
        });

        LogEntry {
            hsm: self.hsm,
            index: self.index,
            partition: self.partition,
            transferring_out: self.transferring_out,
            prev_mac: self.prev_mac,
            entry_mac,
        }
    }
}

#[derive(Default)]
pub struct MerkleHasher(Blake2s256);

impl NodeHasher for MerkleHasher {
    type Output = DataHash;

    fn update(&mut self, d: &[u8]) {
        self.0.update(d)
    }

    fn finalize(self) -> DataHash {
        DataHash(self.0.finalize().into())
    }
}

/// A private key used to encrypt/decrypt record values.
#[derive(Clone, Serialize)]
pub struct RecordEncryptionKey(#[serde(with = "bytes")] [u8; 32]);

impl RecordEncryptionKey {
    pub fn from(v: [u8; 32]) -> Self {
        Self(v)
    }
}

pub struct Hsm<P: Platform> {
    platform: P,
    options: HsmOptions,
    persistent: MutationTracker<PersistentState, NVRamWriter<P>>,
    volatile: VolatileState,
    realm_keys: RealmKeys,
}

#[derive(Clone, Copy)]
pub enum MetricsReporting {
    // If disabled, then per request metrics won't be reported back to the agent
    // even if the request asks for them.
    Disabled,
    Enabled,
}

#[derive(Clone)]
pub struct HsmOptions {
    pub name: String,
    pub tree_overlay_size: u16,
    pub max_sessions: u16,
    // Metrics should be set to Disabled for production deployments.
    pub metrics: MetricsReporting,
}

#[derive(Clone)]
pub struct RealmKeys {
    pub communication: (x25519::StaticSecret, x25519::PublicKey),
    pub record: RecordEncryptionKey,
    pub mac: MacKey,
}

impl Serialize for RealmKeys {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct SerializeAsByteArray(#[serde(with = "bytes")] [u8; 32]);

        let mut ts = serializer.serialize_tuple(4)?;
        ts.serialize_element(&SerializeAsByteArray(*self.communication.0.as_bytes()))?;
        ts.serialize_element(&SerializeAsByteArray(*self.communication.1.as_bytes()))?;
        ts.serialize_element(&self.record)?;
        ts.serialize_element(&self.mac)?;
        ts.end()
    }
}

#[derive(Deserialize, Serialize)]
struct PersistentState {
    id: HsmId,
    realm: Option<PersistentRealmState>,
}

#[derive(Deserialize, Serialize)]
struct PersistentRealmState {
    id: RealmId,
    statement: HsmRealmStatement,
    groups: HashMap<GroupId, PersistentGroupState>,
}

#[derive(Clone, Deserialize, Serialize)]
struct PersistentGroupState {
    configuration: GroupConfiguration,
    captured: Option<(LogIndex, EntryMac)>,
}

struct VolatileState {
    leader: HashMap<GroupId, LeaderVolatileGroupState>,
    captured: HashMap<GroupId, (LogIndex, EntryMac)>,
    // A Group can be in leader, stepping_down or neither. Its never in both leader & stepping_down.
    stepping_down: HashMap<GroupId, SteppingDownVolatileGroupState>,
}

struct LeaderVolatileGroupState {
    log: LeaderLog, // never empty
    committed: Option<LogIndex>,
    incoming: Option<TransferNonce>,
    /// This is `Some` if and only if the last entry in `log` owns a partition.
    tree: Option<Tree<MerkleHasher>>,
    sessions: SessionCache,
}

impl LeaderVolatileGroupState {
    fn new(last_entry: LogEntry, options: &HsmOptions) -> Self {
        let tree = last_entry
            .partition
            .as_ref()
            .map(|p| Tree::with_existing_root(p.root_hash, options.tree_overlay_size));
        Self {
            log: LeaderLog::new(last_entry),
            committed: None,
            incoming: None,
            tree,
            sessions: SessionCache::new(usize::from(options.max_sessions)),
        }
    }
}

struct SteppingDownVolatileGroupState {
    // This contains uncommitted log entries generated while leader and log
    // entries from the new leader that are needed to complete a commit. Never
    // empty.
    log: LeaderLog,
    committed: Option<LogIndex>,
    // EntryMacs that were returned from app_request but will never commit
    // because the in memory leader log and the persisted log have diverged.
    abandoned: Vec<EntryMac>,
    // The last log index owned by this leader. When this (or some index after
    // it) is committed the stepdown is complete.
    stepdown_at: LogIndex,
}

struct LeaderLogEntry {
    entry: LogEntry,
    /// A possible response to the client. This must not be externalized until
    /// after the entry has been committed.
    response: Option<NoiseResponse>,
}

// A contiguous series of Log entries.
//
// invariant: contains at least one log entry at all times.
struct LeaderLog(VecDeque<LeaderLogEntry>);

impl LeaderLog {
    fn new(entry: LogEntry) -> Self {
        Self(VecDeque::from([LeaderLogEntry {
            entry,
            response: None,
        }]))
    }

    fn first(&self) -> &LeaderLogEntry {
        self.0.front().expect("LeaderLog should never be empty")
    }

    fn last(&self) -> &LeaderLogEntry {
        self.0.back().expect("LeaderLog should never be empty")
    }

    fn first_index(&self) -> LogIndex {
        self.first().entry.index
    }

    fn last_index(&self) -> LogIndex {
        self.last().entry.index
    }

    fn get_index(&self, index: LogIndex) -> Option<&LeaderLogEntry> {
        let first = self.first_index();
        let last = self.last_index();
        if index < first || index > last {
            return None;
        }
        let offset = index.0 - first.0;
        // Should run out of memory before hitting this limit for usize==u32
        let offset = usize::try_from(offset).expect("LeaderLog too large");
        let entry = self
            .0
            .get(offset)
            .expect("we already validated the offset is in range");
        assert_eq!(entry.entry.index, index);
        Some(entry)
    }

    // Adds a new entry to the end of the log. Will panic if the LogIndex of the
    // new entry is not the next in the sequence. Will panic if the prev_mac of
    // the new entry does not match the entry_mac of the last entry.
    fn append(&mut self, entry: LogEntry, response: Option<NoiseResponse>) {
        let last = self.last();
        assert_eq!(
            entry.index,
            last.entry.index.next(),
            "LogIndex not sequential"
        );
        assert_eq!(
            entry.prev_mac, last.entry.entry_mac,
            "EntryMacs not chained"
        );
        self.0.push_back(LeaderLogEntry { entry, response });
    }

    fn pop_last(&mut self) -> LeaderLogEntry {
        assert!(
            self.0.len() > 1,
            "there should always be at least one entry in the log"
        );
        self.0.pop_back().unwrap()
    }

    fn pop_first(&mut self) -> LeaderLogEntry {
        assert!(
            self.0.len() > 1,
            "there should always be at least one entry in the log"
        );
        self.0.pop_front().unwrap()
    }

    // Takes the response from the first entry in the log replacing it with None.
    // Returns the response and its related EntryMac if there was one, None otherwise.
    fn take_first_response(&mut self) -> Option<(EntryMac, NoiseResponse)> {
        let e = self.0.front_mut().unwrap();
        e.response.take().map(|r| (e.entry.entry_mac.clone(), r))
    }
}

#[derive(Debug)]
pub enum HsmError {
    Deserialization(marshalling::DeserializationError),
    Serialization(marshalling::SerializationError),
}

#[derive(Debug)]
pub enum PersistenceError {
    IOError(IOError),
    Deserialization(DeserializationError),
    InvalidChecksum,
    InvalidRealmStatement,
}

impl From<IOError> for PersistenceError {
    fn from(value: IOError) -> Self {
        PersistenceError::IOError(value)
    }
}

struct Metrics<'a, C: Clock> {
    values: Vec<(Cow<'a, str>, Nanos)>,
    action: MetricsAction,
    clock: C,
    // tracking for the very outer request, gets recorded as a metric during finish()
    start: Option<C::Instant>,
    req_name: &'a str,
}

impl<'a, C: Clock> Metrics<'a, C> {
    fn new(req_name: &'a str, action: MetricsAction, clock: C) -> Self {
        let start = match &action {
            MetricsAction::Skip => None,
            MetricsAction::Record => clock.now(),
        };
        Self {
            values: Vec::new(),
            action,
            clock,
            start,
            req_name,
        }
    }

    fn finish(mut self) -> Vec<(Cow<'a, str>, Nanos)> {
        let start = self.start.take();
        self.record(self.req_name, start);
        self.values
    }

    /// Call now when you want to capture the start time of a metric you're
    /// going to capture. Later call record to capture when its complete.
    ///
    /// #Example
    ///
    /// let start = metrics.now();
    /// do_expensive_thing();
    /// metrics.record("expensive_op", start);
    ///
    fn now(&self) -> Option<C::Instant> {
        match &self.action {
            MetricsAction::Skip => None,
            MetricsAction::Record => self.clock.now(),
        }
    }

    /// Call record at the end of the thing you're measuring with the value from
    /// the earlier call to now. This will calculate and record the metric. This
    /// is a no-op if we're not capturing metrics for the current request.
    fn record(&mut self, name: &'a str, start: Option<C::Instant>) {
        if let Some(start_ts) = start {
            if let Some(dur) = self.clock.elapsed(start_ts) {
                self.values.push((Cow::Borrowed(name), dur));
            }
        }
    }
}

struct NVRamWriter<N: NVRam> {
    nvram: N,
    hash_of_last_write: Option<[u8; 32]>,
}

impl<N: NVRam> NVRamWriter<N> {
    fn new(nvram: N) -> Self {
        Self {
            nvram,
            hash_of_last_write: None,
        }
    }
}

impl<N: NVRam> OnMutationFinished<PersistentState> for NVRamWriter<N> {
    fn finished(&mut self, state: &PersistentState) {
        let mut data = marshalling::to_vec(&state).expect("failed to serialize state");
        let d: [u8; 32] = Blake2s256::digest(&data).into();
        if Some(d) == self.hash_of_last_write {
            // Data hasn't changed since last write, no need to write it again.
            return;
        }
        data.extend(d);
        self.nvram.write(data).expect("Write to NVRam failed");
        self.hash_of_last_write = Some(d);
    }
}

impl<P: Platform> Hsm<P> {
    pub fn new(
        options: HsmOptions,
        mut platform: P,
        realm_keys: RealmKeys,
    ) -> Result<Self, PersistenceError> {
        let mut writer = NVRamWriter::new(platform.clone());
        let persistent = match Self::read_persisted_state(&platform)? {
            Some(state) => state,
            None => {
                let hsm_id = create_random_hsm_id(&mut platform);
                let state = PersistentState {
                    id: hsm_id,
                    realm: None,
                };
                writer.finished(&state);
                state
            }
        };

        if let Some(realm) = &persistent.realm {
            realm_keys
                .mac
                .hsm_realm_mac(&HsmRealmStatementMessage {
                    realm: realm.id,
                    hsm: persistent.id,
                    keys: &realm_keys,
                })
                .verify(&realm.statement)
                .map_err(|_| PersistenceError::InvalidRealmStatement)?;
        }

        let captured: HashMap<GroupId, (LogIndex, EntryMac)> = persistent
            .realm
            .iter()
            .flat_map(|r| r.groups.iter())
            .filter_map(|(group_id, group_state)| {
                group_state
                    .captured
                    .as_ref()
                    .map(|c| (*group_id, c.clone()))
            })
            .collect();

        Ok(Hsm {
            options,
            platform,
            persistent: MutationTracker::new(persistent, writer),
            volatile: VolatileState {
                leader: HashMap::new(),
                captured,
                stepping_down: HashMap::new(),
            },
            realm_keys,
        })
    }

    pub fn handle_request(&mut self, request_bytes: &[u8]) -> Result<Vec<u8>, HsmError> {
        let request: HsmRequestContainer = match marshalling::from_slice(request_bytes) {
            Ok(request) => request,
            Err(e) => {
                warn!(error = ?e, "deserialization error");
                return Err(HsmError::Deserialization(e));
            }
        };
        let req_name = request.req.name();

        let request_metrics = match self.options.metrics {
            MetricsReporting::Disabled => MetricsAction::Skip,
            MetricsReporting::Enabled => request.metrics,
        };
        let metrics = Metrics::new(req_name, request_metrics, self.platform.clone());

        match request.req {
            HsmRequest::Status(r) => self.dispatch_request(metrics, r, Self::handle_status_request),
            HsmRequest::NewRealm(r) => self.dispatch_request(metrics, r, Self::handle_new_realm),
            HsmRequest::JoinRealm(r) => self.dispatch_request(metrics, r, Self::handle_join_realm),
            HsmRequest::NewGroup(r) => self.dispatch_request(metrics, r, Self::handle_new_group),
            HsmRequest::JoinGroup(r) => self.dispatch_request(metrics, r, Self::handle_join_group),
            HsmRequest::BecomeLeader(r) => {
                self.dispatch_request(metrics, r, Self::handle_become_leader)
            }
            HsmRequest::StepDown(r) => {
                self.dispatch_request(metrics, r, Self::handle_stepdown_as_leader)
            }
            HsmRequest::CaptureNext(r) => {
                self.dispatch_request(metrics, r, Self::handle_capture_next)
            }
            HsmRequest::PersistState(r) => {
                self.dispatch_request(metrics, r, Self::handle_persist_state)
            }
            HsmRequest::Commit(r) => self.dispatch_request(metrics, r, Self::handle_commit),
            HsmRequest::TransferOut(r) => {
                self.dispatch_request(metrics, r, Self::handle_transfer_out)
            }
            HsmRequest::TransferNonce(r) => {
                self.dispatch_request(metrics, r, Self::handle_transfer_nonce)
            }
            HsmRequest::TransferStatement(r) => {
                self.dispatch_request(metrics, r, Self::handle_transfer_statement)
            }
            HsmRequest::TransferIn(r) => {
                self.dispatch_request(metrics, r, Self::handle_transfer_in)
            }
            HsmRequest::CompleteTransfer(r) => {
                self.dispatch_request(metrics, r, Self::handle_complete_transfer)
            }
            HsmRequest::AppRequest(r) => self.dispatch_request(metrics, r, Self::handle_app),
            HsmRequest::HandshakeRequest(r) => {
                self.dispatch_request(metrics, r, Self::handle_handshake)
            }
        }
    }

    fn dispatch_request<Req: HsmRpc, F: FnMut(&mut Self, &mut Metrics<P>, Req) -> Req::Response>(
        &mut self,
        mut metrics: Metrics<P>,
        r: Req,
        mut f: F,
    ) -> Result<Vec<u8>, HsmError> {
        let response = f(self, &mut metrics, r);

        let resp = HsmResponseContainer {
            res: response,
            metrics: metrics.finish(),
        };
        marshalling::to_vec(&resp).map_err(HsmError::Serialization)
    }

    fn read_persisted_state(
        nvram: &impl NVRam,
    ) -> Result<Option<PersistentState>, PersistenceError> {
        let d = nvram.read()?;
        if d.is_empty() {
            return Ok(None);
        }
        if d.len() < Blake2s256::output_size() {
            return Err(PersistenceError::InvalidChecksum);
        }
        let (data, stored_digest) = d.split_at(d.len() - Blake2s256::output_size());
        let calced_digest = Blake2s256::digest(data);
        if stored_digest == calced_digest.as_slice() {
            match marshalling::from_slice(data) {
                Ok(state) => Ok(Some(state)),
                Err(e) => Err(PersistenceError::Deserialization(e)),
            }
        } else {
            Err(PersistenceError::InvalidChecksum)
        }
    }

    fn handle_status_request(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: StatusRequest,
    ) -> StatusResponse {
        trace!(hsm = self.options.name, ?request);
        let response = StatusResponse {
            id: self.persistent.id,
            public_key: PublicKey(self.realm_keys.communication.1.as_bytes().to_vec()),
            realm: self.persistent.realm.as_ref().map(|realm| RealmStatus {
                id: realm.id,
                statement: realm.statement.clone(),
                groups: realm
                    .groups
                    .iter()
                    .map(|(group_id, group)| GroupStatus {
                        id: *group_id,
                        configuration: group.configuration.to_vec(),
                        captured: group.captured.clone(),
                        leader: self
                            .volatile
                            .leader
                            .get(group_id)
                            .map(|leader| LeaderStatus {
                                committed: leader.committed,
                                owned_range: leader
                                    .log
                                    .last()
                                    .entry
                                    .partition
                                    .as_ref()
                                    .map(|p| p.range.clone()),
                            }),
                        role: match self.volatile.leader.get(group_id) {
                            Some(_) => GroupMemberRole::Leader,
                            None => match self.volatile.stepping_down.get(group_id) {
                                Some(_) => GroupMemberRole::SteppingDown,
                                None => GroupMemberRole::Witness,
                            },
                        },
                    })
                    .collect(),
            }),
        };
        trace!(hsm = self.options.name, ?response);
        response
    }

    fn handle_new_realm(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: NewRealmRequest,
    ) -> NewRealmResponse {
        type Response = NewRealmResponse;
        trace!(hsm = self.options.name, ?request);
        let response = if self.persistent.realm.is_some() {
            Response::HaveRealm
        } else {
            let realm = create_random_realm_id(&mut self.platform);
            let group = create_random_group_id(&mut self.platform);

            self.persistent.mutate().realm = Some(PersistentRealmState {
                id: realm,
                statement: self
                    .realm_keys
                    .mac
                    .hsm_realm_mac(&HsmRealmStatementMessage {
                        realm,
                        hsm: self.persistent.id,
                        keys: &self.realm_keys,
                    }),
                groups: HashMap::from_iter([(
                    group,
                    PersistentGroupState {
                        configuration: GroupConfiguration::from_local(&self.persistent.id),
                        captured: None,
                    },
                )]),
            });

            let range = OwnedRange::full();
            let (root_hash, delta) = Tree::<MerkleHasher>::new_tree(&range);

            let entry = LogEntryBuilder {
                hsm: self.persistent.id,
                realm,
                group,
                index: LogIndex::FIRST,
                partition: Some(Partition { range, root_hash }),
                transferring_out: None,
                prev_mac: EntryMac::zero(),
            }
            .build(&self.realm_keys.mac);

            self.volatile.leader.insert(
                group,
                LeaderVolatileGroupState::new(entry.clone(), &self.options),
            );

            Response::Ok {
                realm,
                group,
                entry,
                delta,
            }
        };
        trace!(hsm = self.options.name, ?response);
        response
    }

    fn handle_join_realm(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: JoinRealmRequest,
    ) -> JoinRealmResponse {
        type Response = JoinRealmResponse;
        trace!(hsm = self.options.name, ?request);

        let response = match &self.persistent.realm {
            Some(realm) => {
                if realm.id == request.realm {
                    Response::Ok {
                        hsm: self.persistent.id,
                    }
                } else {
                    Response::HaveOtherRealm
                }
            }
            None => {
                // Check peer's MAC to make sure this HSM has the same keys.
                if self
                    .realm_keys
                    .mac
                    .hsm_realm_mac(&HsmRealmStatementMessage {
                        realm: request.realm,
                        hsm: request.peer,
                        keys: &self.realm_keys,
                    })
                    .verify(&request.statement)
                    .is_err()
                {
                    Response::InvalidStatement
                } else {
                    // Construct a similar MAC but for the local HSM ID. This
                    // will be re-checked on every boot, in case the keys
                    // somehow change.
                    let statement = self
                        .realm_keys
                        .mac
                        .hsm_realm_mac(&HsmRealmStatementMessage {
                            realm: request.realm,
                            hsm: self.persistent.id,
                            keys: &self.realm_keys,
                        });

                    let mut persistent = self.persistent.mutate();
                    persistent.realm = Some(PersistentRealmState {
                        id: request.realm,
                        statement,
                        groups: HashMap::new(),
                    });
                    Response::Ok { hsm: persistent.id }
                }
            }
        };

        trace!(hsm = self.options.name, ?response);
        response
    }

    fn handle_new_group(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: NewGroupRequest,
    ) -> NewGroupResponse {
        type Response = NewGroupResponse;
        trace!(hsm = self.options.name, ?request);

        let response = (|| {
            let Some(realm) = &self.persistent.realm else {
                return Response::InvalidRealm;
            };

            if realm.id != request.realm {
                return Response::InvalidRealm;
            }

            if realm.groups.len() >= usize::from(GROUPS_LIMIT) {
                return Response::TooManyGroups;
            }

            if request.members.iter().any(|(hsm_id, hsm_realm_statement)| {
                self.realm_keys
                    .mac
                    .hsm_realm_mac(&HsmRealmStatementMessage {
                        realm: realm.id,
                        hsm: *hsm_id,
                        keys: &self.realm_keys,
                    })
                    .verify(hsm_realm_statement)
                    .is_err()
            }) {
                return Response::InvalidStatement;
            }

            let Ok(configuration) = GroupConfiguration::from_sorted_including_local(
                request
                    .members
                    .iter()
                    .map(|(id, _)| *id)
                    .collect::<Vec<HsmId>>(),
                &self.persistent.id,
            ) else {
                return Response::InvalidConfiguration;
            };

            let group = create_random_group_id(&mut self.platform);
            let statement =
                self.realm_keys
                    .mac
                    .group_configuration_mac(&GroupConfigurationStatementMessage {
                        realm: request.realm,
                        group,
                        configuration: &configuration,
                    });

            {
                let mut persistent = self.persistent.mutate();
                let existing = persistent.realm.as_mut().unwrap().groups.insert(
                    group,
                    PersistentGroupState {
                        configuration,
                        captured: None,
                    },
                );
                assert!(existing.is_none());
            }

            let entry = LogEntryBuilder {
                hsm: self.persistent.id,
                realm: request.realm,
                group,
                index: LogIndex::FIRST,
                partition: None,
                transferring_out: None,
                prev_mac: EntryMac::zero(),
            }
            .build(&self.realm_keys.mac);

            self.volatile.leader.insert(
                group,
                LeaderVolatileGroupState::new(entry.clone(), &self.options),
            );

            Response::Ok {
                group,
                statement,
                entry,
            }
        })();

        trace!(hsm = self.options.name, ?response);
        response
    }

    fn handle_join_group(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: JoinGroupRequest,
    ) -> JoinGroupResponse {
        type Response = JoinGroupResponse;
        trace!(hsm = self.options.name, ?request);

        let response = (|| {
            let Ok(configuration) = GroupConfiguration::from_sorted_including_local(
                request.configuration,
                &self.persistent.id,
            ) else {
                return Response::InvalidConfiguration;
            };

            match &self.persistent.realm {
                None => return Response::InvalidRealm,

                Some(realm) => {
                    if realm.id != request.realm {
                        return Response::InvalidRealm;
                    }
                    if realm.groups.len() >= usize::from(GROUPS_LIMIT) {
                        return Response::TooManyGroups;
                    }

                    if self
                        .realm_keys
                        .mac
                        .group_configuration_mac(&GroupConfigurationStatementMessage {
                            realm: request.realm,
                            group: request.group,
                            configuration: &configuration,
                        })
                        .verify(&request.statement)
                        .is_err()
                    {
                        return Response::InvalidStatement;
                    }
                }
            }

            self.persistent
                .mutate()
                .realm
                .as_mut()
                .unwrap()
                .groups
                .entry(request.group)
                .or_insert(PersistentGroupState {
                    configuration,
                    captured: None,
                });
            Response::Ok
        })();

        trace!(hsm = self.options.name, ?response);
        response
    }

    fn handle_become_leader(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: BecomeLeaderRequest,
    ) -> BecomeLeaderResponse {
        type Response = BecomeLeaderResponse;
        trace!(hsm = self.options.name, ?request);

        // We need to check against the persisted captures for safety reasons,
        // so make sure they're up to date.
        self.persist_current_captures();

        let response = (|| {
            let configuration = match &self.persistent.realm {
                None => return Response::InvalidRealm,

                Some(realm) => {
                    if realm.id != request.realm {
                        return Response::InvalidRealm;
                    }

                    if self.volatile.stepping_down.get(&request.group).is_some() {
                        return Response::StepdownInProgress;
                    }

                    match realm.groups.get(&request.group) {
                        None => return Response::InvalidGroup,

                        Some(group) => match &group.captured {
                            None => return Response::NotCaptured { have: None },
                            Some((captured_index, captured_mac)) => {
                                if request.last_entry.index != *captured_index
                                    || request.last_entry.entry_mac != *captured_mac
                                {
                                    return Response::NotCaptured {
                                        have: Some(*captured_index),
                                    };
                                }
                                if self
                                    .realm_keys
                                    .mac
                                    .log_entry_mac(&EntryMacMessage::new(
                                        request.realm,
                                        request.group,
                                        &request.last_entry,
                                    ))
                                    .verify(&request.last_entry.entry_mac)
                                    .is_err()
                                {
                                    return Response::InvalidMac;
                                }
                                group.configuration.to_vec()
                            }
                        },
                    }
                }
            };

            self.volatile
                .leader
                .entry(request.group)
                .or_insert_with(|| {
                    LeaderVolatileGroupState::new(request.last_entry, &self.options)
                });

            Response::Ok { configuration }
        })();

        trace!(hsm = self.options.name, ?response);
        response
    }

    fn handle_stepdown_as_leader(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: StepDownRequest,
    ) -> StepDownResponse {
        type Response = StepDownResponse;
        trace!(hsm = self.options.name, ?request);

        let Some(realm) = &self.persistent.realm else {
            return Response::InvalidRealm;
        };
        if realm.id != request.realm {
            return Response::InvalidRealm;
        }
        let Some(_group) = realm.groups.get(&request.group) else {
            return Response::InvalidGroup;
        };
        self.stepdown_at(request.group, StepDownPoint::LastLogIndex)
    }

    // Move to the stepping down state. Stepdown will end once the committed log
    // index >= stepdown_index and any abandoned entries have been reported
    // through a commit request.
    fn stepdown_at(&mut self, group: GroupId, stepdown: StepDownPoint) -> StepDownResponse {
        let Some(mut leader) = self.volatile.leader.remove(&group) else {
            return match self.current_role(&group) {
                Some(role) => StepDownResponse::NotLeader(role),
                None => StepDownResponse::InvalidGroup,
            };
        };
        let stepdown_index = match stepdown {
            StepDownPoint::LastLogIndex => leader.log.last_index(),
            StepDownPoint::LogIndex(index) => index,
        };

        // If we've committed to the stepdown index and there are no log entries
        // that get abandoned we can go straight to the Witness state.
        if let Some(committed) = leader.committed {
            if committed == stepdown_index && leader.log.last_index() == stepdown_index {
                return StepDownResponse::Complete {
                    last: stepdown_index,
                };
            }
        }
        // Otherwise we need to transition to SteppingDown.

        // Anything after the stepdown index is never going to commit and is
        // flagged as abandoned.
        let mut abandoned: Vec<EntryMac> = Vec::new();
        while leader.log.last_index() > stepdown_index {
            let e = leader.log.pop_last();
            abandoned.push(e.entry.entry_mac);
        }

        self.volatile.stepping_down.insert(
            group,
            SteppingDownVolatileGroupState {
                log: leader.log,
                committed: leader.committed,
                stepdown_at: stepdown_index,
                abandoned,
            },
        );
        StepDownResponse::InProgress {
            last: stepdown_index,
        }
    }

    fn handle_persist_state(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: PersistStateRequest,
    ) -> PersistStateResponse {
        type Response = PersistStateResponse;
        trace!(hsm = self.options.name, ?request);

        self.persist_current_captures();

        let state = &*self.persistent;
        let captured = match &state.realm {
            None => Vec::new(),
            Some(r) => r
                .groups
                .iter()
                .filter_map(|(group, group_state)| {
                    group_state.captured.as_ref().map(|(index, entry_mac)| {
                        let statement =
                            self.realm_keys.mac.captured_mac(&CapturedStatementMessage {
                                hsm: state.id,
                                realm: r.id,
                                group: *group,
                                index: *index,
                                entry_mac,
                            });
                        Captured {
                            group: *group,
                            hsm: state.id,
                            realm: r.id,
                            index: *index,
                            mac: entry_mac.clone(),
                            statement,
                        }
                    })
                })
                .collect(),
        };
        Response::Ok { captured }
    }

    fn persist_current_captures(&mut self) {
        if !self.volatile.captured.is_empty() {
            let mut state = self.persistent.mutate();
            if let Some(realm) = &mut state.realm {
                // copy captured over to persist it
                for (group_id, (index, mac)) in &self.volatile.captured {
                    if let Some(g) = realm.groups.get_mut(group_id) {
                        g.captured = Some((*index, mac.clone()));
                    }
                }
            }
        }
    }

    fn handle_handshake(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: HandshakeRequest,
    ) -> HandshakeResponse {
        type Response = HandshakeResponse;
        trace!(hsm = self.options.name, ?request);

        let response = match &self.persistent.realm {
            Some(realm) if realm.id == request.realm => {
                if realm.groups.contains_key(&request.group) {
                    if let Some(leader) = self.volatile.leader.get_mut(&request.group) {
                        if (leader.log.last().entry)
                            .partition
                            .as_ref()
                            .filter(|partition| partition.range.contains(&request.record_id))
                            .is_some()
                        {
                            match noise::Handshake::start(
                                (
                                    &self.realm_keys.communication.0,
                                    &self.realm_keys.communication.1,
                                ),
                                &request.handshake,
                                &mut self.platform,
                            ) {
                                Ok((handshake, payload)) if payload.is_empty() => {
                                    match handshake.finish(&[]) {
                                        Ok((transport, response)) => {
                                            leader.sessions.insert(
                                                (request.record_id, request.session_id),
                                                transport,
                                            );
                                            Response::Ok {
                                                noise: response,
                                                session_lifetime: SESSION_LIFETIME,
                                            }
                                        }
                                        Err(_) => Response::SessionError,
                                    }
                                }
                                _ => Response::SessionError,
                            }
                        } else {
                            Response::NotOwner
                        }
                    } else {
                        Response::NotLeader
                    }
                } else {
                    Response::InvalidGroup
                }
            }

            None | Some(_) => Response::InvalidRealm,
        };

        trace!(hsm = self.options.name, ?response);
        response
    }

    fn handle_app(&mut self, metrics: &mut Metrics<P>, request: AppRequest) -> AppResponse {
        type Response = AppResponse;
        trace!(hsm = self.options.name, ?request);

        let start = metrics.now();
        let mut app_req_name = None;

        let response = (|| {
            let Some(realm) = &self.persistent.realm else {
                return Response::InvalidRealm;
            };
            if realm.id != request.realm {
                return Response::InvalidRealm;
            }
            if !realm.groups.contains_key(&request.group) {
                return Response::InvalidGroup;
            }
            let Some(leader) = self.volatile.leader.get_mut(&request.group) else {
                return Response::NotLeader(
                    self.current_role(&request.group)
                        .expect("We already validated that this HSM is a member of the group"),
                );
            };
            if (leader.log.last().entry)
                .partition
                .as_ref()
                .filter(|partition| partition.range.contains(&request.record_id))
                .is_none()
            {
                return Response::NotOwner;
            }
            // If we get a request where the log index is newer than anything we
            // know about then some other HSM wrote a log entry and therefore we
            // are not leader anymore. This also stops this replying with stale
            // proof and the agent endlessly retrying.
            if request.index > leader.log.last_index() {
                self.handle_stepdown_as_leader(
                    metrics,
                    StepDownRequest {
                        realm: request.realm,
                        group: request.group,
                    },
                );
                return Response::NotLeader(
                    self.current_role(&request.group)
                        .expect("We already validated that this HSM is a member of the group"),
                );
            }
            handle_app_request(
                request,
                self.persistent.id,
                &self.realm_keys,
                leader,
                &mut app_req_name,
                &mut self.platform,
            )
        })();

        metrics.record(app_req_name.unwrap_or("App::unknown"), start);
        trace!(hsm = self.options.name, ?response);
        response
    }

    fn current_role(&self, group: &GroupId) -> Option<GroupMemberRole> {
        if self.volatile.leader.contains_key(group) {
            Some(GroupMemberRole::Leader)
        } else if self.volatile.stepping_down.contains_key(group) {
            Some(GroupMemberRole::SteppingDown)
        } else if self
            .persistent
            .realm
            .as_ref()
            .is_some_and(|r| r.groups.contains_key(group))
        {
            Some(GroupMemberRole::Witness)
        } else {
            None
        }
    }
}

fn secrets_req_name(r: &SecretsRequest) -> &'static str {
    match r {
        SecretsRequest::Register1 => "App::Register1",
        SecretsRequest::Register2(_) => "App::Register2",
        SecretsRequest::Recover1 => "App::Recover1",
        SecretsRequest::Recover2(_) => "App::Recover2",
        SecretsRequest::Recover3(_) => "App::Recover3",
        SecretsRequest::Delete => "App::Delete",
    }
}

fn secrets_request_type(r: &SecretsRequest) -> AppRequestType {
    match r {
        SecretsRequest::Register1 => AppRequestType::Register1,
        SecretsRequest::Register2(_) => AppRequestType::Register2,
        SecretsRequest::Recover1 => AppRequestType::Recover1,
        SecretsRequest::Recover2(_) => AppRequestType::Recover2,
        SecretsRequest::Recover3(_) => AppRequestType::Recover3,
        SecretsRequest::Delete => AppRequestType::Delete,
    }
}

fn handle_app_request(
    request: AppRequest,
    hsm: HsmId,
    keys: &RealmKeys,
    leader: &mut LeaderVolatileGroupState,
    req_name_out: &mut Option<&'static str>,
    rng: &mut impl CryptoRng,
) -> AppResponse {
    let tree = leader
        .tree
        .as_mut()
        .expect("caller should have checked that this leader owns a partition");

    let (merkle, record) =
        match MerkleHelper::get_record(&request.record_id, request.proof, &keys.record, tree) {
            Ok(record) => record,
            Err(response) => return response.into(),
        };

    // This should be enforced by the load balancer, but double check.
    match &request.encrypted {
        NoiseRequest::Transport { ciphertext } => {
            assert!(ciphertext.len() <= BODY_SIZE_LIMIT);
        }
        NoiseRequest::Handshake { handshake } => {
            assert_eq!(handshake.client_ephemeral_public.len(), 32);
            assert!(handshake.payload_ciphertext.len() <= BODY_SIZE_LIMIT);
        }
    }

    let (noise, secrets_request) = match NoiseHelper::decode(
        request.record_id.clone(),
        request.session_id,
        &request.encrypted,
        &mut leader.sessions,
        &keys.communication,
        rng,
    ) {
        Ok(secrets_request) => secrets_request,
        Err(response) => return response.into(),
    };

    let secrets_request_type = secrets_request_type(&secrets_request);
    req_name_out.replace(secrets_req_name(&secrets_request));

    let (secrets_response, change) = app::process(secrets_request, record.as_deref(), rng);

    let secrets_response = noise.encode(secrets_response, &mut leader.sessions);

    let (root_hash, store_delta) = merkle.update_overlay(rng, change);

    let last_entry = leader.log.last();
    let new_entry = LogEntryBuilder {
        hsm,
        realm: request.realm,
        group: request.group,
        index: last_entry.entry.index.next(),
        partition: Some(Partition {
            range: last_entry.entry.partition.as_ref().unwrap().range.clone(),
            root_hash,
        }),
        transferring_out: last_entry.entry.transferring_out.clone(),
        prev_mac: last_entry.entry.entry_mac.clone(),
    }
    .build(&keys.mac);

    leader.log.append(new_entry.clone(), Some(secrets_response));

    AppResponse::Ok {
        entry: new_entry,
        delta: store_delta,
        request_type: secrets_request_type,
    }
}

/// Used in [`handle_app_request`].
struct MerkleHelper<'a> {
    tree: &'a mut Tree<MerkleHasher>,
    leaf_key: &'a RecordEncryptionKey,
    latest_proof: VerifiedProof<DataHash>,
}

impl<'a> MerkleHelper<'a> {
    fn get_record(
        record_id: &RecordId,
        request_proof: ReadProof<DataHash>,
        leaf_key: &'a RecordEncryptionKey,
        tree: &'a mut Tree<MerkleHasher>,
    ) -> Result<(Self, Option<Vec<u8>>), AppError> {
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

        if *record_id != request_proof.key {
            warn!(?record_id, proof_key=?request_proof.key, "Received proof for wrong record_id");
            return Err(AppError::InvalidProof);
        }

        let latest_proof = match tree.latest_proof(request_proof) {
            Ok(v) => v,
            Err(ProofError::Stale) => {
                info!("stale proof trying to get current value");
                return Err(AppError::StaleProof);
            }
            Err(ProofError::Invalid) => {
                warn!("proof was flagged as invalid");
                return Err(AppError::InvalidProof);
            }
        };

        let latest_value = match &latest_proof.leaf {
            None => None,
            Some(l) => {
                let cipher =
                    XChaCha20Poly1305::new_from_slice(&leaf_key.0).expect("couldn't create cipher");
                let nonce_size = XNonce::default().len();
                if l.value.len() <= nonce_size {
                    warn!(size=%l.value.len(), "received leaf value smaller than the nonce size");
                    return Err(AppError::InvalidRecordData);
                }
                let (cipher_text, nonce_bytes) =
                    l.value.as_slice().split_at(l.value.len() - nonce_size);
                let nonce = XNonce::from_slice(nonce_bytes);
                match cipher.decrypt(nonce, cipher_text) {
                    Ok(plain_text) => Some(plain_text),
                    Err(e) => {
                        warn!(?e, "failed to decrypt leaf value");
                        return Err(AppError::InvalidRecordData);
                    }
                }
            }
        };

        Ok((
            MerkleHelper {
                leaf_key,
                tree,
                latest_proof,
            },
            latest_value,
        ))
    }

    fn update_overlay(
        self,
        rng: &mut impl CryptoRng,
        change: Option<RecordChange>,
    ) -> (DataHash, StoreDelta<DataHash>) {
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

        match change {
            Some(change) => match change {
                RecordChange::Update(record) => {
                    let cipher = XChaCha20Poly1305::new_from_slice(&self.leaf_key.0)
                        .expect("couldn't create cipher");

                    let mut nonce = XNonce::default();
                    rng.fill_bytes(&mut nonce);
                    let plain_text: &[u8] = &record;

                    // An optimization we could do is to use the authentication
                    // tag as the leaf's hash. Right now this is checking the
                    // integrity of the record twice: once in the Merkle tree
                    // hash and once in the AEAD tag.
                    let mut cipher_text = cipher
                        .encrypt(&nonce, plain_text)
                        .expect("couldn't encrypt record");
                    cipher_text.extend_from_slice(&nonce);

                    self.tree
                        .insert(self.latest_proof, cipher_text)
                        .expect("proof should be valid and current")
                }
            },

            None => (*self.latest_proof.root_hash(), StoreDelta::default()),
        }
    }
}

/// Used in [`handle_app_request`].
struct NoiseHelper {
    record_id: RecordId,
    session_id: SessionId,
    state: NoiseHelperState,
}

enum NoiseHelperState {
    Handshake(noise::Handshake),
    Transport(noise::Transport),
}

impl NoiseHelper {
    fn decode(
        record_id: RecordId,
        session_id: SessionId,
        encrypted: &NoiseRequest,
        sessions: &mut SessionCache,
        realm_communication: &(x25519::StaticSecret, x25519::PublicKey),
        rng: &mut impl CryptoRng,
    ) -> Result<(Self, SecretsRequest), AppError> {
        let (message, secrets_request) = match encrypted {
            NoiseRequest::Handshake { handshake } => {
                let (handshake, payload) = noise::Handshake::start(
                    (&realm_communication.0, &realm_communication.1),
                    handshake,
                    rng,
                )
                .map_err(|_| AppError::SessionError)?;

                let secrets_request = marshalling::from_slice::<SecretsRequest>(&payload)
                    .map_err(|_| AppError::DecodingError)?;
                if secrets_request.needs_forward_secrecy() {
                    return Err(AppError::SessionError);
                }
                (NoiseHelperState::Handshake(handshake), secrets_request)
            }

            NoiseRequest::Transport { ciphertext } => {
                let mut transport = sessions
                    .remove(&(record_id.clone(), session_id))
                    .ok_or(AppError::MissingSession)?;
                let plaintext = transport
                    .decrypt(ciphertext)
                    .map_err(|_| AppError::SessionError)?;
                let secrets_request = marshalling::from_slice::<SecretsRequest>(&plaintext)
                    .map_err(|_| AppError::DecodingError)?;
                (NoiseHelperState::Transport(transport), secrets_request)
            }
        };
        Ok((
            Self {
                record_id,
                session_id,
                state: message,
            },
            secrets_request,
        ))
    }

    fn encode(self, response: SecretsResponse, sessions: &mut SessionCache) -> NoiseResponse {
        // TODO: The SecretsResponse should probably be padded so that the
        // agent doesn't learn from its encrypted length whether the client was
        // successful.

        // It might not be safe to back out at this point, since some Merkle
        // state has already been modified. Since we don't expect to see
        // encoding and encryption errors, it's probably OK to panic here.
        let response = marshalling::to_vec(&response).expect("SecretsResponse serialization error");
        let (response, transport) = match self.state {
            NoiseHelperState::Handshake(handshake) => {
                let (transport, handshake_response) = handshake
                    .finish(&response)
                    .expect("Noise handshake encryption error");
                (
                    NoiseResponse::Handshake {
                        handshake: handshake_response,
                        session_lifetime: SESSION_LIFETIME,
                    },
                    transport,
                )
            }
            NoiseHelperState::Transport(mut transport) => {
                let ciphertext = transport
                    .encrypt(&response)
                    .expect("Noise transport encryption error");
                (NoiseResponse::Transport { ciphertext }, transport)
            }
        };

        sessions.insert((self.record_id, self.session_id), transport);
        response
    }
}

// Some of the error types from [`AppResponse`].
enum AppError {
    StaleProof,
    InvalidProof,
    InvalidRecordData,
    MissingSession,
    SessionError,
    DecodingError,
}

impl From<AppError> for AppResponse {
    fn from(e: AppError) -> Self {
        match e {
            AppError::StaleProof => Self::StaleProof,
            AppError::InvalidProof => Self::InvalidProof,
            AppError::InvalidRecordData => Self::InvalidRecordData,
            AppError::MissingSession => Self::MissingSession,
            AppError::SessionError => Self::SessionError,
            AppError::DecodingError => Self::DecodingError,
        }
    }
}

enum StepDownPoint {
    // Step down at the index of the last item in leader log.
    LastLogIndex,
    // Step down at this specific log index.
    LogIndex(LogIndex),
}
