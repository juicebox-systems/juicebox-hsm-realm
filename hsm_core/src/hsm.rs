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

use self::mac::{
    CapturedStatementMessage, CtMac, EntryMacMessage, GroupConfigurationStatementMessage,
    HsmRealmStatementMessage, MacKey, TransferStatementMessage,
};
use super::hal::{Clock, CryptoRng, IOError, NVRam, Platform};
use super::merkle::{
    proof::{ProofError, VerifiedProof},
    MergeError, NodeHasher, Tree,
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
    CompleteTransferRequest, CompleteTransferResponse, DataHash, EntryMac, GroupId,
    GroupMemberRole, GroupStatus, HandshakeRequest, HandshakeResponse, HsmId, HsmRealmStatement,
    JoinGroupRequest, JoinGroupResponse, JoinRealmRequest, JoinRealmResponse, LeaderStatus,
    LogEntry, LogIndex, NewGroupRequest, NewGroupResponse, NewRealmRequest, NewRealmResponse,
    OwnedRange, Partition, PersistStateRequest, PersistStateResponse, PublicKey, RealmStatus,
    RecordId, StatusRequest, StatusResponse, StepDownRequest, StepDownResponse, TransferInRequest,
    TransferInResponse, TransferNonce, TransferNonceRequest, TransferNonceResponse,
    TransferOutRequest, TransferOutResponse, TransferStatementRequest, TransferStatementResponse,
    TransferringOut, CONFIGURATION_LIMIT, GROUPS_LIMIT,
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

pub fn create_random_transfer_nonce(rng: &mut impl CryptoRng) -> TransferNonce {
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    TransferNonce(nonce)
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

    /// Returns true if we're only a witness for the groups on this HSM.
    pub fn is_witness_only(&self) -> bool {
        self.volatile.leader.is_empty() && self.volatile.stepping_down.is_empty()
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

    fn handle_transfer_out(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: TransferOutRequest,
    ) -> TransferOutResponse {
        type Response = TransferOutResponse;
        trace!(hsm = self.options.name, ?request);

        let response = (|| {
            let Some(realm) = &self.persistent.realm else {
                return Response::InvalidRealm;
            };
            if realm.id != request.realm {
                return Response::InvalidRealm;
            }

            if realm.groups.get(&request.source).is_none() || request.source == request.destination
            {
                return Response::InvalidGroup;
            }

            let Some(leader) = self.volatile.leader.get_mut(&request.source) else {
                return Response::NotLeader;
            };

            let last_entry = &leader.log.last().entry;

            // Note: The owned_range found in the last entry might not have
            // committed yet. We think that's OK. The source group won't
            // produce a transfer statement unless this last entry and the
            // transferring out entry have committed.
            let Some(owned_partition) = &last_entry.partition else {
                return Response::NotOwner;
            };

            if last_entry.transferring_out.is_some() {
                // TODO: should return an error, not panic
                panic!("can't transfer because already transferring");
            }

            // TODO: This will always return StaleIndex if we're pipelining
            // changes while transferring ownership. We need to bring
            // `request.proof` forward by applying recent changes to it.
            if request.index != last_entry.index {
                return Response::StaleIndex;
            }

            // This supports two options: moving out the entire owned range or
            // splitting the range in two at some key and moving out one of the
            // resulting trees.
            let keeping_partition: Option<Partition>;
            let transferring_partition: Partition;
            let delta;

            if request.range == owned_partition.range {
                keeping_partition = None;
                transferring_partition = owned_partition.clone();
                delta = StoreDelta::default();
            } else {
                let Some(request_proof) = request.proof else {
                    return Response::MissingProof;
                };
                match owned_partition.range.split_at(&request.range) {
                    None => return Response::NotOwner,
                    Some(key) => {
                        if key != request_proof.key {
                            return Response::MissingProof;
                        }
                    }
                }
                let tree = leader
                    .tree
                    .take()
                    .expect("tree must be set if leader owns a partition");
                let (keeping, transferring, split_delta) = match tree.range_split(request_proof) {
                    Err(ProofError::Stale) => return Response::StaleProof,
                    Err(ProofError::Invalid) => return Response::InvalidProof,
                    Ok(split) => {
                        if split.left.range == request.range {
                            (split.right, split.left, split.delta)
                        } else if split.right.range == request.range {
                            (split.left, split.right, split.delta)
                        } else {
                            panic!(
                                "The tree was split but neither half contains the expected key range."
                            );
                        }
                    }
                };
                keeping_partition = Some(Partition {
                    root_hash: keeping.root_hash,
                    range: keeping.range,
                });
                transferring_partition = Partition {
                    root_hash: transferring.root_hash,
                    range: transferring.range,
                };
                delta = split_delta;
            }

            leader.tree = keeping_partition
                .as_ref()
                .map(|p| Tree::with_existing_root(p.root_hash, self.options.tree_overlay_size));

            let index = last_entry.index.next();
            let entry = LogEntryBuilder {
                hsm: self.persistent.id,
                realm: request.realm,
                group: request.source,
                index,
                partition: keeping_partition,
                transferring_out: Some(TransferringOut {
                    destination: request.destination,
                    partition: transferring_partition,
                    at: index,
                }),
                prev_mac: last_entry.entry_mac.clone(),
            }
            .build(&self.realm_keys.mac);

            leader.log.append(entry.clone(), None);

            TransferOutResponse::Ok { entry, delta }
        })();

        trace!(hsm = self.options.name, ?response);
        response
    }

    fn handle_transfer_nonce(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: TransferNonceRequest,
    ) -> TransferNonceResponse {
        type Response = TransferNonceResponse;
        trace!(hsm = self.options.name, ?request);

        let response = (|| {
            let Some(realm) = &self.persistent.realm else {
                return Response::InvalidRealm;
            };
            if realm.id != request.realm {
                return Response::InvalidRealm;
            }

            if realm.groups.get(&request.destination).is_none() {
                return Response::InvalidGroup;
            }

            let Some(leader) = self.volatile.leader.get_mut(&request.destination) else {
                return Response::NotLeader;
            };

            let nonce = create_random_transfer_nonce(&mut self.platform);
            leader.incoming = Some(nonce);
            Response::Ok(nonce)
        })();

        trace!(hsm = self.options.name, ?response);
        response
    }

    fn handle_transfer_statement(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: TransferStatementRequest,
    ) -> TransferStatementResponse {
        type Response = TransferStatementResponse;
        trace!(hsm = self.options.name, ?request);
        let response = (|| {
            let Some(realm) = &self.persistent.realm else {
                return Response::InvalidRealm;
            };
            if realm.id != request.realm {
                return Response::InvalidRealm;
            }

            if realm.groups.get(&request.source).is_none() || request.source == request.destination
            {
                return Response::InvalidGroup;
            }

            let Some(leader) = self.volatile.leader.get_mut(&request.source) else {
                return Response::NotLeader;
            };

            let Some(TransferringOut {
                destination,
                partition,
                at: transferring_at,
            }) = &leader.log.last().entry.transferring_out
            else {
                return Response::NotTransferring;
            };
            if *destination != request.destination {
                return Response::NotTransferring;
            }
            if !matches!(leader.committed, Some(c) if c >= *transferring_at) {
                return Response::Busy;
            }

            let statement = self.realm_keys.mac.transfer_mac(&TransferStatementMessage {
                realm: request.realm,
                destination: *destination,
                partition,
                nonce: request.nonce,
            });

            Response::Ok(statement)
        })();

        trace!(hsm = self.options.name, ?response);
        response
    }

    fn handle_transfer_in(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: TransferInRequest,
    ) -> TransferInResponse {
        type Response = TransferInResponse;
        trace!(hsm = self.options.name, ?request);

        let response = (|| {
            let Some(realm) = &self.persistent.realm else {
                return Response::InvalidRealm;
            };
            if realm.id != request.realm {
                return Response::InvalidRealm;
            }

            if realm.groups.get(&request.destination).is_none() {
                return Response::InvalidGroup;
            }

            let Some(leader) = self.volatile.leader.get_mut(&request.destination) else {
                return Response::NotLeader;
            };

            if leader.incoming != Some(request.nonce) {
                return Response::InvalidNonce;
            }
            leader.incoming = None;

            let last_entry = &leader.log.last().entry;
            let needs_merge = match &last_entry.partition {
                None => false,
                Some(part) => match part.range.join(&request.transferring.range) {
                    None => return Response::UnacceptableRange,
                    Some(_) => {
                        // We need to verify that the transferring proof matches the
                        // transferring partition. We don't need to do this for owned
                        // as the Merkle tree can deal with that from its overlay.
                        if let Some(proofs) = &request.proofs {
                            if request.transferring.range != proofs.transferring.range
                                || request.transferring.root_hash != proofs.transferring.root_hash
                            {
                                return Response::InvalidProof;
                            }
                        } else {
                            return Response::MissingProofs;
                        }
                        true
                    }
                },
            };

            if self
                .realm_keys
                .mac
                .transfer_mac(&TransferStatementMessage {
                    realm: request.realm,
                    destination: request.destination,
                    partition: &request.transferring,
                    nonce: request.nonce,
                })
                .verify(&request.statement)
                .is_err()
            {
                return Response::InvalidStatement;
            }

            let (partition, delta) = if needs_merge {
                let tree = leader.tree.take().unwrap();
                let proofs = request.proofs.unwrap();
                match tree.merge(proofs.owned, proofs.transferring) {
                    Err(MergeError::NotAdjacentRanges) => return Response::UnacceptableRange,
                    Err(MergeError::Proof(ProofError::Stale)) => return Response::StaleProof,
                    Err(MergeError::Proof(ProofError::Invalid)) => return Response::InvalidProof,
                    Ok(merge_result) => (
                        Partition {
                            range: merge_result.range,
                            root_hash: merge_result.root_hash,
                        },
                        merge_result.delta,
                    ),
                }
            } else {
                (request.transferring, StoreDelta::default())
            };

            let entry = LogEntryBuilder {
                hsm: self.persistent.id,
                realm: request.realm,
                group: request.destination,
                index: last_entry.index.next(),
                partition: Some(partition.clone()),
                transferring_out: last_entry.transferring_out.clone(),
                prev_mac: last_entry.entry_mac.clone(),
            }
            .build(&self.realm_keys.mac);

            leader.log.append(entry.clone(), None);

            leader.tree = Some(Tree::with_existing_root(
                partition.root_hash,
                self.options.tree_overlay_size,
            ));
            Response::Ok { entry, delta }
        })();

        trace!(hsm = self.options.name, ?response);
        response
    }

    fn handle_complete_transfer(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: CompleteTransferRequest,
    ) -> CompleteTransferResponse {
        type Response = CompleteTransferResponse;
        info!(hsm = self.options.name, ?request, "complete transfer");

        let response = (|| {
            let Some(realm) = &self.persistent.realm else {
                return Response::InvalidRealm;
            };
            if realm.id != request.realm {
                return Response::InvalidRealm;
            }

            if realm.groups.get(&request.source).is_none() || request.source == request.destination
            {
                return Response::InvalidGroup;
            }

            let Some(leader) = self.volatile.leader.get_mut(&request.source) else {
                return Response::NotLeader;
            };

            let last_entry = &leader.log.last().entry;
            if let Some(transferring_out) = &last_entry.transferring_out {
                if transferring_out.destination != request.destination
                    || transferring_out.partition.range != request.range
                {
                    return Response::NotTransferring;
                }
            } else {
                return Response::NotTransferring;
            }

            let entry = LogEntryBuilder {
                hsm: self.persistent.id,
                realm: request.realm,
                group: request.source,
                index: last_entry.index.next(),
                partition: last_entry.partition.clone(),
                transferring_out: None,
                prev_mac: last_entry.entry_mac.clone(),
            }
            .build(&self.realm_keys.mac);

            leader.log.append(entry.clone(), None);

            Response::Ok(entry)
        })();

        trace!(hsm = self.options.name, ?response);
        response
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

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::iter;
    use rand::Rng;
    use rand_core::{CryptoRng, OsRng, RngCore};
    use std::sync::Mutex;

    use crate::hash::HashMap;
    use crate::merkle::testing::MemStore;
    use juicebox_marshalling as marshalling;
    use juicebox_noise::client::Handshake;
    use juicebox_realm_api::requests::DeleteResponse;
    use juicebox_realm_api::types::RealmId;

    use super::super::hal::MAX_NVRAM_SIZE;
    use super::*;
    use hsm_api::{
        CaptureNextRequest, CaptureNextResponse, CommitRequest, CommitResponse, CommitState,
        EntryMac, GroupId, HsmId, LogIndex, CONFIGURATION_LIMIT,
    };

    fn array_big<const N: usize>(i: u8) -> [u8; N] {
        let mut r = [0xff; N];
        r[N - 1] = 0xff - i;
        r
    }

    // Verify that a PersistentState with GROUPS_LIMIT groups with
    // CONFIGURATION_LIMIT HSMs each fits in the NVRAM limit.
    #[test]
    fn persistent_data_size() {
        let id = HsmId([0xff; 16]);
        let group = PersistentGroupState {
            configuration: GroupConfiguration::from_sorted_including_local(
                (0..CONFIGURATION_LIMIT)
                    .map(|i| HsmId(array_big(i)))
                    .rev()
                    .collect::<Vec<HsmId>>(),
                &id,
            )
            .unwrap(),
            captured: Some((LogIndex(u64::MAX - 1), EntryMac::from([0xff; 32]))),
        };
        let mut groups = HashMap::new();
        for id in 0..GROUPS_LIMIT {
            groups.insert(GroupId(array_big(id)), group.clone());
        }
        let p = PersistentState {
            id,
            realm: Some(PersistentRealmState {
                id: RealmId([0xff; 16]),
                statement: HsmRealmStatement::from([0xff; 32]),
                groups,
            }),
        };
        let s = marshalling::to_vec(&p).unwrap();
        assert!(
            s.len() < MAX_NVRAM_SIZE,
            "serialized persistent state is {} bytes",
            s.len()
        );
    }

    fn make_leader_log() -> (LeaderLog, [EntryMac; 3]) {
        let hsm = HsmId([8; 16]);
        let e = LogEntry {
            index: LogIndex(42),
            partition: None,
            transferring_out: None,
            prev_mac: EntryMac::from([3; 32]),
            entry_mac: EntryMac::from([42; 32]),
            hsm,
        };
        let mut log = LeaderLog::new(e.clone());
        let e2 = LogEntry {
            index: LogIndex(43),
            partition: None,
            transferring_out: None,
            prev_mac: e.entry_mac.clone(),
            entry_mac: EntryMac::from([43; 32]),
            hsm,
        };
        log.append(
            e2.clone(),
            Some(NoiseResponse::Transport {
                ciphertext: vec![43, 43, 43],
            }),
        );
        let e3 = LogEntry {
            index: LogIndex(44),
            partition: None,
            transferring_out: None,
            prev_mac: e2.entry_mac.clone(),
            entry_mac: EntryMac::from([44; 32]),
            hsm,
        };
        log.append(
            e3.clone(),
            Some(NoiseResponse::Transport {
                ciphertext: vec![44, 44, 44],
            }),
        );
        (log, [e.entry_mac, e2.entry_mac, e3.entry_mac])
    }

    #[test]
    #[should_panic(expected = "not sequential")]
    fn leader_log_index_sequential() {
        let (mut log, macs) = make_leader_log();
        let e = LogEntry {
            index: LogIndex(55),
            partition: None,
            transferring_out: None,
            prev_mac: macs[2].clone(),
            entry_mac: EntryMac::from([44; 32]),
            hsm: HsmId([1; 16]),
        };
        log.append(e, None);
    }

    #[test]
    #[should_panic(expected = "not chained")]
    fn leader_log_mac_chain() {
        let (mut log, _) = make_leader_log();
        let last = log.last();
        let e = LogEntry {
            index: last.entry.index.next(),
            partition: None,
            transferring_out: None,
            prev_mac: EntryMac::from([45; 32]),
            entry_mac: EntryMac::from([45; 32]),
            hsm: last.entry.hsm,
        };
        log.append(e, None);
    }

    #[test]
    #[should_panic]
    fn leader_log_cant_empty_pop_first() {
        let (mut log, _) = make_leader_log();
        assert_eq!(LogIndex(42), log.pop_first().entry.index);
        assert_eq!(LogIndex(43), log.pop_first().entry.index);
        log.pop_first();
    }

    #[test]
    #[should_panic]
    fn leader_log_cant_empty_pop_last() {
        let (mut log, _) = make_leader_log();
        assert_eq!(LogIndex(44), log.pop_last().entry.index);
        assert_eq!(LogIndex(43), log.pop_last().entry.index);
        log.pop_last();
    }

    #[test]
    fn leader_log_first_last() {
        let (mut log, _) = make_leader_log();
        assert_eq!(LogIndex(42), log.first().entry.index);
        assert_eq!(LogIndex(44), log.last().entry.index);
        assert_eq!(LogIndex(42), log.first_index());
        assert_eq!(LogIndex(44), log.last_index());
        log.pop_last();
        assert_eq!(LogIndex(43), log.last().entry.index);
    }

    #[test]
    fn leader_log_with_index() {
        let (log, _) = make_leader_log();
        assert_eq!(
            LogIndex(44),
            log.get_index(LogIndex(44)).unwrap().entry.index
        );
        assert_eq!(
            LogIndex(42),
            log.get_index(LogIndex(42)).unwrap().entry.index
        );
        assert_eq!(
            LogIndex(43),
            log.get_index(LogIndex(43)).unwrap().entry.index
        );
        assert!(log.get_index(LogIndex(41)).is_none());
        assert!(log.get_index(LogIndex(45)).is_none());
        assert!(log.get_index(LogIndex::FIRST).is_none());
        assert!(log.get_index(LogIndex(u64::MAX)).is_none());
    }

    #[test]
    fn leader_log_take_first() {
        let (mut log, macs) = make_leader_log();
        assert_eq!(LogIndex(42), log.pop_first().entry.index);

        match log.take_first_response() {
            Some((mac, NoiseResponse::Transport { ciphertext })) => {
                assert_eq!(vec![43, 43, 43], ciphertext);
                assert_eq!(macs[1], mac);
            }
            _ => panic!("should of taken a noise response"),
        }
        assert!(log.take_first_response().is_none());
        assert!(log.pop_first().response.is_none());

        match log.take_first_response() {
            Some((mac, NoiseResponse::Transport { ciphertext })) => {
                assert_eq!(vec![44, 44, 44], ciphertext);
                assert_eq!(macs[2], mac);
            }
            _ => panic!("should of taken a noise response"),
        }
        assert!(log.take_first_response().is_none());
    }

    #[test]
    fn can_commit_from_other_captures() {
        // The leader should be able to commit entries using captures from other
        // HSMs even if it hasn't itself captured to that entry yet.

        let mut cluster = TestCluster::new(3);

        let committed = cluster.commit(cluster.group);
        assert_eq!(1, committed.len());
        let commit_index = committed[0].committed;

        // Make a regular request to the leader.
        let (handshake, res) = cluster.hsms[0].app_request(
            &cluster.store,
            cluster.realm,
            cluster.group,
            RecordId([3; 32]),
            SecretsRequest::Delete,
        );
        let (entry, delta) = unpack_app_response(&res);
        cluster.store.append(cluster.group, entry.clone(), delta);

        // Entry is not captured yet, commit shouldn't find anything new.
        let committed = cluster.commit(cluster.group);
        assert_eq!(1, committed.len());
        assert_eq!(commit_index, committed[0].committed);

        // We can capture on the other HSMs and commit, even if the leader
        // hasn't captured yet.
        for hsm in &mut cluster.hsms[1..] {
            hsm.capture_next(&cluster.store, cluster.realm, cluster.group);
        }
        let committed = cluster.commit(cluster.group);
        assert_eq!(1, committed.len());
        let committed = &committed[0];
        assert_eq!(committed.committed, entry.index);
        assert_eq!(committed.role, GroupMemberRole::Leader);
        assert_eq!(1, committed.responses.len());
        assert_eq!(entry.entry_mac, committed.responses[0].0);
        assert!(matches!(
            finish_handshake(handshake, &committed.responses[0].1),
            SecretsResponse::Delete(DeleteResponse::Ok)
        ));
        assert!(committed.abandoned.is_empty());

        // The leader captures, commit shouldn't do anything as the entry is
        // already committed.
        cluster.hsms[0].capture_next(&cluster.store, cluster.realm, cluster.group);
        let captures = cluster.persist_state(cluster.group);
        let committed2 = cluster.hsms[0].commit(cluster.realm, cluster.group, captures);
        assert_eq!(committed.committed, committed2.committed);
        assert!(committed2.responses.is_empty());
        assert!(committed2.abandoned.is_empty());
        assert_eq!(GroupMemberRole::Leader, committed2.role);
    }

    #[test]
    fn app_request_spots_future_log() {
        // During app_request a HSM can detect that some other HSM wrote
        // a log entry (by looking at the log index) and step down at that point.

        let mut cluster = TestCluster::new(2);
        // Make both HSMs leader.
        let last_entry = cluster.store.latest_log(&cluster.group);
        for hsm in &mut cluster.hsms {
            let res = hsm.become_leader(cluster.realm, cluster.group, last_entry.clone());
            assert!(matches!(res, BecomeLeaderResponse::Ok { .. }));
        }
        // Ensure everyone has committed the current log.
        cluster.capture_next_and_commit_group(cluster.group);

        // Have the first HSM handle a request and write it to the store.
        let (_handshake, res) = cluster.hsms[0].app_request(
            &cluster.store,
            cluster.realm,
            cluster.group,
            RecordId([3; 32]),
            SecretsRequest::Delete,
        );
        cluster.append(cluster.group, &res);

        // Have the other HSM try to handle a request, it should spot
        // that the LogIndex is higher than anything it generated.
        let (_, res) = cluster.hsms[1].app_request(
            &cluster.store,
            cluster.realm,
            cluster.group,
            RecordId([3; 32]),
            SecretsRequest::Delete,
        );
        // The 2nd HSM should of stepped down to Witness.
        assert!(
            matches!(res, AppResponse::NotLeader(GroupMemberRole::Witness)),
            "app_request unexpected result: {res:?}"
        );
    }

    #[test]
    fn capture_next_spots_diverged_log_no_inflight_reqs() {
        // During capture_next processing a leading HSM should spot that its in
        // memory log has diverged from the externally persisted log. If this
        // HSM has no uncommitted log entries, it can step down to Witness at
        // this point.

        let mut cluster = TestCluster::new(2);

        // Make a request to hsms[0] (the original leader) and commit it.
        let (_, res) = cluster.hsms[0].app_request(
            &cluster.store,
            cluster.realm,
            cluster.group,
            RecordId([4; 32]),
            SecretsRequest::Register1,
        );
        cluster.append(cluster.group, &res);
        cluster.capture_next_and_commit_group(cluster.group);

        // Make hsms[1] also a leader.
        let last_entry = cluster.store.latest_log(&cluster.group);
        let res = cluster.hsms[1].become_leader(cluster.realm, cluster.group, last_entry);
        assert!(matches!(res, BecomeLeaderResponse::Ok { .. }));

        // Have hsms[1] handle a request and write it to the store.
        let (_, res) = cluster.hsms[1].app_request(
            &cluster.store,
            cluster.realm,
            cluster.group,
            RecordId([4; 32]),
            SecretsRequest::Recover1,
        );
        cluster.append(cluster.group, &res);

        // When the first HSM captures this new entry from a different leader it
        // should stand down. As it has no requests left to commit, it can go
        // straight to Witness.
        assert_eq!(
            Some(GroupMemberRole::Witness),
            cluster.hsms[0].capture_next(&cluster.store, cluster.realm, cluster.group)
        );
    }

    #[test]
    fn capture_next_spots_diverged_log() {
        // During capture_next processing a leading HSM should spot that its in
        // memory log has diverged from the externally persisted log. If this
        // HSM has uncommitted log entries after the divergence point, it can
        // transition to stepping down and those uncommitted entries should be
        // flagged as abandoned during the next commit.
        //
        // This also covers the case where the log diverges at the first new
        // entry in the log after becoming leader.

        let mut cluster = TestCluster::new(3);
        // Make all the HSMs leader.
        let last = cluster.store.latest_log(&cluster.group);
        for hsm in cluster.hsms.iter_mut() {
            let r = hsm.become_leader(cluster.realm, cluster.group, last.clone());
            assert!(matches!(r, BecomeLeaderResponse::Ok { .. }));
        }

        // They all should be able to commit the existing log.
        cluster.commit(cluster.group);

        // Have them all handle an app request.
        let responses: Vec<AppResponse> = cluster
            .hsms
            .iter_mut()
            .map(|hsm| {
                let (_, r) = hsm.app_request(
                    &cluster.store,
                    cluster.realm,
                    cluster.group,
                    RecordId([3; 32]),
                    SecretsRequest::Delete,
                );
                // Everyone thinks they're leader, these should all succeed.
                assert!(matches!(r, AppResponse::Ok { .. }));
                r
            })
            .collect();

        // hsm[0] wins the log append battle.
        cluster.append(cluster.group, &responses[0]);

        // hsm[0] should happily capture next and think its still leader.
        assert_eq!(
            Some(GroupMemberRole::Leader),
            cluster.hsms[0].capture_next(&cluster.store, cluster.realm, cluster.group)
        );

        // The other HSMs should stand down. They have uncommitted entries but
        // they can't be committed. The HSM should transition to stepping down
        // and report these uncommitted entries as abandoned.
        for hsm in &mut cluster.hsms[1..] {
            assert_eq!(
                Some(GroupMemberRole::SteppingDown),
                hsm.capture_next(&cluster.store, cluster.realm, cluster.group)
            );
        }
        let captures = cluster.persist_state(cluster.group);
        for hsm in &mut cluster.hsms[1..] {
            let res = hsm.commit(cluster.realm, cluster.group, captures.clone());
            assert!(res.responses.is_empty());
            assert_eq!(1, res.abandoned.len());
            // Nothing left for commit to do, transition back to Witness.
            assert_eq!(GroupMemberRole::Witness, res.role);
        }
    }

    #[test]
    fn capture_next_spots_diverged_log_pipelined() {
        // During capture_next processing a leading HSM should spot that its in
        // memory log has diverged from the externally persisted log. The HSM
        // can start stepping down at this point. There may be entries after the
        // divergence point that should be abandoned. There may also be valid
        // uncommitted entries before the divergence point that can still be
        // committed.

        let mut cluster = TestCluster::new(3);

        // Have the leader handle a series of (pipelined) requests.
        let leader1_responses: Vec<AppResponse> = iter::repeat_with(|| {
            cluster.hsms[0]
                .app_request(
                    &cluster.store,
                    cluster.realm,
                    cluster.group,
                    RecordId([3; 32]),
                    SecretsRequest::Delete,
                )
                .1
        })
        .take(5)
        .collect();
        // The first 2 of these are successfully written to the log.
        cluster.append(cluster.group, &leader1_responses[0]);
        cluster.append(cluster.group, &leader1_responses[1]);

        // Make another HSM also leader.
        let last = cluster.store.latest_log(&cluster.group);
        cluster.hsms[1].capture_next(&cluster.store, cluster.realm, cluster.group);
        let r = cluster.hsms[1].become_leader(cluster.realm, cluster.group, last.clone());
        assert!(matches!(r, BecomeLeaderResponse::Ok { .. }),);

        // Have it handle an app request.
        let (_, leader2_response) = cluster.hsms[1].app_request(
            &cluster.store,
            cluster.realm,
            cluster.group,
            RecordId([3; 32]),
            SecretsRequest::Delete,
        );
        // hsm[1] wins the append battle.
        cluster.append(cluster.group, &leader2_response);

        // When hsm[0] (the original leader) captures the log it should spot
        // that it diverged and start stepping down.
        assert_eq!(
            Some(GroupMemberRole::SteppingDown),
            cluster.hsms[0].capture_next(&cluster.store, cluster.realm, cluster.group)
        );

        // hsm[0] is stepping down and should commit the log entries that it
        // successfully wrote to the log.
        let captures = cluster.persist_state(cluster.group);
        let commit = cluster.hsms[0].commit(cluster.realm, cluster.group, captures);
        // The first leader should of committed the first 2 responses it generated.
        let (entry, _) = unpack_app_response(&leader1_responses[0]);
        assert!(commit.responses.iter().any(|r| r.0 == entry.entry_mac));
        assert!(!commit.abandoned.contains(&entry.entry_mac));

        let (entry, _) = unpack_app_response(&leader1_responses[1]);
        assert!(commit.responses.iter().any(|r| r.0 == entry.entry_mac));
        assert!(!commit.abandoned.contains(&entry.entry_mac));
        assert_eq!(commit.committed, entry.index);

        // The other requests it handled should be flagged as abandoned, they'll never get committed.
        for ar in &leader1_responses[2..] {
            let (entry, _) = unpack_app_response(ar);
            assert!(commit.abandoned.contains(&entry.entry_mac));
        }
        assert_eq!(3, commit.abandoned.len());
        // its committed everything it can, it can now go back to being a witness.
        assert_eq!(GroupMemberRole::Witness, commit.role);

        // hsm[1] should be able to commit the new entry it wrote once capture_next has caught up.
        cluster.capture_next(cluster.group);
        let captures = cluster.persist_state(cluster.group);
        let commit = cluster.hsms[1].commit(cluster.realm, cluster.group, captures.clone());
        let (entry, _) = unpack_app_response(&leader2_response);
        assert_eq!(entry.index, commit.committed);
        assert_eq!(1, commit.responses.len());
        assert_eq!(entry.entry_mac, commit.responses[0].0);
        assert!(commit.abandoned.is_empty());
        assert_eq!(GroupMemberRole::Leader, commit.role);
    }

    #[test]
    fn capture_next_spots_diverged_log_while_stepping_down() {
        // A Leading HSM has a number of uncommitted log entries when it is
        // asked to stepdown. While in this stepping down process, capture_next
        // spots that the log has diverged. The stepping down index should be
        // shortened to just before the divergence point, and anything after
        // that should be flagged as abandoned.

        let mut cluster = TestCluster::new(3);
        // Have the leader handle a series of (pipelined) requests.
        let leader1_responses: Vec<AppResponse> = iter::repeat_with(|| {
            cluster.hsms[0]
                .app_request(
                    &cluster.store,
                    cluster.realm,
                    cluster.group,
                    RecordId([3; 32]),
                    SecretsRequest::Delete,
                )
                .1
        })
        .take(5)
        .collect();

        // Ask the HSM to gracefully step down.
        let res = cluster.hsms[0].stepdown_as_leader(cluster.realm, cluster.group);
        assert!(matches!(res, StepDownResponse::InProgress { .. }));

        // The first request is successfully written to the log.
        cluster.append(cluster.group, &leader1_responses[0]);
        // Should be able to capture & commit this fine.
        cluster.capture_next(cluster.group);
        let captures = cluster.persist_state(cluster.group);
        let res = cluster.hsms[0].commit(cluster.realm, cluster.group, captures);
        assert!(res.abandoned.is_empty());
        assert_eq!(1, res.responses.len());
        let (entry, _) = unpack_app_response(&leader1_responses[0]);
        assert_eq!(entry.entry_mac, res.responses[0].0);
        assert_eq!(entry.index, res.committed);
        assert_eq!(GroupMemberRole::SteppingDown, res.role);

        // Write the 2nd request to the log.
        cluster.append(cluster.group, &leader1_responses[1]);

        // Ask another HSM to also be leader.
        cluster.hsms[1].capture_next(&cluster.store, cluster.realm, cluster.group);
        let last_entry = cluster.store.latest_log(&cluster.group);
        let res = cluster.hsms[1].become_leader(cluster.realm, cluster.group, last_entry);
        assert!(matches!(res, BecomeLeaderResponse::Ok { .. }));

        // Have the new leader process a request and write to the log
        let (_, leader2_response) = cluster.hsms[1].app_request(
            &cluster.store,
            cluster.realm,
            cluster.group,
            RecordId([4; 32]),
            SecretsRequest::Register1,
        );
        cluster.append(cluster.group, &leader2_response);

        // hsms[0] capture next sees this diverged log. Its still stepping down.
        assert_eq!(
            Some(GroupMemberRole::SteppingDown),
            cluster.hsms[0].capture_next(&cluster.store, cluster.realm, cluster.group)
        );

        cluster.capture_next(cluster.group);
        let captures = cluster.persist_state(cluster.group);
        // Commit on hsms[0] should release the one entry that got persisted and
        // abandon the later ones.
        let mut res = cluster.hsms[0].commit(cluster.realm, cluster.group, captures);
        assert_eq!(GroupMemberRole::Witness, res.role);
        let (entry2, _) = unpack_app_response(&leader1_responses[1]);
        assert_eq!(1, res.responses.len());
        assert_eq!(entry2.entry_mac, res.responses[0].0);
        // everyone captured the log entry written by the new leader, so we'll commit
        // to that index.
        assert_eq!(entry2.index.next(), res.committed);

        res.abandoned.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let mut expected: Vec<EntryMac> = leader1_responses[2..]
            .iter()
            .map(|r| unpack_app_response(r).0.entry_mac)
            .collect();
        expected.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        assert_eq!(expected, res.abandoned);
    }

    fn unpack_app_response(r: &AppResponse) -> (LogEntry, StoreDelta<DataHash>) {
        if let AppResponse::Ok {
            entry,
            delta,
            request_type: _,
        } = r
        {
            (entry.clone(), delta.clone())
        } else {
            panic!("app_request failed {r:?}")
        }
    }

    fn finish_handshake(hs: Handshake, resp: &NoiseResponse) -> SecretsResponse {
        if let NoiseResponse::Handshake {
            handshake: result, ..
        } = resp
        {
            let app_res = hs.finish(result).unwrap();
            let secret_response: SecretsResponse = marshalling::from_slice(&app_res.1).unwrap();
            secret_response
        } else {
            panic!("expected a NoiseResponse::Handshake but got {:?}", resp);
        }
    }

    struct TestCluster<'a> {
        hsms: Vec<TestHsm<'a>>,
        realm: RealmId,
        group: GroupId,
        store: TestStore,
    }

    impl<'a> TestCluster<'a> {
        fn new(count: usize) -> Self {
            let mut k = [0u8; 32];
            OsRng.fill(&mut k);
            let privk = x25519::StaticSecret::from(k);
            let pubk = x25519::PublicKey::from(&privk);
            let keys = RealmKeys {
                record: RecordEncryptionKey(k),
                mac: MacKey::from(k),
                communication: (privk, pubk),
            };

            let mut store = TestStore::default();
            let mut hsms: Vec<_> = (0..count)
                .map(|i| TestHsm::new(format!("hsm_{i}"), keys.clone()))
                .collect();

            let mut m = Metrics::new("test", MetricsAction::Skip, TestPlatform::default());
            let realm = hsms[0].hsm.handle_new_realm(&mut m, NewRealmRequest {});

            let (realm, starting_group) = match realm {
                NewRealmResponse::Ok {
                    realm,
                    group: starting_group,
                    entry,
                    delta,
                } => {
                    store.append(starting_group, entry, delta);
                    (realm, starting_group)
                }
                NewRealmResponse::HaveRealm => panic!(),
            };

            let realm_statement = hsms[0].status().realm.unwrap().statement;
            let peer = hsms[0].id;
            for hsm in &mut hsms[1..] {
                assert!(matches!(
                    hsm.hsm.handle_join_realm(
                        &mut m,
                        JoinRealmRequest {
                            realm,
                            peer,
                            statement: realm_statement.clone(),
                        },
                    ),
                    JoinRealmResponse::Ok { .. }
                ));
            }

            let mut cluster = TestCluster {
                hsms,
                realm,
                group: starting_group,
                store,
            };
            cluster.capture_next_and_commit_group(starting_group);
            if count == 1 {
                return cluster;
            }

            let mut members: Vec<_> = cluster
                .hsms
                .iter_mut()
                .map(|hsm| {
                    let r = hsm.status();
                    (r.id, r.realm.unwrap().statement)
                })
                .collect();
            members.sort_by_key(|g| g.0);

            let new_group_resp = cluster.hsms[0].hsm.handle_new_group(
                &mut m,
                NewGroupRequest {
                    realm,
                    members: members.clone(),
                },
            );
            let NewGroupResponse::Ok {
                group: new_group,
                statement,
                entry,
            } = new_group_resp
            else {
                panic!("new group failed: {:?}", new_group_resp);
            };
            cluster
                .store
                .append(new_group, entry, StoreDelta::default());

            let config: Vec<HsmId> = members.iter().map(|(id, _stmt)| *id).collect();
            for hsm in &mut cluster.hsms[1..] {
                assert_eq!(
                    hsm.hsm.handle_join_group(
                        &mut m,
                        JoinGroupRequest {
                            realm,
                            group: new_group,
                            configuration: config.clone(),
                            statement: statement.clone(),
                        },
                    ),
                    JoinGroupResponse::Ok
                );
            }

            let TransferOutResponse::Ok { entry, delta } = cluster.hsms[0].hsm.handle_transfer_out(
                &mut m,
                TransferOutRequest {
                    realm,
                    source: starting_group,
                    destination: new_group,
                    range: OwnedRange::full(),
                    index: LogIndex(1),
                    proof: None,
                },
            ) else {
                panic!("transfer out failed")
            };
            cluster.store.append(starting_group, entry.clone(), delta);

            let partition = entry.transferring_out.as_ref().unwrap().partition.clone();
            let TransferNonceResponse::Ok(nonce) = cluster.hsms[0].hsm.handle_transfer_nonce(
                &mut m,
                TransferNonceRequest {
                    realm,
                    destination: new_group,
                },
            ) else {
                panic!("failed to generate transfer nonce");
            };
            cluster.capture_next_and_commit_group(starting_group);
            cluster.capture_next_and_commit_group(new_group);

            let transfer_stmt = cluster.hsms[0].hsm.handle_transfer_statement(
                &mut m,
                TransferStatementRequest {
                    realm,
                    source: starting_group,
                    destination: new_group,
                    nonce,
                },
            );
            let TransferStatementResponse::Ok(stmt) = transfer_stmt else {
                panic!("failed to generate transfer statement: {transfer_stmt:?}");
            };

            let TransferInResponse::Ok { entry, delta } = cluster.hsms[0].hsm.handle_transfer_in(
                &mut m,
                TransferInRequest {
                    realm,
                    destination: new_group,
                    transferring: partition,
                    proofs: None,
                    nonce,
                    statement: stmt,
                },
            ) else {
                panic!("failed to transfer in");
            };
            cluster.store.append(new_group, entry, delta);

            let CompleteTransferResponse::Ok(entry) = cluster.hsms[0].hsm.handle_complete_transfer(
                &mut m,
                CompleteTransferRequest {
                    realm,
                    source: starting_group,
                    destination: new_group,
                    range: OwnedRange::full(),
                },
            ) else {
                panic!("failed to complete transfer");
            };

            cluster
                .store
                .append(starting_group, entry, StoreDelta::default());
            cluster.capture_next_and_commit_group(starting_group);
            cluster.capture_next_and_commit_group(new_group);

            // We have a group of HSMs all initialized with a group, hsms[0] is the leader.
            cluster.group = new_group;
            cluster
        }

        // Brings each HSM up to date on capture_next and then does a commit.
        fn capture_next_and_commit_group(&mut self, group: GroupId) -> Vec<CommitState> {
            self.capture_next(group);
            self.commit(group)
        }

        fn capture_next(&mut self, group: GroupId) {
            for hsm in self.hsms.iter_mut() {
                if hsm.has_group(group) {
                    hsm.capture_next(&self.store, self.realm, group);
                }
            }
        }

        // Collects captures from all cluster members, and asks every HSM that thinks its a leader
        // for the group to do a commit.
        fn commit(&mut self, group: GroupId) -> Vec<CommitState> {
            let captures: Vec<Captured> = self.persist_state(group);

            let mut results = Vec::new();
            for hsm in self.hsms.iter_mut() {
                if hsm.is_leader(group) {
                    results.push(hsm.commit(self.realm, group, captures.clone()));
                }
            }
            results
        }

        fn persist_state(&mut self, group: GroupId) -> Vec<Captured> {
            self.hsms
                .iter_mut()
                .flat_map(|hsm| {
                    let PersistStateResponse::Ok { captured } = hsm
                        .hsm
                        .handle_persist_state(&mut hsm.metrics, PersistStateRequest {});
                    captured
                })
                .filter(|c| c.group == group)
                .collect()
        }

        fn append(&mut self, group: GroupId, r: &AppResponse) {
            if let AppResponse::Ok {
                entry,
                delta,
                request_type: _,
            } = r
            {
                self.store.append(group, entry.clone(), delta.clone());
            } else {
                panic!("app_request failed {r:?}");
            }
        }
    }

    struct TestHsm<'a> {
        hsm: Hsm<TestPlatform>,
        next_capture: HashMap<(RealmId, GroupId), LogIndex>,
        metrics: Metrics<'a, TestPlatform>,
        public_key: x25519_dalek::PublicKey,
        id: HsmId,
    }

    impl<'a> TestHsm<'a> {
        fn new(name: impl Into<String>, keys: RealmKeys) -> Self {
            let opt = HsmOptions {
                name: name.into(),
                tree_overlay_size: 15,
                max_sessions: 15,
                metrics: MetricsReporting::Disabled,
            };
            let public_key = keys.communication.1;
            let hsm = Hsm::new(opt, TestPlatform::default(), keys).unwrap();
            let id = hsm.persistent.id;
            Self {
                hsm,
                next_capture: HashMap::new(),
                metrics: Metrics::new("test", MetricsAction::Skip, TestPlatform::default()),
                public_key,
                id,
            }
        }

        fn status(&mut self) -> StatusResponse {
            self.hsm
                .handle_status_request(&mut self.metrics, StatusRequest {})
        }

        fn has_group(&mut self, group: GroupId) -> bool {
            self.status()
                .realm
                .is_some_and(|r| r.groups.iter().any(|g| g.id == group))
        }

        fn is_leader(&mut self, group: GroupId) -> bool {
            self.status()
                .realm
                .is_some_and(|r| r.groups.iter().any(|g| g.id == group && g.leader.is_some()))
        }

        fn become_leader(
            &mut self,
            realm: RealmId,
            group: GroupId,
            last_entry: LogEntry,
        ) -> BecomeLeaderResponse {
            self.hsm.handle_become_leader(
                &mut self.metrics,
                BecomeLeaderRequest {
                    realm,
                    group,
                    last_entry,
                },
            )
        }

        fn stepdown_as_leader(&mut self, realm: RealmId, group: GroupId) -> StepDownResponse {
            self.hsm
                .handle_stepdown_as_leader(&mut self.metrics, StepDownRequest { realm, group })
        }

        // Makes a CaptureNext request to the HSM if there are any new log
        // entries to capture. returns the role as returned by capture next. If
        // there were no new log entries to capture returns None.
        fn capture_next(
            &mut self,
            store: &TestStore,
            realm: RealmId,
            group: GroupId,
        ) -> Option<GroupMemberRole> {
            let log = store.group_log(&group);
            let next_capture = self
                .next_capture
                .entry((realm, group))
                .or_insert_with(|| LogIndex::FIRST);

            let offset = (next_capture.0 - log[0].index.0) as usize;
            if log[offset..].is_empty() {
                // nothing new to capture
                return None;
            }
            let r = self.hsm.handle_capture_next(
                &mut self.metrics,
                CaptureNextRequest {
                    realm,
                    group,
                    entries: log[offset..].to_vec(),
                },
            );
            match r {
                CaptureNextResponse::Ok(role) => {
                    *next_capture = log.last().unwrap().index.next();
                    Some(role)
                }
                _ => panic!("capture_next failed: {r:?}"),
            }
        }

        fn commit(
            &mut self,
            realm: RealmId,
            group: GroupId,
            captures: Vec<Captured>,
        ) -> CommitState {
            let r = self.hsm.handle_commit(
                &mut self.metrics,
                CommitRequest {
                    realm,
                    group,
                    captures,
                },
            );
            if let CommitResponse::Ok(state) = r {
                state
            } else {
                panic!("commit failed {r:?}");
            }
        }

        fn app_request(
            &mut self,
            store: &TestStore,
            realm: RealmId,
            group: GroupId,
            record_id: RecordId,
            req: SecretsRequest,
        ) -> (Handshake, AppResponse) {
            let req_bytes = marshalling::to_vec(&req).unwrap();
            let (handshake, req) =
                Handshake::start(&self.public_key, &req_bytes, &mut OsRng).unwrap();

            let last = store.latest_log(&group);
            let partition = last.partition.as_ref().unwrap();
            let proof = store
                .tree
                .read(&partition.range, &partition.root_hash, &record_id)
                .unwrap();

            (
                handshake,
                self.hsm.handle_app(
                    &mut self.metrics,
                    AppRequest {
                        realm,
                        group,
                        record_id,
                        session_id: SessionId(OsRng.next_u32()),
                        encrypted: NoiseRequest::Handshake { handshake: req },
                        proof,
                        index: last.index,
                    },
                ),
            )
        }
    }

    #[derive(Default)]
    struct TestStore {
        logs: HashMap<GroupId, Vec<LogEntry>>,
        tree: MemStore<DataHash>,
    }

    impl TestStore {
        fn append(&mut self, g: GroupId, e: LogEntry, d: StoreDelta<DataHash>) {
            if let Some(p) = &e.partition {
                self.tree.apply_store_delta(p.root_hash, d);
            }
            self.logs.entry(g).or_default().push(e);
        }

        fn group_log(&self, g: &GroupId) -> &[LogEntry] {
            match self.logs.get(g) {
                Some(log) => log.as_slice(),
                None => panic!("no log found for group {g:?}"),
            }
        }

        fn latest_log(&self, g: &GroupId) -> LogEntry {
            self.group_log(g).last().unwrap().clone()
        }
    }

    #[derive(Clone, Default)]
    struct TestPlatform {
        nvram: Arc<Mutex<Vec<u8>>>,
    }

    impl RngCore for TestPlatform {
        fn next_u32(&mut self) -> u32 {
            OsRng.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            OsRng.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            OsRng.fill_bytes(dest)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            OsRng.try_fill_bytes(dest)
        }
    }
    impl CryptoRng for TestPlatform {}

    impl NVRam for TestPlatform {
        fn read(&self) -> Result<Vec<u8>, IOError> {
            Ok(self.nvram.lock().unwrap().clone())
        }

        fn write(&self, data: Vec<u8>) -> Result<(), IOError> {
            *self.nvram.lock().unwrap() = data;
            Ok(())
        }
    }

    impl Clock for TestPlatform {
        type Instant = StdInstant;

        fn now(&self) -> Option<Self::Instant> {
            Some(StdInstant(std::time::Instant::now()))
        }

        fn elapsed(&self, start: Self::Instant) -> Option<Nanos> {
            Some(Nanos(
                start.0.elapsed().as_nanos().try_into().unwrap_or(u32::MAX),
            ))
        }
    }

    struct StdInstant(std::time::Instant);
    impl core::ops::Sub for StdInstant {
        type Output = Nanos;

        fn sub(self, rhs: Self) -> Self::Output {
            Nanos((self.0 - rhs.0).as_nanos().try_into().unwrap_or(u32::MAX))
        }
    }
}
