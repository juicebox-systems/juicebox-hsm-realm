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
use hashbrown::hash_map::Entry;
use serde::ser::SerializeTuple;
use serde::{Deserialize, Serialize};
use tracing::{info, trace, warn};
use x25519_dalek as x25519;

mod app;
pub mod cache;
pub mod commit;
mod configuration;
pub mod mac;
pub mod rpc;
pub mod types;

use self::mac::{
    CapturedStatementMessage, CtMac, EntryMacMessage, GroupConfigurationStatementMessage,
    HsmRealmStatementMessage, MacKey, TransferStatementMessage,
};
use super::hal::{Clock, CryptoRng, IOError, NVRam, Nanos, Platform};
use super::merkle::{
    agent::StoreDelta,
    proof::{ProofError, ReadProof, VerifiedProof},
    MergeError, NodeHasher, Tree,
};
use super::mutation::{MutationTracker, OnMutationFinished};
use crate::hash::{HashExt, HashMap};
use app::RecordChange;
use configuration::GroupConfiguration;
use juicebox_sdk_core::{
    requests::{NoiseRequest, NoiseResponse, SecretsRequest, SecretsResponse, BODY_SIZE_LIMIT},
    types::{RealmId, SessionId},
};
use juicebox_sdk_marshalling::{self as marshalling, bytes, DeserializationError};
use juicebox_sdk_noise::server as noise;
use rpc::{HsmRequest, HsmRequestContainer, HsmResponseContainer, HsmRpc, MetricsAction};
use types::{
    AppRequest, AppRequestType, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse,
    CaptureNextRequest, CaptureNextResponse, Captured, CompleteTransferRequest,
    CompleteTransferResponse, DataHash, EntryMac, GroupId, GroupMemberRole, GroupStatus,
    HandshakeRequest, HandshakeResponse, HsmId, HsmRealmStatement, JoinGroupRequest,
    JoinGroupResponse, JoinRealmRequest, JoinRealmResponse, LeaderStatus, LogEntry, LogIndex,
    NewGroupRequest, NewGroupResponse, NewRealmRequest, NewRealmResponse, OwnedRange, Partition,
    PersistStateRequest, PersistStateResponse, PublicKey, RealmStatus, RecordId, StatusRequest,
    StatusResponse, StepDownRequest, StepDownResponse, TransferInRequest, TransferInResponse,
    TransferNonce, TransferNonceRequest, TransferNonceResponse, TransferOutRequest,
    TransferOutResponse, TransferStatementRequest, TransferStatementResponse, TransferringOut,
    CONFIGURATION_LIMIT, GROUPS_LIMIT,
};

// TODO: This is susceptible to DoS attacks. One user could create many
// sessions to evict all other users' Noise connections, or one attacker could
// collect many (currently 511) user accounts to evict all other connections.
type SessionCache = cache::Cache<
    (RecordId, SessionId),
    noise::Transport,
    cache::LogicalClock,
    crate::hash::RandomState,
>;

/// Returned in Noise handshake requests as a hint to the client of how long it
/// should reuse an inactive session.
///
/// The agent or load balancer could override this default with a more
/// sophisticated estimate, so it's OK for this to be a constant here.
const SESSION_LIFETIME: Duration = Duration::from_secs(5);

impl GroupId {
    fn random(rng: &mut impl CryptoRng) -> Self {
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        Self(id)
    }
}

impl HsmId {
    fn random(rng: &mut impl CryptoRng) -> Self {
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        Self(id)
    }
}

fn create_random_realm_id(rng: &mut impl CryptoRng) -> RealmId {
    let mut id = [0u8; 16];
    rng.fill_bytes(&mut id);
    RealmId(id)
}

struct LogEntryBuilder {
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
            realm: self.realm,
            group: self.group,
            index: self.index,
            partition: &self.partition,
            transferring_out: &self.transferring_out,
            prev_mac: &self.prev_mac,
        });

        LogEntry {
            index: self.index,
            partition: self.partition,
            transferring_out: self.transferring_out,
            prev_mac: self.prev_mac,
            entry_mac,
        }
    }
}

impl TransferNonce {
    pub fn random(rng: &mut impl CryptoRng) -> Self {
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        Self(nonce)
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
#[derive(Serialize)]
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

pub enum MetricsReporting {
    // If disabled, then per request metrics won't be reported back to the agent
    // even if the request asks for them.
    Disabled,
    Enabled,
}

pub struct HsmOptions {
    pub name: String,
    pub tree_overlay_size: u16,
    pub max_sessions: u16,
    // Metrics should be set to Disabled for production deployments.
    pub metrics: MetricsReporting,
}

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
    log: VecDeque<LeaderLogEntry>, // never empty
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
            log: VecDeque::from([LeaderLogEntry {
                entry: last_entry,
                response: None,
            }]),
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
    log: VecDeque<LeaderLogEntry>,
    committed: Option<LogIndex>,
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
                let hsm_id = HsmId::random(&mut platform);
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
                                    .back()
                                    .expect("leader's log is never empty")
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
            let group = GroupId::random(&mut self.platform);

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
                request.members.iter().map(|(id, _)| *id).collect::<Vec<HsmId>>(),
                &self.persistent.id,
            ) else {
                return Response::InvalidConfiguration;
            };

            let group = GroupId::random(&mut self.platform);
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

    fn handle_capture_next(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: CaptureNextRequest,
    ) -> CaptureNextResponse {
        type Response = CaptureNextResponse;
        trace!(hsm = self.options.name, ?request);

        let response = (|| {
            if request.entries.is_empty() {
                return Response::MissingEntries;
            }

            match &self.persistent.realm {
                None => Response::InvalidRealm,

                Some(realm) => {
                    if realm.id != request.realm {
                        return Response::InvalidRealm;
                    }

                    if realm.groups.get(&request.group).is_none() {
                        return Response::InvalidGroup;
                    }

                    for entry in request.entries {
                        if self
                            .realm_keys
                            .mac
                            .log_entry_mac(&EntryMacMessage::new(
                                request.realm,
                                request.group,
                                &entry,
                            ))
                            .verify(&entry.entry_mac)
                            .is_err()
                        {
                            return Response::InvalidMac;
                        }

                        let e = self.volatile.captured.entry(request.group);
                        match &e {
                            Entry::Vacant(_) => {
                                if entry.index != LogIndex::FIRST {
                                    return Response::MissingPrev;
                                }
                                if entry.prev_mac != EntryMac::zero() {
                                    return Response::InvalidChain;
                                }
                            }
                            Entry::Occupied(v) => {
                                let (captured_index, captured_mac) = v.get();
                                if entry.index != captured_index.next() {
                                    return Response::MissingPrev;
                                }
                                if entry.prev_mac != *captured_mac {
                                    return Response::InvalidChain;
                                }
                            }
                        }

                        // If we're stepping down we need to get the commit
                        // index up to the stepping down index. It's not
                        // possible for the agent to create a commit request
                        // with that exact index as the witnesses may have
                        // already passed the index and they can't generate a
                        // capture statement for an earlier index. So while
                        // stepping down we collect the new log entries that
                        // we're witnessing into the stepping down log. Commit
                        // can then successfully process a commit request that
                        // is after the stepdown index and complete the
                        // stepdown.
                        if let Some(sd) = self.volatile.stepping_down.get_mut(&request.group) {
                            let last = &sd.log.back().unwrap().entry;
                            if entry.index == last.index.next() && entry.prev_mac == last.entry_mac
                            {
                                sd.log.push_back(LeaderLogEntry {
                                    entry: entry.clone(),
                                    response: None,
                                });
                            }
                        }
                        e.insert((entry.index, entry.entry_mac));
                    }
                    Response::Ok
                }
            }
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
        let Some(leader) = self.volatile.leader.remove(&request.group) else {
            return Response::NotLeader;
        };
        let stepdown_index = leader.log.back().unwrap().entry.index;
        match leader.committed {
            Some(c) if c == stepdown_index => Response::Complete {
                last: stepdown_index,
            },
            _ => {
                self.volatile.stepping_down.insert(
                    request.group,
                    SteppingDownVolatileGroupState {
                        log: leader.log,
                        committed: leader.committed,
                        stepdown_at: stepdown_index,
                    },
                );
                Response::InProgress {
                    last: stepdown_index,
                }
            }
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

            let last_entry = &leader.log.back().unwrap().entry;

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

            leader.log.push_back(LeaderLogEntry {
                entry: entry.clone(),
                response: None,
            });

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

            let nonce = TransferNonce::random(&mut self.platform);
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
            }) = &leader.log.back().unwrap().entry.transferring_out else {
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

            let last_entry = &leader.log.back().unwrap().entry;
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
                realm: request.realm,
                group: request.destination,
                index: last_entry.index.next(),
                partition: Some(partition.clone()),
                transferring_out: last_entry.transferring_out.clone(),
                prev_mac: last_entry.entry_mac.clone(),
            }
            .build(&self.realm_keys.mac);

            leader.log.push_back(LeaderLogEntry {
                entry: entry.clone(),
                response: None,
            });

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

            let last_entry = &leader.log.back().unwrap().entry;
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
                realm: request.realm,
                group: request.source,
                index: last_entry.index.next(),
                partition: last_entry.partition.clone(),
                transferring_out: None,
                prev_mac: last_entry.entry_mac.clone(),
            }
            .build(&self.realm_keys.mac);

            leader.log.push_back(LeaderLogEntry {
                entry: entry.clone(),
                response: None,
            });

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
                        if (leader.log.back().unwrap().entry)
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
        let hsm_name = &self.options.name;

        let start = metrics.now();
        let mut app_req_name = None;

        let response = match &self.persistent.realm {
            Some(realm) if realm.id == request.realm => {
                if realm.groups.contains_key(&request.group) {
                    if let Some(leader) = self.volatile.leader.get_mut(&request.group) {
                        if (leader.log.back().unwrap().entry)
                            .partition
                            .as_ref()
                            .filter(|partition| partition.range.contains(&request.record_id))
                            .is_some()
                        {
                            let app_ctx = app::AppContext { hsm_name };
                            handle_app_request(
                                &app_ctx,
                                request,
                                &self.realm_keys,
                                leader,
                                &mut app_req_name,
                                &mut self.platform,
                            )
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

        metrics.record(app_req_name.unwrap_or("App::unknown"), start);
        trace!(hsm = self.options.name, ?response);
        response
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
    app_ctx: &app::AppContext,
    request: AppRequest,
    keys: &RealmKeys,
    leader: &mut LeaderVolatileGroupState,
    req_name_out: &mut Option<&'static str>,
    rng: &mut dyn CryptoRng,
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

    let (secrets_response, change) = app::process(
        app_ctx,
        &request.record_id,
        secrets_request,
        record.as_deref(),
    );

    let secrets_response = noise.encode(secrets_response, &mut leader.sessions);

    let (root_hash, store_delta) = merkle.update_overlay(rng, change);

    let last_entry = leader.log.back().unwrap();
    let new_entry = LogEntryBuilder {
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

    leader.log.push_back(LeaderLogEntry {
        entry: new_entry.clone(),
        response: Some(secrets_response),
    });
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
        rng: &mut dyn CryptoRng,
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
        rng: &mut dyn CryptoRng,
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

#[cfg(test)]
mod test {
    use crate::hash::HashMap;
    use juicebox_sdk_core::types::RealmId;
    use juicebox_sdk_marshalling as marshalling;

    use super::super::bitvec;
    use super::super::hal::MAX_NVRAM_SIZE;
    use super::super::merkle::agent::StoreKey;
    use super::super::merkle::testing::rec_id;
    use super::super::merkle::NodeHashBuilder;
    use super::types::{DataHash, EntryMac, GroupId, HsmId, LogIndex, CONFIGURATION_LIMIT};
    use super::*;

    #[test]
    fn test_store_key_parse_data_hash() {
        let prefix = bitvec![0, 1, 1, 1];
        let hash = NodeHashBuilder::<MerkleHasher>::Leaf(&rec_id(&[1]), &[1, 2, 3, 4]).build();

        let sk = StoreKey::new(&prefix, &hash);
        match StoreKey::parse::<DataHash>(&sk.into_bytes()) {
            None => panic!("should have decoded store key"),
            Some((_p, h)) => {
                assert_eq!(h, hash);
            }
        }
    }

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
}
