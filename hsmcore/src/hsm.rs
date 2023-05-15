extern crate alloc;

use alloc::borrow::Cow;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use blake2::Blake2s256;
use chacha20poly1305::aead::Aead;
use core::fmt::{self, Debug};
use core::time::Duration;
use digest::Digest;
use hashbrown::{hash_map::Entry, HashMap}; // TODO: randomize hasher
use hkdf::Hkdf;
use hmac::{Mac, SimpleHmac};
use serde::{Deserialize, Serialize};
use tracing::{info, trace, warn};
use x25519_dalek as x25519;

mod app;
mod cache;
pub mod commit;
pub mod rpc;
pub mod types;

use super::hal::{Clock, CryptoRng, IOError, NVRam, Nanos, Platform};
use super::merkle::{
    agent::StoreDelta,
    proof::{ProofError, ReadProof, VerifiedProof},
    MergeError, NodeHasher, Tree,
};
use super::mutation::{MutationTracker, OnMutationFinished};
use app::RecordChange;
use cache::Cache;
use loam_sdk_core::{
    requests::{NoiseRequest, NoiseResponse, SecretsRequest, SecretsResponse, BODY_SIZE_LIMIT},
    types::{RealmId, SessionId},
    {marshalling, marshalling::DeserializationError},
};
use loam_sdk_noise::server as noise;
use rpc::{HsmRequest, HsmRequestContainer, HsmResponseContainer, HsmRpc, MetricsAction};
use types::{
    AppError, AppRequest, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse,
    CaptureNextRequest, CaptureNextResponse, Captured, CapturedStatement, CompleteTransferRequest,
    CompleteTransferResponse, Configuration, DataHash, EntryHmac, GroupConfigurationStatement,
    GroupId, GroupMemberRole, GroupStatus, HandshakeRequest, HandshakeResponse, HsmId,
    JoinGroupRequest, JoinGroupResponse, JoinRealmRequest, JoinRealmResponse, LeaderStatus,
    LogEntry, LogIndex, NewGroupInfo, NewGroupRequest, NewGroupResponse, NewRealmRequest,
    NewRealmResponse, OwnedRange, Partition, PersistStateRequest, PersistStateResponse,
    RealmStatus, RecordId, StatusRequest, StatusResponse, StepDownRequest, StepDownResponse,
    TransferInRequest, TransferInResponse, TransferNonce, TransferNonceRequest,
    TransferNonceResponse, TransferOutRequest, TransferOutResponse, TransferStatement,
    TransferStatementRequest, TransferStatementResponse, TransferringOut,
};

/// Returned in Noise handshake requests as a hint to the client of how long
/// they should reuse an inactive session.
///
/// The agent or load balancer could override this default with a more
/// sophisticated estimate, so it's OK for this to be a constant here.
const SESSION_LIFETIME: Duration = Duration::from_secs(5);

#[derive(Clone, Deserialize, Serialize)]
pub struct MacKey(digest::Key<SimpleHmac<Blake2s256>>);

impl fmt::Debug for MacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

impl MacKey {
    pub fn from(v: [u8; 64]) -> Self {
        let mut key = digest::Key::<SimpleHmac<Blake2s256>>::default();
        key.copy_from_slice(&v);
        Self(key)
    }

    pub fn random(rng: &mut impl CryptoRng) -> Self {
        let mut key = digest::Key::<SimpleHmac<Blake2s256>>::default();
        rng.fill_bytes(&mut key);
        Self(key)
    }
    // derive a realmKey from the supplied input.
    // TODO, ensure this goes away.
    pub fn derive_from(b: &[u8]) -> Self {
        let kdf = Hkdf::<Blake2s256, SimpleHmac<Blake2s256>>::new(Some(b"worlds worst secret"), b);
        let mut out = [0u8; 64];
        kdf.expand(&[], &mut out).unwrap();
        Self(out.into())
    }
}

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

impl Configuration {
    /// Checks that the configuration is non-empty and that the HSM IDs are
    /// sorted and unique.
    fn is_ok(&self) -> bool {
        if self.0.is_empty() {
            return false;
        }
        let mut pairwise = self.0.iter().zip(self.0.iter().skip(1));
        pairwise.all(|(a, b)| a < b)
    }
}

struct GroupConfigurationStatementBuilder<'a> {
    realm: RealmId,
    group: GroupId,
    configuration: &'a Configuration,
}

impl<'a> GroupConfigurationStatementBuilder<'a> {
    fn calculate(&self, key: &MacKey) -> SimpleHmac<Blake2s256> {
        let mut mac = SimpleHmac::<Blake2s256>::new(&key.0);
        mac.update(b"group configuration|");
        mac.update(&self.realm.0);
        mac.update(b"|");
        mac.update(&self.group.0);
        for hsm_id in &self.configuration.0 {
            mac.update(b"|");
            mac.update(&hsm_id.0);
        }
        mac
    }

    fn build(&self, key: &MacKey) -> GroupConfigurationStatement {
        GroupConfigurationStatement(self.calculate(key).finalize().into_bytes())
    }

    fn verify(
        &self,
        key: &MacKey,
        statement: &GroupConfigurationStatement,
    ) -> Result<(), digest::MacError> {
        self.calculate(key).verify(&statement.0)
    }
}

struct CapturedStatementBuilder<'a> {
    hsm: HsmId,
    realm: RealmId,
    group: GroupId,
    index: LogIndex,
    entry_hmac: &'a EntryHmac,
}

impl<'a> CapturedStatementBuilder<'a> {
    fn calculate(&self, key: &MacKey) -> SimpleHmac<Blake2s256> {
        let mut mac = SimpleHmac::<Blake2s256>::new(&key.0);
        mac.update(b"captured|");
        mac.update(&self.hsm.0);
        mac.update(b"|");
        mac.update(&self.realm.0);
        mac.update(b"|");
        mac.update(&self.group.0);
        mac.update(b"|");
        mac.update(&self.index.0.to_be_bytes());
        mac.update(b"|");
        mac.update(&self.entry_hmac.0);
        mac
    }

    fn build(&self, key: &MacKey) -> CapturedStatement {
        CapturedStatement(self.calculate(key).finalize().into_bytes())
    }

    fn verify(&self, key: &MacKey, statement: &CapturedStatement) -> Result<(), digest::MacError> {
        self.calculate(key).verify(&statement.0)
    }
}

struct EntryHmacBuilder<'a> {
    realm: RealmId,
    group: GroupId,
    index: LogIndex,
    partition: &'a Option<Partition>,
    transferring_out: &'a Option<TransferringOut>,
    prev_hmac: &'a EntryHmac,
}

impl<'a> EntryHmacBuilder<'a> {
    fn calculate(&self, key: &MacKey) -> SimpleHmac<Blake2s256> {
        let mut mac = SimpleHmac::<Blake2s256>::new(&key.0);
        mac.update(b"entry|");
        mac.update(&self.realm.0);
        mac.update(b"|");
        mac.update(&self.group.0);
        mac.update(b"|");
        mac.update(&self.index.0.to_be_bytes());
        mac.update(b"|");

        match self.partition {
            Some(p) => {
                mac.update(&p.range.start.0);
                mac.update(b"|");
                mac.update(&p.range.end.0);
                mac.update(b"|");
                mac.update(&p.root_hash.0);
            }
            None => mac.update(b"none|none|none"),
        }

        mac.update(b"|");

        match self.transferring_out {
            Some(TransferringOut {
                destination,
                partition,
                at,
            }) => {
                mac.update(&destination.0);
                mac.update(b"|");
                mac.update(&partition.range.start.0);
                mac.update(b"|");
                mac.update(&partition.range.end.0);
                mac.update(b"|");
                mac.update(&partition.root_hash.0);
                mac.update(b"|");
                mac.update(&at.0.to_be_bytes());
            }
            None => {
                mac.update(b"none|none|none|none|none");
            }
        }

        mac.update(b"|");
        mac.update(&self.prev_hmac.0);
        mac
    }

    fn build(&self, key: &MacKey) -> EntryHmac {
        EntryHmac(self.calculate(key).finalize().into_bytes())
    }

    fn verify(&self, key: &MacKey, hmac: &EntryHmac) -> Result<(), digest::MacError> {
        self.calculate(key).verify(&hmac.0)
    }

    fn verify_entry(
        key: &MacKey,
        realm: RealmId,
        group: GroupId,
        entry: &'a LogEntry,
    ) -> Result<(), digest::MacError> {
        Self {
            realm,
            group,
            index: entry.index,
            partition: &entry.partition,
            transferring_out: &entry.transferring_out,
            prev_hmac: &entry.prev_hmac,
        }
        .verify(key, &entry.entry_hmac)
    }
}

impl TransferNonce {
    pub fn random(rng: &mut impl CryptoRng) -> Self {
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        Self(nonce)
    }
}

struct TransferStatementBuilder<'a> {
    realm: RealmId,
    partition: &'a Partition,
    destination: GroupId,
    nonce: TransferNonce,
}

impl<'a> TransferStatementBuilder<'a> {
    fn calculate(&self, key: &MacKey) -> SimpleHmac<Blake2s256> {
        let mut mac = SimpleHmac::<Blake2s256>::new(&key.0);
        mac.update(b"transfer|");
        mac.update(&self.realm.0);
        mac.update(b"|");
        mac.update(&self.partition.range.start.0);
        mac.update(b"|");
        mac.update(&self.partition.range.end.0);
        mac.update(b"|");
        mac.update(&self.partition.root_hash.0);
        mac.update(b"|");
        mac.update(&self.destination.0);
        mac.update(b"|");
        mac.update(&self.nonce.0);
        mac
    }

    fn build(&self, key: &MacKey) -> TransferStatement {
        TransferStatement(self.calculate(key).finalize().into_bytes())
    }

    fn verify(&self, key: &MacKey, statement: &TransferStatement) -> Result<(), digest::MacError> {
        self.calculate(key).verify(&statement.0)
    }
}

pub struct MerkleHasher();
impl NodeHasher<DataHash> for MerkleHasher {
    fn calc_hash(&self, parts: &[&[u8]]) -> DataHash {
        let mut h = Blake2s256::new();
        for p in parts {
            h.update([b'|']); //delim all the parts
            h.update(p);
        }
        DataHash(h.finalize())
    }
}

/// A private key used to encrypt/decrypt record values.
pub struct RecordEncryptionKey([u8; 32]);

impl RecordEncryptionKey {
    pub fn from(v: [u8; 32]) -> Self {
        Self(v)
    }

    fn derive_from(realm_key: &MacKey) -> Self {
        // generated from /dev/random
        let salt = [
            0x61u8, 0x33, 0xcf, 0xf6, 0xf6, 0x70, 0x27, 0xd2, 0x0c, 0x3d, 0x8b, 0x42, 0x5a, 0x21,
            0xeb, 0xb2, 0x6b, 0x91, 0x0a, 0x97, 0x5c, 0xee, 0xfa, 0x57, 0xf7, 0x76, 0x5d, 0x96,
            0x49, 0xa4, 0xd3, 0xd6,
        ];
        let info = "record".as_bytes();
        let hk = Hkdf::<Blake2s256, SimpleHmac<Blake2s256>>::new(Some(&salt), &realm_key.0);
        let mut out = [0u8; 32];
        hk.expand(info, &mut out).unwrap();
        Self(out)
    }
}

pub struct Hsm<P: Platform> {
    platform: P,
    options: HsmOptions,
    persistent: MutationTracker<PersistentState, NVRamWriter<P>>,
    volatile: VolatileState,
    realm_keys: RealmKeys,
}

pub struct HsmOptions {
    pub name: String,
    pub tree_overlay_size: u16,
    pub max_sessions: u16,
}

pub struct RealmKeys {
    pub communication: (x25519::StaticSecret, x25519::PublicKey),
    pub record: RecordEncryptionKey,
    pub mac: MacKey,
}

#[derive(Deserialize, Serialize)]
struct PersistentState {
    id: HsmId,
    realm: Option<PersistentRealmState>,
}

#[derive(Deserialize, Serialize)]
struct PersistentRealmState {
    id: RealmId,
    groups: HashMap<GroupId, PersistentGroupState>,
}

#[derive(Clone, Deserialize, Serialize)]
struct PersistentGroupState {
    configuration: Configuration,
    captured: Option<(LogIndex, EntryHmac)>,
}

struct VolatileState {
    leader: HashMap<GroupId, LeaderVolatileGroupState>,
    captured: HashMap<GroupId, (LogIndex, EntryHmac)>,
    // A Group can be in leader, stepping_down or neither. Its never in both leader & stepping_down.
    stepping_down: HashMap<GroupId, SteppingDownVolatileGroupState>,
}

struct LeaderVolatileGroupState {
    log: VecDeque<LeaderLogEntry>, // never empty
    committed: Option<LogIndex>,
    incoming: Option<TransferNonce>,
    /// This is `Some` if and only if the last entry in `log` owns a partition.
    tree: Option<Tree<MerkleHasher, DataHash>>,
    sessions: Cache<(RecordId, SessionId), noise::Transport>,
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
    InvalidSignature,
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
}
impl<N: NVRam> OnMutationFinished<PersistentState> for NVRamWriter<N> {
    fn finished(&self, state: &PersistentState) {
        // TODO, which if any of the keys in self.persistent should be written out here vs read from the HSM
        // key store at initialization time.
        let mut data = marshalling::to_vec(&state).expect("failed to serialize state");
        let d = Blake2s256::digest(&data);
        data.extend(d);
        self.nvram.write(data).expect("Write to NVRam failed")
    }
}

impl RealmKeys {
    // TODO: This is an insecure placeholder.
    pub fn insecure_derive(k: MacKey) -> Self {
        let communication = {
            // TODO: This is an insecure placeholder.
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&k.0[..32]);
            let secret = x25519::StaticSecret::from(buf);
            let public = x25519::PublicKey::from(&secret);
            (secret, public)
        };
        let record = RecordEncryptionKey::derive_from(&k);
        RealmKeys {
            communication,
            record,
            mac: k,
        }
    }
}

impl<P: Platform> Hsm<P> {
    pub fn new(
        options: HsmOptions,
        mut platform: P,
        realm_keys: RealmKeys,
    ) -> Result<Self, PersistenceError> {
        let writer = NVRamWriter {
            nvram: platform.clone(),
        };
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

        let captured: HashMap<GroupId, (LogIndex, EntryHmac)> = persistent
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

        // TODO: We need to ensure that metrics can't be enabled on production builds for HSMs.
        let metrics = Metrics::new(req_name, request.metrics, self.platform.clone());

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
            return Err(PersistenceError::InvalidSignature);
        }
        let (data, stored_digest) = d.split_at(d.len() - Blake2s256::output_size());
        let calced_digest = Blake2s256::digest(data);
        if stored_digest == calced_digest.as_slice() {
            match marshalling::from_slice(data) {
                Ok(state) => Ok(Some(state)),
                Err(e) => Err(PersistenceError::Deserialization(e)),
            }
        } else {
            Err(PersistenceError::InvalidSignature)
        }
    }

    fn create_new_group(
        &mut self,
        realm: RealmId,
        configuration: Configuration,
        owned_range: Option<OwnedRange>,
    ) -> NewGroupInfo {
        let group = GroupId::random(&mut self.platform);
        let statement = GroupConfigurationStatementBuilder {
            realm,
            group,
            configuration: &configuration,
        }
        .build(&self.realm_keys.mac);

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

        let index = LogIndex::FIRST;
        let (partition, data) = match &owned_range {
            None => (None, StoreDelta::default()),
            Some(key_range) => {
                let h = MerkleHasher();
                let (root_hash, delta) = Tree::new_tree(&h, key_range);
                (
                    Some(Partition {
                        range: key_range.clone(),
                        root_hash,
                    }),
                    delta,
                )
            }
        };
        let transferring_out = None;
        let prev_hmac = EntryHmac::zero();

        let entry_hmac = EntryHmacBuilder {
            realm,
            group,
            index,
            partition: &partition,
            transferring_out: &transferring_out,
            prev_hmac: &prev_hmac,
        }
        .build(&self.realm_keys.mac);

        let entry = LogEntry {
            index,
            partition: partition.clone(),
            transferring_out,
            prev_hmac,
            entry_hmac,
        };

        self.volatile.leader.insert(
            group,
            LeaderVolatileGroupState {
                log: VecDeque::from([LeaderLogEntry {
                    entry: entry.clone(),
                    response: None,
                }]),
                committed: None,
                incoming: None,
                tree: partition.as_ref().map(|p| {
                    Tree::with_existing_root(
                        MerkleHasher(),
                        p.root_hash,
                        self.options.tree_overlay_size,
                    )
                }),
                sessions: Cache::new(usize::from(self.options.max_sessions)),
            },
        );

        NewGroupInfo {
            realm,
            group,
            statement,
            entry,
            delta: data,
        }
    }

    fn handle_status_request(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: StatusRequest,
    ) -> StatusResponse {
        trace!(hsm = self.options.name, ?request);
        let response =
            StatusResponse {
                id: self.persistent.id,
                public_key: self.realm_keys.communication.1.as_bytes().to_vec(),
                realm: self.persistent.realm.as_ref().map(|realm| RealmStatus {
                    id: realm.id,
                    groups: realm
                        .groups
                        .iter()
                        .map(|(group_id, group)| {
                            let configuration = group.configuration.clone();
                            let captured = group.captured.clone();
                            GroupStatus {
                                id: *group_id,
                                configuration,
                                captured,
                                leader: self.volatile.leader.get(group_id).map(|leader| {
                                    LeaderStatus {
                                        committed: leader.committed,
                                        owned_range: leader
                                            .log
                                            .back()
                                            .expect("leader's log is never empty")
                                            .entry
                                            .partition
                                            .as_ref()
                                            .map(|p| p.range.clone()),
                                    }
                                }),
                                role: match self.volatile.leader.get(group_id) {
                                    Some(_) => GroupMemberRole::Leader,
                                    None => match self.volatile.stepping_down.get(group_id) {
                                        Some(_) => GroupMemberRole::SteppingDown,
                                        None => GroupMemberRole::Witness,
                                    },
                                },
                            }
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
        } else if !request.configuration.is_ok()
            || !request.configuration.0.contains(&self.persistent.id)
        {
            Response::InvalidConfiguration
        } else {
            let realm_id = create_random_realm_id(&mut self.platform);
            self.persistent.mutate().realm = Some(PersistentRealmState {
                id: realm_id,
                groups: HashMap::new(),
            });
            let group_info =
                self.create_new_group(realm_id, request.configuration, Some(OwnedRange::full()));
            Response::Ok(group_info)
        };
        trace!(hsm = self.options.name, ?response);
        response
    }

    fn handle_join_realm(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: JoinRealmRequest,
    ) -> JoinRealmResponse {
        trace!(hsm = self.options.name, ?request);

        let response = match &self.persistent.realm {
            Some(realm) => {
                if realm.id == request.realm {
                    JoinRealmResponse::Ok {
                        hsm: self.persistent.id,
                    }
                } else {
                    JoinRealmResponse::HaveOtherRealm
                }
            }
            None => {
                let mut persistent = self.persistent.mutate();
                persistent.realm = Some(PersistentRealmState {
                    id: request.realm,
                    groups: HashMap::new(),
                });
                JoinRealmResponse::Ok { hsm: persistent.id }
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

        let Some(realm) = &self.persistent.realm else {
            trace!(hsm = self.options.name, response = ?Response::InvalidRealm);
            return Response::InvalidRealm;
        };

        let response = if realm.id != request.realm {
            Response::InvalidRealm
        } else if !request.configuration.is_ok()
            || !request.configuration.0.contains(&self.persistent.id)
        {
            Response::InvalidConfiguration
        } else {
            let owned_range: Option<OwnedRange> = None;
            let group_info =
                self.create_new_group(request.realm, request.configuration, owned_range);
            Response::Ok(group_info)
        };
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
            match &self.persistent.realm {
                None => return Response::InvalidRealm,

                Some(realm) => {
                    if realm.id != request.realm {
                        return Response::InvalidRealm;
                    } else if (GroupConfigurationStatementBuilder {
                        realm: request.realm,
                        group: request.group,
                        configuration: &request.configuration,
                    })
                    .verify(&self.realm_keys.mac, &request.statement)
                    .is_err()
                    {
                        return Response::InvalidStatement;
                    } else if !request.configuration.is_ok()
                        || !request.configuration.0.contains(&self.persistent.id)
                    {
                        return Response::InvalidConfiguration;
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
                    configuration: request.configuration,
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
                        if EntryHmacBuilder::verify_entry(
                            &self.realm_keys.mac,
                            request.realm,
                            request.group,
                            &entry,
                        )
                        .is_err()
                        {
                            return Response::InvalidHmac;
                        }

                        let e = self.volatile.captured.entry(request.group);
                        match &e {
                            Entry::Vacant(_) => {
                                if entry.index != LogIndex::FIRST {
                                    return Response::MissingPrev;
                                }
                                if entry.prev_hmac != EntryHmac::zero() {
                                    return Response::InvalidChain;
                                }
                            }
                            Entry::Occupied(v) => {
                                let (captured_index, captured_hmac) = v.get();
                                if entry.index != captured_index.next() {
                                    return Response::MissingPrev;
                                }
                                if entry.prev_hmac != *captured_hmac {
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
                            if entry.index == last.index.next()
                                && entry.prev_hmac == last.entry_hmac
                            {
                                sd.log.push_back(LeaderLogEntry {
                                    entry: entry.clone(),
                                    response: None,
                                });
                            }
                        }
                        e.insert((entry.index, entry.entry_hmac));
                    }
                    Response::Ok {
                        hsm_id: self.persistent.id,
                    }
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
            let config = match &self.persistent.realm {
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
                            Some((captured_index, captured_hmac)) => {
                                if request.last_entry.index != *captured_index
                                    || request.last_entry.entry_hmac != *captured_hmac
                                {
                                    return Response::NotCaptured {
                                        have: Some(*captured_index),
                                    };
                                }
                                if EntryHmacBuilder::verify_entry(
                                    &self.realm_keys.mac,
                                    request.realm,
                                    request.group,
                                    &request.last_entry,
                                )
                                .is_err()
                                {
                                    return Response::InvalidHmac;
                                }
                                group.configuration.clone()
                            }
                        },
                    }
                }
            };

            let tree = request.last_entry.partition.as_ref().map(|p| {
                Tree::with_existing_root(
                    MerkleHasher(),
                    p.root_hash,
                    self.options.tree_overlay_size,
                )
            });

            self.volatile
                .leader
                .entry(request.group)
                .or_insert_with(|| LeaderVolatileGroupState {
                    log: VecDeque::from([LeaderLogEntry {
                        entry: request.last_entry,
                        response: None,
                    }]),
                    committed: None,
                    incoming: None,
                    tree,
                    sessions: Cache::new(usize::from(self.options.max_sessions)),
                });

            Response::Ok { config }
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
                    group_state.captured.as_ref().map(|(index, entry_hmac)| {
                        let statement = CapturedStatementBuilder {
                            hsm: state.id,
                            realm: r.id,
                            group: *group,
                            index: *index,
                            entry_hmac,
                        }
                        .build(&self.realm_keys.mac);
                        Captured {
                            group: *group,
                            hsm: state.id,
                            realm: r.id,
                            index: *index,
                            hmac: entry_hmac.clone(),
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
                for (group_id, (index, hmac)) in &self.volatile.captured {
                    if let Some(g) = realm.groups.get_mut(group_id) {
                        g.captured = Some((*index, hmac.clone()));
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
            };

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

            // TODO: This will always return StaleIndex if we're pipelining
            // changes while transferring ownership. We need to bring
            // `request.data` forward by applying recent changes to it.
            if request.index != last_entry.index {
                return Response::StaleIndex;
            }

            // This support two options: moving out the entire owned range or
            // splitting the range in 2 at some key and moving out one of the
            // halves.
            let keeping_partition: Option<Partition>;
            let transferring_partition: Partition;
            let delta;

            if request.range == owned_partition.range {
                keeping_partition = None;
                transferring_partition = owned_partition.clone();
                delta = StoreDelta::default();
            } else {
                match owned_partition.range.split_at(&request.range) {
                    None => return Response::NotOwner,
                    Some(key) => {
                        if key != request.proof.key {
                            return Response::NotOwner;
                        }
                    }
                }
                let Some(tree) = leader.tree.take() else {
                    return Response::NotLeader;
                };
                let (keeping, transferring, split_delta) = match tree.range_split(request.proof) {
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

            let index = last_entry.index.next();
            let transferring_out = Some(TransferringOut {
                destination: request.destination,
                partition: transferring_partition,
                at: index,
            });
            let prev_hmac = last_entry.entry_hmac.clone();

            let entry_hmac = EntryHmacBuilder {
                realm: request.realm,
                group: request.source,
                index,
                partition: &keeping_partition,
                transferring_out: &transferring_out,
                prev_hmac: &prev_hmac,
            }
            .build(&self.realm_keys.mac);

            leader.tree = keeping_partition.as_ref().map(|p| {
                Tree::with_existing_root(
                    MerkleHasher(),
                    p.root_hash,
                    self.options.tree_overlay_size,
                )
            });

            let entry = LogEntry {
                index,
                partition: keeping_partition,
                transferring_out,
                prev_hmac,
                entry_hmac,
            };

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
            };

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
            };

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

            let statement = TransferStatementBuilder {
                realm: request.realm,
                destination: *destination,
                partition,
                nonce: request.nonce,
            }
            .build(&self.realm_keys.mac);

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
            };

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

            if (TransferStatementBuilder {
                realm: request.realm,
                destination: request.destination,
                partition: &request.transferring,
                nonce: request.nonce,
            })
            .verify(&self.realm_keys.mac, &request.statement)
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

            let index = last_entry.index.next();
            let partition_hash = partition.root_hash;
            let partition = Some(partition);
            let transferring_out = last_entry.transferring_out.clone();
            let prev_hmac = last_entry.entry_hmac.clone();

            let entry_hmac = EntryHmacBuilder {
                realm: request.realm,
                group: request.destination,
                index,
                partition: &partition,
                transferring_out: &transferring_out,
                prev_hmac: &prev_hmac,
            }
            .build(&self.realm_keys.mac);

            let entry = LogEntry {
                index,
                partition,
                transferring_out,
                prev_hmac,
                entry_hmac,
            };

            leader.log.push_back(LeaderLogEntry {
                entry: entry.clone(),
                response: None,
            });

            leader.tree = Some(Tree::with_existing_root(
                MerkleHasher(),
                partition_hash,
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
            };

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
            };

            let index = last_entry.index.next();
            let owned_partition = last_entry.partition.clone();
            let transferring_out = None;
            let prev_hmac = last_entry.entry_hmac.clone();

            let entry_hmac = EntryHmacBuilder {
                realm: request.realm,
                group: request.source,
                index,
                partition: &owned_partition,
                transferring_out: &transferring_out,
                prev_hmac: &prev_hmac,
            }
            .build(&self.realm_keys.mac);

            let entry = LogEntry {
                index,
                partition: owned_partition,
                transferring_out,
                prev_hmac,
                entry_hmac,
            };

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

    let (merkle, record) = match MerkleHelper::get_record(request.proof, &keys.record, tree) {
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

    req_name_out.replace(secrets_req_name(&secrets_request));

    let (secrets_response, change) = app::process(
        app_ctx,
        &request.record_id,
        secrets_request,
        record.as_deref(),
    );

    let secrets_response = noise.encode(secrets_response, &mut leader.sessions);

    let (root_hash, store_delta) = merkle.update_overlay(rng, change);

    let new_entry = make_next_log_entry(leader, request.realm, request.group, root_hash, &keys.mac);
    leader.log.push_back(LeaderLogEntry {
        entry: new_entry.clone(),
        response: Some(secrets_response),
    });
    AppResponse::Ok {
        entry: new_entry,
        delta: store_delta,
    }
}

/// Used in [`handle_app_request`].
struct MerkleHelper<'a> {
    tree: &'a mut Tree<MerkleHasher, DataHash>,
    leaf_key: &'a RecordEncryptionKey,
    latest_proof: VerifiedProof<DataHash>,
    update_num: u64,
}

impl<'a> MerkleHelper<'a> {
    fn get_record(
        request_proof: ReadProof<DataHash>,
        leaf_key: &'a RecordEncryptionKey,
        tree: &'a mut Tree<MerkleHasher, DataHash>,
    ) -> Result<(Self, Option<Vec<u8>>), AppError> {
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

        // TODO: do we check anywhere that `request_proof.key` matches `request.record_id`?

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

        // The last 8 bytes of the value are a sequential update number to stop
        // leaf hashes repeating.
        let (update_num, latest_value) = match latest_value {
            Some(mut v) => {
                let split_at = v
                    .len()
                    .checked_sub(8)
                    .expect("node should be at least 8 bytes");

                let update_num = u64::from_be_bytes(v[split_at..].try_into().unwrap());
                v.truncate(split_at);
                (update_num, Some(v))
            }
            None => (0, None),
        };

        Ok((
            MerkleHelper {
                leaf_key,
                tree,
                latest_proof,
                update_num,
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
                RecordChange::Update(mut record) => {
                    let cipher = XChaCha20Poly1305::new_from_slice(&self.leaf_key.0)
                        .expect("couldn't create cipher");

                    let mut nonce = XNonce::default();
                    rng.fill_bytes(&mut nonce);
                    record
                        .extend_from_slice(&self.update_num.checked_add(1).unwrap().to_be_bytes());
                    let plain_text: &[u8] = &record;

                    // TODO: An optimization we could do is to use the authentication tag as the leaf's hash. Right now this is checking
                    // the integrity of the record twice: once in the Merkle tree hash and once in the AEAD tag.
                    // We may also want to use the AD part of AEAD. For example, the generation number in the user's record isn't necessarily
                    // private and could allow the agent to reply to some queries without the HSM getting involved.
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
        sessions: &mut Cache<(RecordId, SessionId), noise::Transport>,
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

    fn encode(
        self,
        response: SecretsResponse,
        sessions: &mut Cache<(RecordId, SessionId), noise::Transport>,
    ) -> NoiseResponse {
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

fn make_next_log_entry(
    leader: &LeaderVolatileGroupState,
    realm: RealmId,
    group: GroupId,
    root_hash: DataHash,
    mac_key: &MacKey,
) -> LogEntry {
    let last_entry = leader.log.back().unwrap();

    let index = last_entry.entry.index.next();
    let partition = Some(Partition {
        range: last_entry.entry.partition.as_ref().unwrap().range.clone(),
        root_hash,
    });

    let transferring_out = last_entry.entry.transferring_out.clone();
    let prev_hmac = last_entry.entry.entry_hmac.clone();

    let entry_hmac = EntryHmacBuilder {
        realm,
        group,
        index,
        partition: &partition,
        transferring_out: &transferring_out,
        prev_hmac: &prev_hmac,
    }
    .build(mac_key);

    LogEntry {
        index,
        partition,
        transferring_out,
        prev_hmac,
        entry_hmac,
    }
}

#[cfg(test)]
mod test {
    use hashbrown::HashMap;
    use loam_sdk_core::{marshalling, types::RealmId};

    use super::{
        super::bitvec,
        super::hal::MAX_NVRAM_SIZE,
        super::merkle::{agent::StoreKey, NodeHasher},
        types::{Configuration, DataHash, EntryHmac, GroupId, HsmId, LogIndex},
        MerkleHasher, PersistentGroupState, PersistentRealmState, PersistentState,
    };

    #[test]
    fn test_store_key_parse_data_hash() {
        let prefix = bitvec![0, 1, 1, 1];
        let mh = MerkleHasher();
        let hash = mh.calc_hash(&[&[1, 2, 3, 4]]);

        let sk = StoreKey::new(&prefix, &hash);
        match StoreKey::parse::<DataHash>(&sk.into_bytes()) {
            None => panic!("should have decoded store key"),
            Some((_p, h)) => {
                assert_eq!(h, hash);
            }
        }
    }

    #[test]
    fn persistent_data_size() {
        // Verify that a PersistentState with 16 groups with 8 HSMs each fits in the NVRAM limit.

        let group = PersistentGroupState {
            configuration: Configuration(vec![
                HsmId([10; 16]),
                HsmId([11; 16]),
                HsmId([12; 16]),
                HsmId([13; 16]),
                HsmId([14; 16]),
                HsmId([15; 16]),
                HsmId([16; 16]),
                HsmId([17; 16]),
            ]),
            captured: Some((LogIndex(u64::MAX - 1), EntryHmac([3; 32].into()))),
        };
        let mut groups = HashMap::new();
        for id in 0..16 {
            groups.insert(GroupId([id; 16]), group.clone());
        }
        let p = PersistentState {
            id: HsmId([1; 16]),
            realm: Some(PersistentRealmState {
                id: RealmId([2; 16]),
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
