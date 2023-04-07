extern crate alloc;

use aes_gcm::aead::Aead;
use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Debug};
use core::time::Duration;
use digest::Digest;
use hashbrown::HashMap; // TODO: randomize hasher
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{info, trace, warn};
use x25519_dalek as x25519;

mod app;
mod cache;
pub mod rpc;
pub mod types;

use super::hal::{Clock, CryptoRng, IOError, NVRam, Nanos, Platform};
use super::merkle::{
    agent::StoreDelta,
    proof::{ProofError, ReadProof, VerifiedProof},
    MergeError, NodeHasher, Tree,
};
use app::{RecordChange, RootOprfKey};
use cache::Cache;
use loam_sdk_core::{
    requests::{NoiseRequest, NoiseResponse, SecretsRequest, SecretsResponse},
    types::{RealmId, SessionId},
    {marshalling, marshalling::DeserializationError},
};
use loam_sdk_noise::server as noise;
use rpc::{HsmRequest, HsmRequestContainer, HsmResponseContainer, HsmRpc, MetricsAction};
use types::{
    AppError, AppRequest, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse,
    CaptureNextRequest, CaptureNextResponse, CapturedStatement, CommitRequest, CommitResponse,
    CompleteTransferRequest, CompleteTransferResponse, Configuration, DataHash, EntryHmac,
    GroupConfigurationStatement, GroupId, GroupStatus, HandshakeRequest, HandshakeResponse, HsmId,
    JoinGroupRequest, JoinGroupResponse, JoinRealmRequest, JoinRealmResponse, LeaderStatus,
    LogEntry, LogIndex, NewGroupInfo, NewGroupRequest, NewGroupResponse, NewRealmRequest,
    NewRealmResponse, OwnedRange, Partition, ReadCapturedRequest, ReadCapturedResponse,
    RealmStatus, RecordId, StatusRequest, StatusResponse, TransferInRequest, TransferInResponse,
    TransferNonce, TransferNonceRequest, TransferNonceResponse, TransferOutRequest,
    TransferOutResponse, TransferStatement, TransferStatementRequest, TransferStatementResponse,
    TransferringOut,
};

/// Returned in Noise handshake requests as a hint to the client of how long
/// they should reuse an inactive session.
///
/// The agent or load balancer could override this default with a more
/// sophisticated estimate, so it's OK for this to be a constant here.
const SESSION_LIFETIME: Duration = Duration::from_secs(5);

#[derive(Clone, Deserialize, Serialize)]
pub struct RealmKey(digest::Key<Hmac<Sha256>>);

impl fmt::Debug for RealmKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

impl RealmKey {
    pub fn random(rng: &mut impl CryptoRng) -> Self {
        let mut key = digest::Key::<Hmac<Sha256>>::default();
        rng.fill_bytes(&mut key);
        Self(key)
    }
    // derive a realmKey from the supplied input.
    // TODO, ensure this goes away.
    pub fn derive_from(b: &[u8]) -> Self {
        let mut mac = Hmac::<sha2::Sha512>::new_from_slice(b"worlds worst secret").expect("TODO");
        mac.update(b);
        Self(mac.finalize().into_bytes())
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
    fn calculate(&self, key: &RealmKey) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new(&key.0);
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

    fn build(&self, key: &RealmKey) -> GroupConfigurationStatement {
        GroupConfigurationStatement(self.calculate(key).finalize().into_bytes())
    }

    fn verify(
        &self,
        key: &RealmKey,
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
    fn calculate(&self, key: &RealmKey) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new(&key.0);
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

    fn build(&self, key: &RealmKey) -> CapturedStatement {
        CapturedStatement(self.calculate(key).finalize().into_bytes())
    }

    fn verify(
        &self,
        key: &RealmKey,
        statement: &CapturedStatement,
    ) -> Result<(), digest::MacError> {
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
    fn calculate(&self, key: &RealmKey) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new(&key.0);
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

    fn build(&self, key: &RealmKey) -> EntryHmac {
        EntryHmac(self.calculate(key).finalize().into_bytes())
    }

    fn verify(&self, key: &RealmKey, hmac: &EntryHmac) -> Result<(), digest::MacError> {
        self.calculate(key).verify(&hmac.0)
    }

    fn verify_entry(
        key: &RealmKey,
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
    fn calculate(&self, key: &RealmKey) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new(&key.0);
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

    fn build(&self, key: &RealmKey) -> TransferStatement {
        TransferStatement(self.calculate(key).finalize().into_bytes())
    }

    fn verify(
        &self,
        key: &RealmKey,
        statement: &TransferStatement,
    ) -> Result<(), digest::MacError> {
        self.calculate(key).verify(&statement.0)
    }
}

pub struct MerkleHasher();
impl NodeHasher<DataHash> for MerkleHasher {
    fn calc_hash(&self, parts: &[&[u8]]) -> DataHash {
        let mut h = Sha256::new();
        for p in parts {
            h.update([b'|']); //delim all the parts
            h.update(p);
        }
        DataHash(h.finalize())
    }
}

/// A private key used to encrypt/decrypt record values.
struct RecordEncryptionKey([u8; 32]);

impl RecordEncryptionKey {
    fn from(realm_key: &RealmKey) -> Self {
        // generated from /dev/random
        let salt = [
            0x61u8, 0x33, 0xcf, 0xf6, 0xf6, 0x70, 0x27, 0xd2, 0x0c, 0x3d, 0x8b, 0x42, 0x5a, 0x21,
            0xeb, 0xb2, 0x6b, 0x91, 0x0a, 0x97, 0x5c, 0xee, 0xfa, 0x57, 0xf7, 0x76, 0x5d, 0x96,
            0x49, 0xa4, 0xd3, 0xd6,
        ];
        let info = "record".as_bytes();
        let hk = Hkdf::<Sha256>::new(Some(&salt), &realm_key.0);
        let mut out = [0u8; 32];
        hk.expand(info, &mut out).unwrap();
        Self(out)
    }
}

pub struct Hsm<P: Platform> {
    platform: P,
    options: HsmOptions,
    persistent: PersistentState,
    volatile: VolatileState,
}

pub struct HsmOptions {
    pub name: String,
    pub tree_overlay_size: u16,
    pub max_sessions: u16,
}

#[derive(Deserialize, Serialize)]
struct PersistentState {
    id: HsmId,
    realm_key: RealmKey, // TODO: rename. This is used for MACs.
    realm_communication: (x25519::StaticSecret, x25519::PublicKey),
    realm: Option<PersistentRealmState>,
    root_oprf_key: RootOprfKey, // TODO: switch to random per-generation OPRF keys.
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
    record_key: RecordEncryptionKey,
}

struct LeaderVolatileGroupState {
    log: Vec<LeaderLogEntry>, // never empty
    committed: Option<LogIndex>,
    incoming: Option<TransferNonce>,
    /// This is `Some` if and only if the last entry in `log` owns a partition.
    tree: Option<Tree<MerkleHasher, DataHash>>,
    sessions: Cache<(RecordId, SessionId), noise::Transport>,
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

impl<P: Platform> Hsm<P> {
    pub fn new(
        options: HsmOptions,
        mut platform: P,
        realm_key: RealmKey,
    ) -> Result<Self, PersistenceError> {
        let persistent = match Self::read_persisted_state(&platform)? {
            Some(state) => state,
            None => {
                let root_oprf_key = RootOprfKey::from(&realm_key);
                let hsm_id = HsmId::random(&mut platform);

                let realm_communication = {
                    // TODO: This is an insecure placeholder.
                    let mut buf = [0u8; 32];
                    buf.copy_from_slice(&realm_key.0[..32]);
                    let secret = x25519::StaticSecret::from(buf);
                    let public = x25519::PublicKey::from(&secret);
                    (secret, public)
                };
                let state = PersistentState {
                    id: hsm_id,
                    realm_key,
                    realm_communication,
                    realm: None,
                    root_oprf_key,
                };
                Self::persist_state(&platform, &state)?;
                state
            }
        };

        let record_key = RecordEncryptionKey::from(&persistent.realm_key);
        Ok(Hsm {
            options,
            platform,
            persistent,
            volatile: VolatileState {
                leader: HashMap::new(),
                record_key,
            },
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
            HsmRequest::CaptureNext(r) => {
                self.dispatch_request(metrics, r, Self::handle_capture_next)
            }
            HsmRequest::ReadCaptured(r) => {
                self.dispatch_request(metrics, r, Self::handle_read_captured)
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

    fn persist_state(nvram: &impl NVRam, state: &PersistentState) -> Result<(), IOError> {
        // TODO, which if any of the keys in self.persistent should be written out here vs read from the HSM
        // key store at initialization time.
        let mut data = marshalling::to_vec(&state).expect("failed to serialize state");
        let d = Sha256::digest(&data);
        data.extend(d);
        nvram.write(data)
    }

    fn read_persisted_state(
        nvram: &impl NVRam,
    ) -> Result<Option<PersistentState>, PersistenceError> {
        let d = nvram.read()?;
        if d.is_empty() {
            return Ok(None);
        }
        if d.len() < Sha256::output_size() {
            return Err(PersistenceError::InvalidSignature);
        }
        let (data, stored_digest) = d.split_at(d.len() - Sha256::output_size());
        let calced_digest = Sha256::digest(data);
        if stored_digest == calced_digest.as_slice() {
            match marshalling::from_slice(data) {
                Ok(state) => Ok(Some(state)),
                Err(e) => Err(PersistenceError::Deserialization(e)),
            }
        } else {
            Err(PersistenceError::InvalidSignature)
        }
    }

    // Mutate the persisted state. If the closure returns OK(_) NVRAM is updated, if it returns Err
    // it is not. The embedded R in Ok or Err is returned as the result from this function. Which
    // is weird but works with the way errors are returned out of the HSM.
    //
    // Depending on types & scope, the PARAM value can let you get values into the closure where
    // trying to capture it with the closure would fail the borrow checker.
    fn mut_persisted_state<F, PARAM, R>(&mut self, param: PARAM, mut f: F) -> R
    where
        F: FnMut(&mut PersistentState, PARAM) -> Result<R, R>,
    {
        match f(&mut self.persistent, param) {
            Ok(r) => {
                Self::persist_state(&self.platform, &self.persistent)
                    .expect("Failed to write to NVRAM");
                r
            }
            Err(r) => r,
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
        .build(&self.persistent.realm_key);

        self.mut_persisted_state(configuration, |persistent, configuration| {
            let existing = persistent.realm.as_mut().unwrap().groups.insert(
                group,
                PersistentGroupState {
                    configuration,
                    captured: None,
                },
            );
            assert!(existing.is_none());
            Ok(())
        });

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
        .build(&self.persistent.realm_key);

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
                log: vec![LeaderLogEntry {
                    entry: entry.clone(),
                    response: None,
                }],
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
                public_key: self.persistent.realm_communication.1.as_bytes().to_vec(),
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
                                            .last()
                                            .expect("leader's log is never empty")
                                            .entry
                                            .partition
                                            .as_ref()
                                            .map(|p| p.range.clone()),
                                    }
                                }),
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
            self.persistent.realm = Some(PersistentRealmState {
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
            None => self.mut_persisted_state(request.realm, |persistent, realm| {
                persistent.realm = Some(PersistentRealmState {
                    id: realm,
                    groups: HashMap::new(),
                });
                Ok(JoinRealmResponse::Ok { hsm: persistent.id })
            }),
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
        let response =
            self.mut_persisted_state(request, |persistent, request| match &mut persistent.realm {
                None => Err(Response::InvalidRealm),

                Some(realm) => {
                    if realm.id != request.realm {
                        Err(Response::InvalidRealm)
                    } else if (GroupConfigurationStatementBuilder {
                        realm: request.realm,
                        group: request.group,
                        configuration: &request.configuration,
                    })
                    .verify(&persistent.realm_key, &request.statement)
                    .is_err()
                    {
                        Err(Response::InvalidStatement)
                    } else if !request.configuration.is_ok()
                        || !request.configuration.0.contains(&persistent.id)
                    {
                        Err(Response::InvalidConfiguration)
                    } else {
                        realm
                            .groups
                            .entry(request.group)
                            .or_insert(PersistentGroupState {
                                configuration: request.configuration,
                                captured: None,
                            });
                        Ok(Response::Ok)
                    }
                }
            });

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

        let response =
            self.mut_persisted_state(request, |persistent, request| match &mut persistent.realm {
                None => Err(Response::InvalidRealm),

                Some(realm) => {
                    if realm.id != request.realm {
                        return Err(Response::InvalidRealm);
                    }

                    if EntryHmacBuilder::verify_entry(
                        &persistent.realm_key,
                        request.realm,
                        request.group,
                        &request.entry,
                    )
                    .is_err()
                    {
                        return Err(Response::InvalidHmac);
                    }

                    match realm.groups.get_mut(&request.group) {
                        None => Err(Response::InvalidGroup),

                        Some(group) => {
                            match &group.captured {
                                None => {
                                    if request.entry.index != LogIndex::FIRST {
                                        return Err(Response::MissingPrev);
                                    }
                                    if request.entry.prev_hmac != EntryHmac::zero() {
                                        return Err(Response::InvalidChain);
                                    }
                                }
                                Some((captured_index, captured_hmac)) => {
                                    if request.entry.index != captured_index.next() {
                                        return Err(Response::MissingPrev);
                                    }
                                    if request.entry.prev_hmac != *captured_hmac {
                                        return Err(Response::InvalidChain);
                                    }
                                }
                            }

                            let statement = CapturedStatementBuilder {
                                hsm: persistent.id,
                                realm: request.realm,
                                group: request.group,
                                index: request.entry.index,
                                entry_hmac: &request.entry.entry_hmac,
                            }
                            .build(&persistent.realm_key);
                            group.captured = Some((request.entry.index, request.entry.entry_hmac));
                            Ok(Response::Ok {
                                hsm_id: persistent.id,
                                captured: statement,
                            })
                        }
                    }
                }
            });

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

        let response = (|| {
            match &self.persistent.realm {
                None => return Response::InvalidRealm,

                Some(realm) => {
                    if realm.id != request.realm {
                        return Response::InvalidRealm;
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
                                    &self.persistent.realm_key,
                                    request.realm,
                                    request.group,
                                    &request.last_entry,
                                )
                                .is_err()
                                {
                                    return Response::InvalidHmac;
                                }
                            }
                        },
                    }
                }
            }

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
                    log: vec![LeaderLogEntry {
                        entry: request.last_entry,
                        response: None,
                    }],
                    committed: None,
                    incoming: None,
                    tree,
                    sessions: Cache::new(usize::from(self.options.max_sessions)),
                });
            Response::Ok
        })();

        trace!(hsm = self.options.name, ?response);
        response
    }

    fn handle_read_captured(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: ReadCapturedRequest,
    ) -> ReadCapturedResponse {
        type Response = ReadCapturedResponse;
        trace!(hsm = self.options.name, ?request);
        let response = match &self.persistent.realm {
            None => Response::InvalidRealm,

            Some(realm) => {
                if realm.id != request.realm {
                    return Response::InvalidRealm;
                }

                match realm.groups.get(&request.group) {
                    None => Response::InvalidGroup,

                    Some(group) => match &group.captured {
                        None => Response::None,
                        Some((index, entry_hmac)) => Response::Ok {
                            hsm_id: self.persistent.id,
                            index: *index,
                            entry_hmac: entry_hmac.clone(),
                            statement: CapturedStatementBuilder {
                                hsm: self.persistent.id,
                                realm: request.realm,
                                group: request.group,
                                index: *index,
                                entry_hmac,
                            }
                            .build(&self.persistent.realm_key),
                        },
                    },
                }
            }
        };
        trace!(hsm = self.options.name, ?response);
        response
    }

    fn handle_commit(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: CommitRequest,
    ) -> CommitResponse {
        type Response = CommitResponse;
        trace!(hsm = self.options.name, ?request);

        let response = (|| {
            let Some(realm) = &self.persistent.realm else {
                return Response::InvalidRealm;
            };
            if realm.id != request.realm {
                return Response::InvalidRealm;
            }

            let Some(group) = realm.groups.get(&request.group) else {
                return Response::InvalidGroup;
            };

            let Some(leader) = self.volatile.leader.get_mut(&request.group) else {
                return Response::NotLeader;
            };

            if let Some(committed) = leader.committed {
                if committed >= request.index {
                    return Response::AlreadyCommitted { committed };
                }
            }

            let mut election = HsmElection::new(&group.configuration.0);
            for (hsm_id, captured_statement) in request.captures {
                if (CapturedStatementBuilder {
                    hsm: hsm_id,
                    realm: request.realm,
                    group: request.group,
                    index: request.index,
                    entry_hmac: &request.entry_hmac,
                }
                .verify(&self.persistent.realm_key, &captured_statement)
                .is_ok())
                {
                    election.vote(hsm_id);
                };
            }
            if let Some((index, entry_hmac)) = &group.captured {
                if *index == request.index && *entry_hmac == request.entry_hmac {
                    election.vote(self.persistent.id);
                }
            };

            let election_outcome = election.outcome();
            if election_outcome.has_quorum {
                trace!(hsm = self.options.name, index = ?request.index, "leader committed entry");
                // todo: skip already committed entries
                let responses = leader
                    .log
                    .iter_mut()
                    .filter(|entry| entry.entry.index <= request.index)
                    .filter_map(|entry| {
                        entry
                            .response
                            .take()
                            .map(|r| (entry.entry.entry_hmac.clone(), r))
                    })
                    .collect();
                leader.committed = Some(request.index);
                CommitResponse::Ok {
                    committed: leader.committed,
                    responses,
                }
            } else {
                warn!(
                    hsm = self.options.name,
                    election = ?election_outcome,
                    "no quorum. buggy caller?"
                );
                CommitResponse::NoQuorum
            }
        })();

        trace!(hsm = self.options.name, ?response);
        response
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

            if realm.groups.get(&request.source).is_none() {
                return Response::InvalidGroup;
            };

            let Some(leader) = self.volatile.leader.get_mut(&request.source) else {
                return Response::NotLeader;
            };

            let last_entry = &leader.log.last().unwrap().entry;

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
            .build(&self.persistent.realm_key);

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

            leader.log.push(LeaderLogEntry {
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

            if realm.groups.get(&request.source).is_none() {
                return Response::InvalidGroup;
            };

            let Some(leader) = self.volatile.leader.get_mut(&request.source) else {
                return Response::NotLeader;
            };

            let Some(TransferringOut {
                destination,
                partition,
                at: transferring_at,
            }) = &leader.log.last().unwrap().entry.transferring_out else {
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
            .build(&self.persistent.realm_key);

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

            let last_entry = &leader.log.last().unwrap().entry;
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
            .verify(&self.persistent.realm_key, &request.statement)
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
            .build(&self.persistent.realm_key);

            let entry = LogEntry {
                index,
                partition,
                transferring_out,
                prev_hmac,
                entry_hmac,
            };

            leader.log.push(LeaderLogEntry {
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

            if realm.groups.get(&request.source).is_none() {
                return Response::InvalidGroup;
            };

            let Some(leader) = self.volatile.leader.get_mut(&request.source) else {
                return Response::NotLeader;
            };

            let last_entry = &leader.log.last().unwrap().entry;
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
            .build(&self.persistent.realm_key);

            let entry = LogEntry {
                index,
                partition: owned_partition,
                transferring_out,
                prev_hmac,
                entry_hmac,
            };

            leader.log.push(LeaderLogEntry {
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
                        if (leader.log.last().unwrap().entry)
                            .partition
                            .as_ref()
                            .filter(|partition| partition.range.contains(&request.record_id))
                            .is_some()
                        {
                            match noise::Handshake::start(
                                (
                                    &self.persistent.realm_communication.0,
                                    &self.persistent.realm_communication.1,
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
                        if (leader.log.last().unwrap().entry)
                            .partition
                            .as_ref()
                            .filter(|partition| partition.range.contains(&request.record_id))
                            .is_some()
                        {
                            let app_ctx = app::AppContext {
                                root_oprf_key: &self.persistent.root_oprf_key,
                                hsm_name,
                            };
                            handle_app_request(
                                &app_ctx,
                                request,
                                &self.volatile.record_key,
                                &self.persistent,
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
        SecretsRequest::Register1(_) => "App::Register1",
        SecretsRequest::Register2(_) => "App::Register2",
        SecretsRequest::Recover1(_) => "App::Recover1",
        SecretsRequest::Recover2(_) => "App::Recover2",
        SecretsRequest::Delete(_) => "App::Delete",
    }
}

fn handle_app_request(
    app_ctx: &app::AppContext,
    request: AppRequest,
    leaf_key: &RecordEncryptionKey,
    persistent: &PersistentState,
    leader: &mut LeaderVolatileGroupState,
    req_name_out: &mut Option<&'static str>,
    rng: &mut dyn CryptoRng,
) -> AppResponse {
    let tree = leader
        .tree
        .as_mut()
        .expect("caller should have checked that this leader owns a partition");

    let (merkle, record) = match MerkleHelper::get_record(request.proof, leaf_key, tree) {
        Ok(record) => record,
        Err(response) => return response.into(),
    };

    let (noise, secrets_request) = match NoiseHelper::decode(
        request.record_id.clone(),
        request.session_id,
        &request.encrypted,
        &mut leader.sessions,
        &persistent.realm_communication,
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

    let (root_hash, store_delta) = merkle.update_overlay(change);

    let new_entry = make_next_log_entry(
        leader,
        request.realm,
        request.group,
        root_hash,
        &persistent.realm_key,
    );
    leader.log.push(LeaderLogEntry {
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
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

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
                    Aes256Gcm::new_from_slice(&leaf_key.0).expect("couldn't create cipher");
                let nonce = Nonce::from_slice(&latest_proof.key.0[..12]);
                match cipher.decrypt(nonce, l.value.as_slice()) {
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

    fn update_overlay(self, change: Option<RecordChange>) -> (DataHash, StoreDelta<DataHash>) {
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        match change {
            Some(change) => match change {
                RecordChange::Update(mut record) => {
                    let cipher = Aes256Gcm::new_from_slice(&self.leaf_key.0)
                        .expect("couldn't create cipher");
                    // TODO: can we use this nonce to help generate unique leaf hashes?
                    // TODO: can we use or add the previous root hash into this? (this seems hard as you need the same nonce to decode it)
                    let nonce = Nonce::from_slice(&self.latest_proof.key.0[..12]);
                    record
                        .extend_from_slice(&self.update_num.checked_add(1).unwrap().to_be_bytes());
                    let plain_text: &[u8] = &record;

                    // TODO: An optimization we could do is to use the authentication tag as the leaf's hash. Right now this is checking
                    // the integrity of the record twice: once in the Merkle tree hash and once in the AES GCM tag.
                    // We may also want to use the AD part of AEAD. For example, the generation number in the user's record isn't necessarily
                    // private and could allow the agent to reply to some queries without the HSM getting involved.
                    let cipher_text = cipher
                        .encrypt(nonce, plain_text)
                        .expect("couldn't encrypt record");

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
    realm_key: &RealmKey,
) -> LogEntry {
    let last_entry = leader.log.last().unwrap();

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
    .build(realm_key);

    LogEntry {
        index,
        partition,
        transferring_out,
        prev_hmac,
        entry_hmac,
    }
}

pub struct HsmElection {
    votes: HashMap<HsmId, bool>,
}

#[derive(PartialEq, Eq)]
pub struct HsmElectionOutcome {
    pub has_quorum: bool,
    pub vote_count: usize,
    pub member_count: usize,
}

impl HsmElection {
    pub fn new(voters: &[HsmId]) -> HsmElection {
        assert!(!voters.is_empty());
        HsmElection {
            votes: HashMap::from_iter(voters.iter().map(|id| (*id, false))),
        }
    }

    pub fn vote(&mut self, voter: HsmId) {
        self.votes.entry(voter).and_modify(|f| *f = true);
    }

    pub fn outcome(self) -> HsmElectionOutcome {
        let yay = self.votes.iter().filter(|(_, v)| **v).count();
        let all = self.votes.len();
        HsmElectionOutcome {
            has_quorum: yay * 2 > all,
            vote_count: yay,
            member_count: all,
        }
    }
}

impl Debug for HsmElectionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HsmElectionOutcome votes {} out of {}, {}",
            self.vote_count,
            self.member_count,
            if self.has_quorum {
                "Quorum"
            } else {
                "NoQuorum"
            }
        )
    }
}

#[cfg(test)]
mod test {
    use hashbrown::HashMap;
    use loam_sdk_core::{marshalling, types::RealmId};
    use x25519_dalek as x25519;

    use super::{
        super::bitvec,
        super::hal::MAX_NVRAM_SIZE,
        super::merkle::{agent::StoreKey, NodeHasher},
        app::RootOprfKey,
        types::{Configuration, DataHash, EntryHmac, GroupId, HsmId, LogIndex},
        HsmElection, HsmElectionOutcome, MerkleHasher, PersistentGroupState, PersistentRealmState,
        PersistentState, RealmKey,
    };

    #[test]
    #[should_panic]
    fn empty_election() {
        HsmElection::new(&[]);
    }

    #[test]
    fn election_voters() {
        let ids = (0..6).map(|b| HsmId([b; 16])).collect::<Vec<_>>();
        fn has_q(ids: &[HsmId], voters: &[HsmId]) -> bool {
            let mut q = HsmElection::new(ids);
            for v in voters.iter() {
                q.vote(*v);
            }
            let o = q.outcome();
            assert_eq!(voters.len(), o.vote_count);
            assert_eq!(ids.len(), o.member_count);
            o.has_quorum
        }
        // 1 member
        assert!(has_q(&ids[..1], &ids[..1]));
        assert!(!has_q(&ids[..1], &ids[..0]));
        // 2 members
        assert!(has_q(&ids[..2], &ids[..2]));
        assert!(!has_q(&ids[..2], &ids[..1]));
        assert!(!has_q(&ids[..2], &ids[..0]));
        // 3 members
        assert!(has_q(&ids[..3], &ids[..3]));
        assert!(has_q(&ids[..3], &ids[..2]));
        assert!(!has_q(&ids[..3], &ids[..1]));
        assert!(!has_q(&ids[..3], &ids[..0]));
        // 4
        assert!(has_q(&ids[..4], &ids[..4]));
        assert!(has_q(&ids[..4], &ids[..3]));
        assert!(!has_q(&ids[..4], &ids[..2]));
        assert!(!has_q(&ids[..4], &ids[..1]));
        assert!(!has_q(&ids[..4], &ids[..0]));
        // 5
        assert!(has_q(&ids[..5], &ids[..5]));
        assert!(has_q(&ids[..5], &ids[..4]));
        assert!(has_q(&ids[..5], &ids[..3]));
        assert!(!has_q(&ids[..5], &ids[..2]));
        assert!(!has_q(&ids[..5], &ids[..1]));
        assert!(!has_q(&ids[..5], &ids[..0]));
        // 6
        assert!(has_q(&ids[..6], &ids[..6]));
        assert!(has_q(&ids[..6], &[ids[0], ids[4], ids[1], ids[5], ids[3]]));
        assert!(has_q(&ids[..6], &[ids[5], ids[0], ids[2], ids[3]]));
        assert!(!has_q(&ids[..6], &[ids[4], ids[0], ids[2]]));
        assert!(!has_q(&ids[..6], &ids[3..5]));
        assert!(!has_q(&ids[..6], &[ids[5], ids[1]]));
        assert!(!has_q(&ids[..6], &ids[4..5]));
        assert!(!has_q(&ids[..6], &ids[..0]));
    }

    #[test]
    fn election_non_voters() {
        let ids = (0..10).map(|b| HsmId([b; 16])).collect::<Vec<_>>();
        let mut q = HsmElection::new(&ids[..5]);
        for not_member in &ids[5..] {
            q.vote(*not_member);
        }
        assert_eq!(
            HsmElectionOutcome {
                has_quorum: false,
                vote_count: 0,
                member_count: 5
            },
            q.outcome()
        );
    }

    #[test]
    fn election_vote_only_counts_once() {
        let ids = (0..5).map(|b| HsmId([b; 16])).collect::<Vec<_>>();
        let mut q = HsmElection::new(&ids);
        q.vote(ids[0]);
        q.vote(ids[0]);
        q.vote(ids[0]);
        q.vote(ids[1]);
        assert_eq!(
            HsmElectionOutcome {
                has_quorum: false,
                vote_count: 2,
                member_count: 5
            },
            q.outcome()
        );
    }

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

        let realm_key = RealmKey::derive_from("its a test".as_bytes());
        let root_oprf_key = RootOprfKey::from(&realm_key);

        let realm_communication = {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&realm_key.0[..32]);
            let secret = x25519::StaticSecret::from(buf);
            let public = x25519::PublicKey::from(&secret);
            (secret, public)
        };
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
            realm_key,
            realm_communication,
            realm: Some(PersistentRealmState {
                id: RealmId([2; 16]),
                groups,
            }),
            root_oprf_key,
        };
        let s = marshalling::to_vec(&p).unwrap();
        assert!(
            s.len() < MAX_NVRAM_SIZE,
            "serialized persistent state is {} bytes",
            s.len()
        );
    }
}
