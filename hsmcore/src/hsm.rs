extern crate alloc;

use aes_gcm::aead::Aead;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use digest::Digest;
use hashbrown::{HashMap, HashSet}; // TODO: randomize hasher
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{info, trace, warn};

mod app;
pub mod rpc;
pub mod types;

use self::rpc::{HsmRequest, HsmRpc};
use self::types::Partition;
use super::marshalling;
use super::merkle::{proof::ProofError, MergeError, NodeHasher, Tree};
use super::rand::GetRandom;
use app::{RecordChange, RootOprfKey};
use types::{
    AppRequest, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse, CaptureNextRequest,
    CaptureNextResponse, CapturedStatement, CommitRequest, CommitResponse, CompleteTransferRequest,
    CompleteTransferResponse, Configuration, DataHash, EntryHmac, GroupConfigurationStatement,
    GroupId, GroupStatus, HsmId, JoinGroupRequest, JoinGroupResponse, JoinRealmRequest,
    JoinRealmResponse, LeaderStatus, LogEntry, LogIndex, NewGroupInfo, NewGroupRequest,
    NewGroupResponse, NewRealmRequest, NewRealmResponse, OwnedRange, ReadCapturedRequest,
    ReadCapturedResponse, RealmId, RealmStatus, SecretsResponse, StatusRequest, StatusResponse,
    TransferInRequest, TransferInResponse, TransferNonce, TransferNonceRequest,
    TransferNonceResponse, TransferOutRequest, TransferOutResponse, TransferStatement,
    TransferStatementRequest, TransferStatementResponse, TransferringOut,
};

#[derive(Clone)]
pub struct RealmKey(digest::Key<Hmac<Sha256>>);

impl fmt::Debug for RealmKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

impl RealmKey {
    pub fn random(rng: &mut impl GetRandom) -> Self {
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
    fn random(rng: &mut Box<dyn GetRandom>) -> Self {
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        Self(id)
    }
}

impl HsmId {
    fn random(rng: &mut Box<dyn GetRandom>) -> Self {
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        Self(id)
    }
}

impl RealmId {
    fn random(rng: &mut Box<dyn GetRandom>) -> Self {
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        Self(id)
    }
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
    pub fn random(rng: &mut Box<dyn GetRandom>) -> Self {
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

struct MerkleHasher();
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

pub struct Hsm {
    name: String,
    persistent: PersistentState,
    volatile: VolatileState,
    rng: Box<dyn GetRandom>,
}

struct PersistentState {
    id: HsmId,
    realm_key: RealmKey,
    realm: Option<PersistentRealmState>,
    root_oprf_key: RootOprfKey,
}

struct PersistentRealmState {
    id: RealmId,
    groups: HashMap<GroupId, PersistentGroupState>,
}

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
    tree: Option<Tree<MerkleHasher, DataHash>>,
}

struct LeaderLogEntry {
    entry: LogEntry,
    /// A possible response to the client. This must not be externalized until
    /// after the entry has been committed.
    response: Option<SecretsResponse>,
}

pub enum HsmError {
    Deserialization(marshalling::DeserializationError),
    Serialization(marshalling::SerializationError),
}

impl Hsm {
    pub fn new(name: String, realm_key: RealmKey, mut rng: Box<dyn GetRandom>) -> Self {
        let root_oprf_key = RootOprfKey::from(&realm_key);
        let record_key = RecordEncryptionKey::from(&realm_key);
        let hsm_id = HsmId::random(&mut rng);
        Hsm {
            rng,
            name,
            persistent: PersistentState {
                id: hsm_id,
                realm_key,
                realm: None,
                root_oprf_key,
            },
            volatile: VolatileState {
                leader: HashMap::new(),
                record_key,
            },
        }
    }
    pub fn handle_request(&mut self, request_bytes: bytes::Bytes) -> Result<Vec<u8>, HsmError> {
        let request: HsmRequest = match marshalling::from_slice(request_bytes.as_ref()) {
            Ok(request) => request,
            Err(e) => {
                warn!(error = ?e, "deserialization error");
                return Err(HsmError::Deserialization(e));
            }
        };
        match request {
            HsmRequest::Status(r) => self.dispatch_request(r, Self::handle_status_request),
            HsmRequest::NewRealm(r) => self.dispatch_request(r, Self::handle_new_realm),
            HsmRequest::JoinRealm(r) => self.dispatch_request(r, Self::handle_join_realm),
            HsmRequest::NewGroup(r) => self.dispatch_request(r, Self::handle_new_group),
            HsmRequest::JoinGroup(r) => self.dispatch_request(r, Self::handle_join_group),
            HsmRequest::BecomeLeader(r) => self.dispatch_request(r, Self::handle_become_leader),
            HsmRequest::CaptureNext(r) => self.dispatch_request(r, Self::handle_capture_next),
            HsmRequest::ReadCaptured(r) => self.dispatch_request(r, Self::handle_read_captured),
            HsmRequest::Commit(r) => self.dispatch_request(r, Self::handle_commit),
            HsmRequest::TransferOut(r) => self.dispatch_request(r, Self::handle_transfer_out),
            HsmRequest::TransferNonce(r) => self.dispatch_request(r, Self::handle_transfer_nonce),
            HsmRequest::TransferStatement(r) => {
                self.dispatch_request(r, Self::handle_transfer_statement)
            }
            HsmRequest::TransferIn(r) => self.dispatch_request(r, Self::handle_transfer_in),
            HsmRequest::CompleteTransfer(r) => {
                self.dispatch_request(r, Self::handle_complete_transfer)
            }
            HsmRequest::AppRequest(r) => self.dispatch_request(r, Self::handle_app),
        }
    }
    fn dispatch_request<Req: HsmRpc, F: FnMut(&mut Self, Req) -> Req::Response>(
        &mut self,
        r: Req,
        mut f: F,
    ) -> Result<Vec<u8>, HsmError> {
        let response = f(self, r);
        marshalling::to_vec(&response).map_err(HsmError::Serialization)
    }

    fn create_new_group(
        &mut self,
        realm: RealmId,
        configuration: Configuration,
        owned_range: Option<OwnedRange>,
    ) -> NewGroupInfo {
        let group = GroupId::random(&mut self.rng);
        let statement = GroupConfigurationStatementBuilder {
            realm,
            group,
            configuration: &configuration,
        }
        .build(&self.persistent.realm_key);

        let existing = self.persistent.realm.as_mut().unwrap().groups.insert(
            group,
            PersistentGroupState {
                configuration,
                captured: None,
            },
        );
        assert!(existing.is_none());

        let index = LogIndex::FIRST;
        let (partition, data) = match &owned_range {
            None => (None, None),
            Some(key_range) => {
                let h = MerkleHasher();
                let (root_hash, delta) = Tree::new_tree(&h, key_range);
                (
                    Some(Partition {
                        range: key_range.clone(),
                        root_hash,
                    }),
                    Some(delta),
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
                tree: partition
                    .as_ref()
                    .map(|p| Tree::with_existing_root(MerkleHasher(), p.root_hash)),
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

    fn handle_status_request(&mut self, request: StatusRequest) -> StatusResponse {
        trace!(hsm = self.name, ?request);
        let response =
            StatusResponse {
                id: self.persistent.id,
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
        trace!(hsm = self.name, ?response);
        response
    }

    fn handle_new_realm(&mut self, request: NewRealmRequest) -> NewRealmResponse {
        type Response = NewRealmResponse;
        trace!(hsm = self.name, ?request);
        let response = if self.persistent.realm.is_some() {
            Response::HaveRealm
        } else if !request.configuration.is_ok()
            || !request.configuration.0.contains(&self.persistent.id)
        {
            Response::InvalidConfiguration
        } else {
            let realm_id = RealmId::random(&mut self.rng);
            self.persistent.realm = Some(PersistentRealmState {
                id: realm_id,
                groups: HashMap::new(),
            });
            let group_info =
                self.create_new_group(realm_id, request.configuration, Some(OwnedRange::full()));
            Response::Ok(group_info)
        };
        trace!(hsm = self.name, ?response);
        response
    }

    fn handle_join_realm(&mut self, request: JoinRealmRequest) -> JoinRealmResponse {
        trace!(hsm = self.name, ?request);

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
                self.persistent.realm = Some(PersistentRealmState {
                    id: request.realm,
                    groups: HashMap::new(),
                });
                JoinRealmResponse::Ok {
                    hsm: self.persistent.id,
                }
            }
        };

        trace!(hsm = self.name, ?response);
        response
    }

    fn handle_new_group(&mut self, request: NewGroupRequest) -> NewGroupResponse {
        type Response = NewGroupResponse;
        trace!(hsm = self.name, ?request);

        let Some(realm) = &mut self.persistent.realm else {
            trace!(hsm = self.name, response = ?Response::InvalidRealm);
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
        trace!(hsm = self.name, ?response);
        response
    }

    fn handle_join_group(&mut self, request: JoinGroupRequest) -> JoinGroupResponse {
        type Response = JoinGroupResponse;
        trace!(hsm = self.name, ?request);
        let response = match &mut self.persistent.realm {
            None => Response::InvalidRealm,

            Some(realm) => {
                if realm.id != request.realm {
                    Response::InvalidRealm
                } else if (GroupConfigurationStatementBuilder {
                    realm: request.realm,
                    group: request.group,
                    configuration: &request.configuration,
                })
                .verify(&self.persistent.realm_key, &request.statement)
                .is_err()
                {
                    Response::InvalidStatement
                } else if !request.configuration.is_ok()
                    || !request.configuration.0.contains(&self.persistent.id)
                {
                    Response::InvalidConfiguration
                } else {
                    realm
                        .groups
                        .entry(request.group)
                        .or_insert(PersistentGroupState {
                            configuration: request.configuration,
                            captured: None,
                        });
                    Response::Ok
                }
            }
        };
        trace!(hsm = self.name, ?response);
        response
    }

    fn handle_capture_next(&mut self, request: CaptureNextRequest) -> CaptureNextResponse {
        type Response = CaptureNextResponse;
        trace!(hsm = self.name, ?request);

        let response = (|| match &mut self.persistent.realm {
            None => Response::InvalidRealm,

            Some(realm) => {
                if realm.id != request.realm {
                    return Response::InvalidRealm;
                }

                if EntryHmacBuilder::verify_entry(
                    &self.persistent.realm_key,
                    request.realm,
                    request.group,
                    &request.entry,
                )
                .is_err()
                {
                    return Response::InvalidHmac;
                }

                match realm.groups.get_mut(&request.group) {
                    None => Response::InvalidGroup,

                    Some(group) => {
                        match &group.captured {
                            None => {
                                if request.entry.index != LogIndex::FIRST {
                                    return Response::MissingPrev;
                                }
                                if request.entry.prev_hmac != EntryHmac::zero() {
                                    return Response::InvalidChain;
                                }
                            }
                            Some((captured_index, captured_hmac)) => {
                                if request.entry.index != captured_index.next() {
                                    return Response::MissingPrev;
                                }
                                if request.entry.prev_hmac != *captured_hmac {
                                    return Response::InvalidChain;
                                }
                            }
                        }

                        let statement = CapturedStatementBuilder {
                            hsm: self.persistent.id,
                            realm: request.realm,
                            group: request.group,
                            index: request.entry.index,
                            entry_hmac: &request.entry.entry_hmac,
                        }
                        .build(&self.persistent.realm_key);
                        group.captured = Some((request.entry.index, request.entry.entry_hmac));
                        Response::Ok {
                            hsm_id: self.persistent.id,
                            captured: statement,
                        }
                    }
                }
            }
        })();

        trace!(hsm = self.name, ?response);
        response
    }

    fn handle_become_leader(&mut self, request: BecomeLeaderRequest) -> BecomeLeaderResponse {
        type Response = BecomeLeaderResponse;
        trace!(hsm = self.name, ?request);

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

            let tree = request
                .last_entry
                .partition
                .as_ref()
                .map(|p| Tree::with_existing_root(MerkleHasher(), p.root_hash));
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
                });
            Response::Ok
        })();

        trace!(hsm = self.name, ?response);
        response
    }

    fn handle_read_captured(&mut self, request: ReadCapturedRequest) -> ReadCapturedResponse {
        type Response = ReadCapturedResponse;
        trace!(hsm = self.name, ?request);
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
        trace!(hsm = self.name, ?response);
        response
    }

    fn handle_commit(&mut self, request: CommitRequest) -> CommitResponse {
        type Response = CommitResponse;
        trace!(hsm = self.name, ?request);

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

            let captures = request
                .captures
                .iter()
                .filter_map(|(hsm_id, captured_statement)| {
                    (group.configuration.0.contains(hsm_id)
                        && CapturedStatementBuilder {
                            hsm: *hsm_id,
                            realm: request.realm,
                            group: request.group,
                            index: request.index,
                            entry_hmac: &request.entry_hmac,
                        }
                        .verify(&self.persistent.realm_key, captured_statement)
                        .is_ok())
                    .then_some(*hsm_id)
                })
                .chain(match &group.captured {
                    Some((index, entry_hmac))
                        if *index == request.index && *entry_hmac == request.entry_hmac =>
                    {
                        Some(self.persistent.id)
                    }
                    _ => None,
                })
                .collect::<HashSet<HsmId>>()
                .len();

            if captures > group.configuration.0.len() / 2 {
                trace!(hsm = self.name, index = ?request.index, "leader committed entry");
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
                    hsm = self.name,
                    captures,
                    total = group.configuration.0.len(),
                    "no quorum. buggy caller?"
                );
                CommitResponse::NoQuorum
            }
        })();

        trace!(hsm = self.name, ?response);
        response
    }

    fn handle_transfer_out(&mut self, request: TransferOutRequest) -> TransferOutResponse {
        type Response = TransferOutResponse;
        trace!(hsm = self.name, ?request);

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
                delta = None;
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
                delta = Some(split_delta);
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

            leader.tree = keeping_partition
                .as_ref()
                .map(|p| Tree::with_existing_root(MerkleHasher(), p.root_hash));

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

        trace!(hsm = self.name, ?response);
        response
    }

    fn handle_transfer_nonce(&mut self, request: TransferNonceRequest) -> TransferNonceResponse {
        type Response = TransferNonceResponse;
        trace!(hsm = self.name, ?request);

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

            let nonce = TransferNonce::random(&mut self.rng);
            leader.incoming = Some(nonce);
            Response::Ok(nonce)
        })();

        trace!(hsm = self.name, ?response);
        response
    }

    fn handle_transfer_statement(
        &mut self,
        request: TransferStatementRequest,
    ) -> TransferStatementResponse {
        type Response = TransferStatementResponse;
        trace!(hsm = self.name, ?request);
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

        trace!(hsm = self.name, ?response);
        response
    }

    fn handle_transfer_in(&mut self, request: TransferInRequest) -> TransferInResponse {
        type Response = TransferInResponse;
        trace!(hsm = self.name, ?request);

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
                        Some(merge_result.delta),
                    ),
                }
            } else {
                (request.transferring, None)
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

            leader.tree = Some(Tree::with_existing_root(MerkleHasher(), partition_hash));
            Response::Ok { entry, delta }
        })();

        trace!(hsm = self.name, ?response);
        response
    }

    fn handle_complete_transfer(
        &mut self,
        request: CompleteTransferRequest,
    ) -> CompleteTransferResponse {
        type Response = CompleteTransferResponse;
        trace!(hsm = self.name, ?request);

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

        trace!(hsm = self.name, ?response);
        response
    }

    fn handle_app(&mut self, request: AppRequest) -> AppResponse {
        type Response = AppResponse;
        trace!(hsm = self.name, ?request);
        let hsm_name = &self.name;

        let response = match &self.persistent.realm {
            Some(realm) if realm.id == request.realm => {
                if realm.groups.contains_key(&request.group) {
                    if let Some(leader) = self.volatile.leader.get_mut(&request.group) {
                        if (leader.log.last().unwrap().entry)
                            .partition
                            .as_ref()
                            .filter(|partition| partition.range.contains(&request.rid))
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

        trace!(hsm = self.name, ?response);
        response
    }
}

fn handle_app_request(
    app_ctx: &app::AppContext,
    request: AppRequest,
    leaf_key: &RecordEncryptionKey,
    persistent: &PersistentState,
    leader: &mut LeaderVolatileGroupState,
) -> AppResponse {
    type Response = AppResponse;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let tree = leader
        .tree
        .as_mut()
        .expect("caller verified we're the leader");

    let tree_latest_proof = match tree.latest_proof(request.proof.clone()) {
        Ok(v) => v,
        Err(ProofError::Stale) => {
            info!(
                r = ?request.proof.key,
                root = ?request.proof.root_hash,
                "stale proof trying to get current value"
            );
            return Response::StaleProof;
        }
        Err(ProofError::Invalid) => {
            warn!("proof was flagged as invalid");
            return Response::InvalidProof;
        }
    };
    let latest_value = match &tree_latest_proof.leaf {
        None => None,
        Some(l) => {
            let cipher = Aes256Gcm::new_from_slice(&leaf_key.0).expect("couldn't create cipher");
            let nonce = Nonce::from_slice(&tree_latest_proof.key.0[..12]);
            let cipher_text: &[u8] = &l.value;
            match cipher.decrypt(nonce, cipher_text) {
                Ok(plain_text) => Some(plain_text),
                Err(e) => {
                    warn!(?e, "failed to decrypt leaf value");
                    return Response::InvalidRecordData;
                }
            }
        }
    };
    let last_entry = leader.log.last().unwrap();

    // The last 8 bytes of the value are a sequential update number to stop leaf
    // hashes repeating.
    let (update_num, value) = match &latest_value {
        Some(v) => {
            let (record, update_num) = v.split_at(
                v.len()
                    .checked_sub(8)
                    .expect("node should be at least 8 bytes"),
            );
            (
                u64::from_be_bytes(update_num.try_into().unwrap()),
                Some(record),
            )
        }
        None => (0, None),
    };
    let (client_response, change) = app::process(app_ctx, request.request, value);
    let (root_hash, delta) = match change {
        Some(change) => match change {
            RecordChange::Update(mut record) => {
                let cipher =
                    Aes256Gcm::new_from_slice(&leaf_key.0).expect("couldn't create cipher");
                // TODO: can we use this nonce to help generate unique leaf hashes?
                // TODO: can we use or add the previous root hash into this? (this seems hard as you need the same nonce to decode it)
                let nonce = Nonce::from_slice(&tree_latest_proof.key.0[..12]);
                record.extend_from_slice(&update_num.checked_add(1).unwrap().to_be_bytes());
                let plain_text: &[u8] = &record;

                // TODO: An optimization we could do is to use the authentication tag as the leaf's hash. Right now this is checking
                // the integrity of the record twice: once in the Merkle tree hash and once in the AES GCM tag.
                // We may also want to use the AD part of AEAD. For example, the generation number in the user's record isn't necessarily
                // private and could allow the agent to reply to some queries without the HSM getting involved.
                let cipher_text = cipher
                    .encrypt(nonce, plain_text)
                    .expect("couldn't encrypt record");

                match tree.insert(tree_latest_proof, cipher_text) {
                    Ok((root_hash, delta)) => (root_hash, delta),
                    Err(ProofError::Stale) => return Response::StaleProof,
                    Err(ProofError::Invalid) => return Response::InvalidProof,
                }
            }
        },
        None => (*tree_latest_proof.root_hash(), None),
    };

    let index = last_entry.entry.index.next();
    let partition = Some(Partition {
        range: last_entry.entry.partition.as_ref().unwrap().range.clone(),
        root_hash,
    });

    let transferring_out = last_entry.entry.transferring_out.clone();
    let prev_hmac = last_entry.entry.entry_hmac.clone();

    let entry_hmac = EntryHmacBuilder {
        realm: request.realm,
        group: request.group,
        index,
        partition: &partition,
        transferring_out: &transferring_out,
        prev_hmac: &prev_hmac,
    }
    .build(&persistent.realm_key);

    let new_entry = LogEntry {
        index,
        partition,
        transferring_out,
        prev_hmac,
        entry_hmac,
    };

    leader.log.push(LeaderLogEntry {
        entry: new_entry.clone(),
        response: Some(client_response),
    });
    Response::Ok {
        entry: new_entry,
        delta,
    }
}

#[cfg(test)]
mod test {
    use super::{
        super::bitvec,
        super::merkle::{agent::StoreKey, NodeHasher},
        types::DataHash,
        MerkleHasher,
    };

    #[test]
    fn test_store_key_parse_datahash() {
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
}
