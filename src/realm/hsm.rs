use actix::prelude::*;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::fmt;
use tracing::{info, trace, warn};

mod app;
pub mod types;

use crate::realm::merkle::TreeError;

use super::merkle::{NodeHasher, Tree};
use app::RecordChange;
use types::{
    AppRequest, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse, CaptureNextRequest,
    CaptureNextResponse, CapturedStatement, CommitRequest, CommitResponse, CompleteTransferRequest,
    CompleteTransferResponse, Configuration, DataHash, EntryHmac, GroupConfigurationStatement,
    GroupId, GroupStatus, HsmId, JoinGroupRequest, JoinGroupResponse, JoinRealmRequest,
    JoinRealmResponse, LeaderStatus, LogEntry, LogIndex, NewGroupInfo, NewGroupRequest,
    NewGroupResponse, NewRealmRequest, NewRealmResponse, OwnedPrefix, ReadCapturedRequest,
    ReadCapturedResponse, RealmId, RealmStatus, RecordId, SecretsResponse, StatusRequest,
    StatusResponse, TransferInRequest, TransferInResponse, TransferNonce, TransferNonceRequest,
    TransferNonceResponse, TransferOutRequest, TransferOutResponse, TransferStatement,
    TransferStatementRequest, TransferStatementResponse, TransferringOut,
};

use self::types::Partition;

#[derive(Clone)]
pub struct RealmKey(digest::Key<Hmac<Sha256>>);

impl fmt::Debug for RealmKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

impl RealmKey {
    pub fn random() -> Self {
        let mut key = digest::Key::<Hmac<Sha256>>::default();
        OsRng.fill_bytes(&mut key);
        Self(key)
    }
}

impl GroupId {
    fn random() -> Self {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        Self(id)
    }
}

impl HsmId {
    fn random() -> Self {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        Self(id)
    }
}

impl RealmId {
    fn random() -> Self {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
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
                for bit in &p.prefix.0 {
                    mac.update(if *bit { b"1" } else { b"0" });
                }
                mac.update(b"|");
                mac.update(&p.root_hash.0);
            }
            None => mac.update(b"none|none"),
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
                for bit in &partition.prefix.0 {
                    mac.update(if *bit { b"1" } else { b"0" });
                }
                mac.update(b"|");
                mac.update(&partition.root_hash.0);
                mac.update(b"|");
                mac.update(&at.0.to_be_bytes());
            }
            None => {
                mac.update(b"none|none|none|none");
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
    pub fn random() -> Self {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
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
        for bit in &self.partition.prefix.0 {
            mac.update(if *bit { b"1" } else { b"0" });
        }
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

struct MerkleHasher(RealmKey);
impl NodeHasher<DataHash> for MerkleHasher {
    fn calc_hash(&self, parts: &[&[u8]]) -> DataHash {
        let mut h = Hmac::<Sha256>::new(&self.0 .0);
        for p in parts {
            h.update(p);
        }
        DataHash(h.finalize().into_bytes())
    }
}

pub struct Hsm {
    name: String,
    persistent: PersistentState,
    volatile: VolatileState,
}

struct PersistentState {
    id: HsmId,
    realm_key: RealmKey,
    realm: Option<PersistentRealmState>,
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

impl Hsm {
    pub fn new(name: String, realm_key: RealmKey) -> Self {
        Self {
            name,
            persistent: PersistentState {
                id: HsmId::random(),
                realm_key,
                realm: None,
            },
            volatile: VolatileState {
                leader: HashMap::new(),
            },
        }
    }

    fn create_new_group(
        &mut self,
        realm: RealmId,
        configuration: Configuration,
        owned_prefix: Option<OwnedPrefix>,
    ) -> NewGroupInfo {
        let group = GroupId::random();
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

        let index = LogIndex(1);
        let (partition, data) = match &owned_prefix {
            None => (None, None),
            Some(prefix) => {
                let h = MerkleHasher(self.persistent.realm_key.clone());
                let (root_hash, delta) = Tree::new_tree(&h, &prefix.0);
                (
                    Some(Partition {
                        prefix: prefix.clone(),
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
                tree: partition.as_ref().map(|p| {
                    Tree::with_existing_root(
                        MerkleHasher(self.persistent.realm_key.clone()),
                        RecordId::size(),
                        p.root_hash,
                    )
                }),
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
}

impl Actor for Hsm {
    type Context = Context<Self>;
}

impl Handler<StatusRequest> for Hsm {
    type Result = StatusResponse;

    fn handle(&mut self, request: StatusRequest, _ctx: &mut Context<Self>) -> Self::Result {
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
                                        owned_prefix: leader
                                            .log
                                            .last()
                                            .expect("leader's log is never empty")
                                            .entry
                                            .partition
                                            .as_ref()
                                            .map(|p| p.prefix.clone()),
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
}

impl Handler<NewRealmRequest> for Hsm {
    type Result = NewRealmResponse;

    fn handle(&mut self, request: NewRealmRequest, _ctx: &mut Context<Self>) -> Self::Result {
        type Response = NewRealmResponse;
        trace!(hsm = self.name, ?request);
        let response = if self.persistent.realm.is_some() {
            Response::HaveRealm
        } else if !request.configuration.is_ok()
            || !request.configuration.0.contains(&self.persistent.id)
        {
            Response::InvalidConfiguration
        } else {
            let realm_id = RealmId::random();
            self.persistent.realm = Some(PersistentRealmState {
                id: realm_id,
                groups: HashMap::new(),
            });
            let group_info =
                self.create_new_group(realm_id, request.configuration, Some(OwnedPrefix::full()));
            Response::Ok(group_info)
        };
        trace!(hsm = self.name, ?response);
        response
    }
}

impl Handler<JoinRealmRequest> for Hsm {
    type Result = JoinRealmResponse;

    fn handle(&mut self, request: JoinRealmRequest, _ctx: &mut Context<Self>) -> Self::Result {
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
}

impl Handler<NewGroupRequest> for Hsm {
    type Result = NewGroupResponse;

    fn handle(&mut self, request: NewGroupRequest, _ctx: &mut Context<Self>) -> Self::Result {
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
            let owned_prefix: Option<OwnedPrefix> = None;
            let group_info =
                self.create_new_group(request.realm, request.configuration, owned_prefix);
            Response::Ok(group_info)
        };
        trace!(hsm = self.name, ?response);
        response
    }
}

impl Handler<JoinGroupRequest> for Hsm {
    type Result = JoinGroupResponse;

    fn handle(&mut self, request: JoinGroupRequest, _ctx: &mut Context<Self>) -> Self::Result {
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
}

impl Handler<CaptureNextRequest> for Hsm {
    type Result = CaptureNextResponse;

    fn handle(&mut self, request: CaptureNextRequest, _ctx: &mut Context<Self>) -> Self::Result {
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
                                if request.entry.index != LogIndex(1) {
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
}

impl Handler<BecomeLeaderRequest> for Hsm {
    type Result = BecomeLeaderResponse;

    fn handle(&mut self, request: BecomeLeaderRequest, _ctx: &mut Context<Self>) -> Self::Result {
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

            let tree = request.last_entry.partition.as_ref().map(|p| {
                Tree::with_existing_root(
                    MerkleHasher(self.persistent.realm_key.clone()),
                    RecordId::size(),
                    p.root_hash,
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
                });
            Response::Ok
        })();

        trace!(hsm = self.name, ?response);
        response
    }
}

impl Handler<ReadCapturedRequest> for Hsm {
    type Result = ReadCapturedResponse;

    fn handle(&mut self, request: ReadCapturedRequest, _ctx: &mut Context<Self>) -> Self::Result {
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
}

impl Handler<CommitRequest> for Hsm {
    type Result = CommitResponse;

    fn handle(&mut self, request: CommitRequest, _ctx: &mut Context<Self>) -> Self::Result {
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
}

impl Handler<TransferOutRequest> for Hsm {
    type Result = TransferOutResponse;

    fn handle(&mut self, request: TransferOutRequest, _ctx: &mut Context<Self>) -> Self::Result {
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

            // Note: The owned_prefix found in the last entry might not have
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

            // This support two options: moving out the entire owned
            // prefix, or moving out the owned prefix plus one more bit.
            let keeping_partition: Option<Partition>;
            let transferring_partition: Partition;
            let delta;

            if request.prefix == owned_partition.prefix {
                keeping_partition = None;
                transferring_partition = owned_partition.clone();
                delta = None;
            } else if request.prefix.0.len() == owned_partition.prefix.0.len() + 1
                && request.prefix.0.starts_with(&owned_partition.prefix.0)
            {
                let Some(tree) = &mut leader.tree else {
                    return Response::NotLeader;
                };
                let (keeping, transferring, split_delta) =
                    match tree.split_tree(&owned_partition.prefix.0, request.proof) {
                        Err(TreeError::StaleProof) => return Response::StaleProof,
                        Err(TreeError::InvalidProof) => return Response::InvalidProof,
                        Err(TreeError::InvalidKey) => return Response::InvalidProof,
                        Ok(split) => {
                            if split.left.prefix == request.prefix.0 {
                                (split.right, split.left, split.delta)
                            } else if split.right.prefix == request.prefix.0 {
                                (split.left, split.right, split.delta)
                            } else {
                                panic!(
                                "The tree was split but neither half contains the expected prefix."
                            );
                            }
                        }
                    };
                keeping_partition = Some(Partition {
                    root_hash: keeping.root_hash,
                    prefix: OwnedPrefix(keeping.prefix),
                });
                transferring_partition = Partition {
                    root_hash: transferring.root_hash,
                    prefix: OwnedPrefix(transferring.prefix),
                };
                delta = Some(split_delta);
            } else {
                return Response::NotOwner;
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

            leader.tree = match &keeping_partition {
                None => None,
                Some(p) => Some(Tree::with_existing_root(
                    MerkleHasher(self.persistent.realm_key.clone()),
                    RecordId::size(),
                    p.root_hash,
                )),
            };

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
}

impl Handler<TransferNonceRequest> for Hsm {
    type Result = TransferNonceResponse;

    fn handle(&mut self, request: TransferNonceRequest, _ctx: &mut Self::Context) -> Self::Result {
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

            let nonce = TransferNonce::random();
            leader.incoming = Some(nonce);
            Response::Ok(nonce)
        })();

        trace!(hsm = self.name, ?response);
        response
    }
}

impl Handler<TransferStatementRequest> for Hsm {
    type Result = TransferStatementResponse;

    fn handle(
        &mut self,
        request: TransferStatementRequest,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
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
}

impl Handler<TransferInRequest> for Hsm {
    type Result = TransferInResponse;

    fn handle(&mut self, request: TransferInRequest, _ctx: &mut Self::Context) -> Self::Result {
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
            if last_entry.partition.is_some() {
                // merging prefixes is currently unsupported
                return Response::UnacceptablePrefix;
            }

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

            let index = last_entry.index.next();
            let partition_hash = request.transferring.root_hash;
            let partition = Some(request.transferring);
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
                MerkleHasher(self.persistent.realm_key.clone()),
                RecordId::size(),
                partition_hash,
            ));
            Response::Ok { entry }
        })();

        trace!(hsm = self.name, ?response);
        response
    }
}

impl Handler<CompleteTransferRequest> for Hsm {
    type Result = CompleteTransferResponse;

    fn handle(
        &mut self,
        request: CompleteTransferRequest,
        _ctx: &mut Context<Self>,
    ) -> Self::Result {
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
                    || transferring_out.partition.prefix != request.prefix
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
}

impl Handler<AppRequest> for Hsm {
    type Result = AppResponse;

    fn handle(&mut self, request: AppRequest, _ctx: &mut Context<Self>) -> Self::Result {
        type Response = AppResponse;
        trace!(hsm = self.name, ?request);

        let response = match &self.persistent.realm {
            Some(realm) if realm.id == request.realm => {
                if realm.groups.contains_key(&request.group) {
                    if let Some(leader) = self.volatile.leader.get_mut(&request.group) {
                        if (leader.log.last().unwrap().entry)
                            .partition
                            .as_ref()
                            .filter(|partition| partition.prefix.contains(&request.rid))
                            .is_some()
                        {
                            handle_app_request(request, &self.persistent, leader)
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
    request: AppRequest,
    persistent: &PersistentState,
    leader: &mut LeaderVolatileGroupState,
) -> AppResponse {
    type Response = AppResponse;

    let tree = leader
        .tree
        .as_mut()
        .expect("caller verified we're the leader");

    let latest_value = match tree.latest_value(request.proof.clone()) {
        Ok(v) => v,
        Err(TreeError::StaleProof) => {
            info!(
                r = ?request.proof.key,
                root = ?request.proof.root_hash(),
                "stale proof trying to get current value"
            );
            return Response::StaleProof;
        }
        Err(err) => {
            warn!(err=?err, "failed to get latest tree value");
            return Response::InvalidData;
        }
    };

    let last_entry = leader.log.last().unwrap();

    let (client_response, change) = app::process(request.request, latest_value);
    let delta = match change {
        Some(change) => match change {
            RecordChange::Update(record) => match tree.insert(request.proof, record) {
                Ok(None) => None,
                Ok(Some(d)) => Some((*d.root(), d.store_delta())),
                Err(_) => return Response::InvalidData,
            },
            RecordChange::Delete => todo!(),
        },
        None => None,
    };

    let index = last_entry.entry.index.next();
    let mut partition = last_entry.entry.partition.as_ref().unwrap().clone();
    if let Some((root_hash, _)) = &delta {
        partition.root_hash = *root_hash;
    }
    let partition = Some(partition);

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
        delta: delta.map(|(_, sd)| sd),
    }
}
