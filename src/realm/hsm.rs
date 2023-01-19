use actix::prelude::*;
use digest::Digest;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use tracing::{info, trace, warn};

mod app;
pub mod types;

use app::RecordChange;
use types::{
    AppRequest, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse, CaptureNextRequest,
    CaptureNextResponse, CapturedStatement, CommitRequest, CommitResponse, Configuration, DataHash,
    EntryHmac, GroupConfigurationStatement, GroupId, GroupStatus, HsmId, JoinGroupRequest,
    JoinGroupResponse, JoinRealmRequest, JoinRealmResponse, LeaderStatus, LogEntry, LogIndex,
    NewGroupInfo, NewGroupRequest, NewGroupResponse, NewRealmRequest, NewRealmResponse,
    OwnedPrefix, ReadCapturedRequest, ReadCapturedResponse, RealmId, RealmStatus, RecordMap,
    SecretsResponse, StatusRequest, StatusResponse, UserId,
};

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
    owned_prefix: &'a Option<OwnedPrefix>,
    data_hash: &'a DataHash,
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
        match self.owned_prefix {
            Some(owned_prefix) => {
                for bit in owned_prefix.0.iter() {
                    mac.update(if *bit { b"1" } else { b"0" });
                }
            }
            None => mac.update(b"none"),
        }
        mac.update(b"|");
        mac.update(&self.data_hash.0);
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
}

impl RecordMap {
    fn new() -> Self {
        Self(BTreeMap::new())
    }

    fn hash(&self) -> DataHash {
        let mut hash = Sha256::new();
        for (uid, record) in &self.0 {
            for bit in &uid.0 {
                if *bit {
                    hash.update(b"1");
                } else {
                    hash.update(b"0");
                }
            }
            hash.update(":");
            hash.update(record.serialized());
            hash.update(";");
        }
        DataHash(hash.finalize())
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
}

struct LeaderLogEntry {
    entry: LogEntry,
    /// If set, this is a change to the data that resulted in the log entry.
    /// If `None`, either the change happened before this HSM became leader,
    /// or the log entry didn't change the data.
    delta: Option<(UserId, RecordChange)>,
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
        let data = RecordMap::new();
        let data_hash = data.hash();
        let prev_hmac = EntryHmac::zero();

        let entry_hmac = EntryHmacBuilder {
            realm,
            group,
            index,
            owned_prefix: &owned_prefix,
            data_hash: &data_hash,
            prev_hmac: &prev_hmac,
        }
        .build(&self.persistent.realm_key);

        let entry = LogEntry {
            index,
            owned_prefix,
            data_hash,
            prev_hmac,
            entry_hmac,
        };

        self.volatile.leader.insert(
            group,
            LeaderVolatileGroupState {
                log: vec![LeaderLogEntry {
                    entry: entry.clone(),
                    delta: None,
                    response: None,
                }],
                committed: None,
            },
        );

        NewGroupInfo {
            realm,
            group,
            statement,
            entry,
            data,
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
                                            .owned_prefix
                                            .clone(),
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

                if (EntryHmacBuilder {
                    realm: request.realm,
                    group: request.group,
                    index: request.index,
                    owned_prefix: &request.owned_prefix,
                    data_hash: &request.data_hash,
                    prev_hmac: &request.prev_hmac,
                })
                .verify(&self.persistent.realm_key, &request.entry_hmac)
                .is_err()
                {
                    return Response::InvalidHmac;
                }

                match realm.groups.get_mut(&request.group) {
                    None => Response::InvalidGroup,

                    Some(group) => {
                        match &group.captured {
                            None => {
                                if request.index != LogIndex(1) {
                                    return Response::MissingPrev;
                                }
                                if request.prev_hmac != EntryHmac::zero() {
                                    return Response::InvalidChain;
                                }
                            }
                            Some((captured_index, captured_hmac)) => {
                                if request.index != captured_index.next() {
                                    return Response::MissingPrev;
                                }
                                if request.prev_hmac != *captured_hmac {
                                    return Response::InvalidChain;
                                }
                            }
                        }

                        let statement = CapturedStatementBuilder {
                            hsm: self.persistent.id,
                            realm: request.realm,
                            group: request.group,
                            index: request.index,
                            entry_hmac: &request.entry_hmac,
                        }
                        .build(&self.persistent.realm_key);
                        group.captured = Some((request.index, request.entry_hmac));
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
                                if (EntryHmacBuilder {
                                    realm: request.realm,
                                    group: request.group,
                                    index: request.last_entry.index,
                                    owned_prefix: &request.last_entry.owned_prefix,
                                    data_hash: &request.last_entry.data_hash,
                                    prev_hmac: &request.last_entry.prev_hmac,
                                })
                                .verify(&self.persistent.realm_key, &request.last_entry.entry_hmac)
                                .is_err()
                                {
                                    return Response::InvalidHmac;
                                }
                            }
                        },
                    }
                }
            }

            self.volatile
                .leader
                .entry(request.group)
                .or_insert_with(|| LeaderVolatileGroupState {
                    log: vec![LeaderLogEntry {
                        entry: request.last_entry,
                        delta: None,
                        response: None,
                    }],
                    committed: None,
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
                info!(hsm = self.name, index = ?request.index, "leader committed entry");
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

impl Handler<AppRequest> for Hsm {
    type Result = AppResponse;

    fn handle(&mut self, request: AppRequest, _ctx: &mut Context<Self>) -> Self::Result {
        type Response = AppResponse;
        trace!(hsm = self.name, ?request);

        let response = match &self.persistent.realm {
            Some(realm) if realm.id == request.realm => {
                if realm.groups.contains_key(&request.group) {
                    if let Some(leader) = self.volatile.leader.get_mut(&request.group) {
                        handle_app_request(request, &self.persistent, leader)
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

    let mut data = {
        let start_index = leader.log.first().expect("log never empty").entry.index;
        let Some(offset) =
            (request.index.0)
            .checked_sub(start_index.0)
            .and_then(|offset| usize::try_from(offset).ok()) else {
            return Response::StaleIndex;
        };

        let mut iter = leader.log.iter().skip(offset);
        if let Some(request_entry) = iter.next() {
            if request_entry.entry.data_hash != request.data.hash() {
                return Response::InvalidData;
            }
        } else {
            return Response::StaleIndex;
        };

        let mut data = request.data;
        for entry in iter.clone() {
            match &entry.delta {
                Some((uid, change)) => {
                    if *uid == request.uid {
                        return Response::Busy;
                    }
                    match change {
                        RecordChange::Update(record) => {
                            data.0.insert(uid.clone(), record.clone());
                        }
                        RecordChange::Delete => {
                            data.0.remove(uid);
                        }
                    }
                }
                None => {}
            }
        }
        data
    };
    let last_entry = leader.log.last().unwrap();

    let record = data.0.get(&request.uid);
    let (client_response, change) = app::process(request.request, record);
    let delta = match change {
        Some(change) => {
            match &change {
                RecordChange::Update(record) => {
                    data.0.insert(request.uid.clone(), record.clone());
                }
                RecordChange::Delete => {
                    data.0.remove(&request.uid);
                }
            }
            Some((request.uid, change))
        }
        None => None,
    };

    let index = last_entry.entry.index.next();
    let owned_prefix = last_entry.entry.owned_prefix.clone();
    let data_hash = data.hash();
    let prev_hmac = last_entry.entry.entry_hmac.clone();

    let entry_hmac = EntryHmacBuilder {
        realm: request.realm,
        group: request.group,
        index,
        owned_prefix: &owned_prefix,
        data_hash: &data_hash,
        prev_hmac: &prev_hmac,
    }
    .build(&persistent.realm_key);

    let new_entry = LogEntry {
        index,
        owned_prefix,
        data_hash,
        prev_hmac,
        entry_hmac,
    };

    leader.log.push(LeaderLogEntry {
        entry: new_entry.clone(),
        delta,
        response: Some(client_response),
    });
    Response::Ok {
        entry: new_entry,
        data,
    }
}
