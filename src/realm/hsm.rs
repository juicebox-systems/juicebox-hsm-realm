use actix::prelude::*;
use digest::Digest;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::fmt;
use tracing::{info, trace, warn};

pub mod types;

use types::{
    BecomeLeaderRequest, BecomeLeaderResponse, CaptureNextRequest, CaptureNextResponse,
    CapturedStatement, CommitRequest, CommitResponse, Configuration, DataHash, EntryHmac,
    GroupConfigurationStatement, GroupId, GroupStatus, HsmId, JoinGroupRequest, JoinGroupResponse,
    JoinRealmRequest, JoinRealmResponse, LogEntry, LogIndex, NewRealmRequest, NewRealmResponse,
    NewRealmResponseOk, OwnedPrefix, ReadCapturedRequest, ReadCapturedResponse, RealmId,
    RealmStatus, StatusRequest, StatusResponse,
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
        let mut id = digest::Key::<Hmac<Sha256>>::default();
        OsRng.fill_bytes(&mut id);
        Self(id)
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
    owned_prefix: &'a OwnedPrefix,
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
        mac.update(&self.owned_prefix.bits.to_be_bytes());
        mac.update(b"|");
        mac.update(&self.owned_prefix.mask.to_be_bytes());
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
    #[allow(dead_code)]
    log: VolatileLog,
    committed: Option<LogIndex>,
}

struct VolatileLog {
    #[allow(dead_code)]
    start_index: LogIndex,
    #[allow(dead_code)]
    entries: Vec<LogEntry>,
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
}

impl Actor for Hsm {
    type Context = Context<Self>;
}

impl Handler<StatusRequest> for Hsm {
    type Result = StatusResponse;

    fn handle(&mut self, request: StatusRequest, _ctx: &mut Context<Self>) -> Self::Result {
        trace!(hsm = self.name, ?request);
        let response = StatusResponse {
            id: self.persistent.id,
            realm: self.persistent.realm.as_ref().map(|realm| RealmStatus {
                id: realm.id,
                groups: realm
                    .groups
                    .iter()
                    .map(|(group_id, group)| {
                        let configuration = group.configuration.clone();
                        let captured = group.captured.clone();
                        match self.volatile.leader.get(group_id) {
                            Some(leader) => GroupStatus {
                                id: *group_id,
                                configuration,
                                is_leader: true,
                                captured,
                                committed: leader.committed,
                            },
                            None => GroupStatus {
                                id: *group_id,
                                configuration,
                                is_leader: false,
                                captured,
                                committed: None,
                            },
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
            let group_id = GroupId::random();
            let statement = GroupConfigurationStatementBuilder {
                realm: realm_id,
                group: group_id,
                configuration: &request.configuration,
            }
            .build(&self.persistent.realm_key);
            self.persistent.realm = Some(PersistentRealmState {
                id: realm_id,
                groups: HashMap::from([(
                    group_id,
                    PersistentGroupState {
                        configuration: request.configuration,
                        captured: None,
                    },
                )]),
            });

            let index = LogIndex(1);
            let owned_prefix = OwnedPrefix { bits: 0, mask: 0 };
            let data = Vec::new();
            let data_hash = DataHash(Sha256::digest(&data));
            let prev_hmac = EntryHmac::zero();

            let entry_hmac = EntryHmacBuilder {
                realm: realm_id,
                group: group_id,
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
                group_id,
                LeaderVolatileGroupState {
                    log: VolatileLog {
                        start_index: index,
                        entries: Vec::from([entry.clone()]),
                    },
                    committed: None,
                },
            );

            Response::Ok(NewRealmResponseOk {
                realm: realm_id,
                group: group_id,
                statement,
                entry,
                data,
            })
        };
        trace!(hsm = self.name, ?response);
        response
    }
}

impl Handler<JoinRealmRequest> for Hsm {
    type Result = JoinRealmResponse;

    fn handle(&mut self, request: JoinRealmRequest, _ctx: &mut Context<Self>) -> Self::Result {
        trace!(hsm = self.name, ?request);
        let response = if self.persistent.realm.is_some() {
            JoinRealmResponse::HaveRealm
        } else {
            self.persistent.realm = Some(PersistentRealmState {
                id: request.realm,
                groups: HashMap::new(),
            });
            JoinRealmResponse::Ok
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
                                if request.index != LogIndex(captured_index.0 + 1) {
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
                            Some((captured_index, _captured_hmac)) => {
                                if request.index != *captured_index {
                                    return Response::NotCaptured {
                                        have: Some(*captured_index),
                                    };
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
                    log: VolatileLog {
                        start_index: LogIndex(request.index.0 + 1),
                        entries: Vec::new(),
                    },
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

        let response = (|| match &self.persistent.realm {
            None => Response::InvalidRealm,

            Some(realm) => {
                if realm.id != request.realm {
                    return Response::InvalidRealm;
                }

                match realm.groups.get(&request.group) {
                    None => Response::InvalidGroup,

                    Some(group) => {
                        let leader = match self.volatile.leader.get_mut(&request.group) {
                            Some(leader) => {
                                if let Some(i) = leader.committed {
                                    if i > request.index {
                                        return Response::Ok {
                                            committed: leader.committed,
                                        };
                                    }
                                }
                                leader
                            }
                            None => return Response::NotLeader,
                        };

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
                                    if *index == request.index
                                        && *entry_hmac == request.entry_hmac =>
                                {
                                    Some(self.persistent.id)
                                }
                                _ => None,
                            })
                            .collect::<HashSet<HsmId>>()
                            .len();

                        if captures > group.configuration.0.len() / 2 {
                            info!(hsm = self.name, index = ?request.index, "leader committed entry");
                            leader.committed = Some(request.index);
                            CommitResponse::Ok {
                                committed: leader.committed,
                            }
                        } else {
                            warn!(hsm = self.name, "no quorum. buggy caller?");
                            CommitResponse::NoQuorum
                        }
                    }
                }
            }
        })();

        trace!(hsm = self.name, ?response);
        response
    }
}
