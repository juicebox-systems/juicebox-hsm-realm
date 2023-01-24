use actix::clock::sleep;
use actix::fut::future::LocalBoxActorFuture;
use actix::prelude::*;
use futures::channel::oneshot;
use futures::future;
use futures::future::join_all;
use futures::Future;
use std::collections::btree_map::Entry::{Occupied, Vacant};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{info, trace, warn};

pub mod types;

use super::hsm::types as hsm_types;
use super::hsm::Hsm;
use super::store::types::{
    AddressEntry, AppendRequest, AppendResponse, DataChange, GetAddressesRequest,
    GetAddressesResponse, ReadEntryRequest, ReadEntryResponse, ReadLatestRequest,
    ReadLatestResponse, SetAddressRequest, SetAddressResponse,
};
use super::store::Store;
use hsm_types::{
    CaptureNextRequest, CaptureNextResponse, CapturedStatement, CommitRequest, CommitResponse,
    EntryHmac, GroupId, HsmId, LogIndex, RealmId, SecretsResponse,
};
use types::{
    AppRequest, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse, CompleteTransferRequest,
    CompleteTransferResponse, JoinGroupRequest, JoinGroupResponse, JoinRealmRequest,
    JoinRealmResponse, NewGroupRequest, NewGroupResponse, NewRealmRequest, NewRealmResponse,
    ReadCapturedRequest, ReadCapturedResponse, StatusRequest, StatusResponse, TransferInRequest,
    TransferInResponse, TransferNonceRequest, TransferNonceResponse, TransferOutRequest,
    TransferOutResponse, TransferStatementRequest, TransferStatementResponse,
};

#[derive(Debug)]
pub struct Agent {
    name: String,
    hsm: Addr<Hsm>,
    store: Addr<Store>,
    leader: HashMap<(RealmId, GroupId), LeaderState>,
}

#[derive(Debug)]
struct LeaderState {
    /// Log entries may be received out of order from the HSM. They are buffered
    /// here until they can be appended to the log in order.
    append_queue: HashMap<LogIndex, AppendRequest>,
    /// This serves as a mutex to prevent multiple concurrent appends to the
    /// store.
    appending: AppendingState,
    response_channels: HashMap<EntryHmac, oneshot::Sender<SecretsResponse>>,
}

#[derive(Debug)]
enum AppendingState {
    NotAppending { next: LogIndex },
    Appending,
}
use AppendingState::{Appending, NotAppending};

impl Agent {
    pub fn new(name: String, hsm: Addr<Hsm>, store: Addr<Store>) -> Self {
        Self {
            name,
            hsm,
            store,
            leader: HashMap::new(),
        }
    }

    fn start_watching(
        &mut self,
        realm: RealmId,
        group: GroupId,
        next_index: LogIndex,
        ctx: &mut Context<Self>,
    ) {
        let name = self.name.clone();
        trace!(agent = name, realm = ?realm, group = ?group, ?next_index, "start watching log");
        let hsm = self.hsm.clone();
        let store = self.store.clone();
        ctx.spawn(
            async move {
                match store
                    .send(ReadEntryRequest {
                        realm,
                        group,
                        index: next_index,
                    })
                    .await
                {
                    Err(_) => todo!(),
                    Ok(ReadEntryResponse::Discarded { .. }) => todo!(),
                    Ok(ReadEntryResponse::DoesNotExist { .. }) => {
                        sleep(Duration::from_millis(1)).await;
                        next_index
                    }
                    Ok(ReadEntryResponse::Ok(entry)) => {
                        let index = entry.index;
                        trace!(agent = name, ?realm, ?group, ?index, "found log entry");
                        match hsm
                            .send(CaptureNextRequest {
                                realm,
                                group,
                                entry,
                            })
                            .await
                        {
                            Err(_) => todo!(),
                            Ok(CaptureNextResponse::Ok { hsm_id, .. }) => {
                                trace!(agent = name, ?realm, ?group, hsm=?hsm_id, ?index,
                                    "HSM captured entry");
                                // TODO: cache capture statement
                                next_index.next()
                            }
                            Ok(r) => todo!("{r:#?}"),
                        }
                    }
                }
            }
            .into_actor(self)
            .map(move |next_index, agent, ctx| agent.start_watching(realm, group, next_index, ctx)),
        );
    }

    fn collect_captures(&mut self, realm_id: RealmId, group_id: GroupId, ctx: &mut Context<Self>) {
        let name = self.name.clone();
        trace!(agent = name, realm = ?realm_id, group = ?group_id, "start collecting captures");
        let hsm = self.hsm.clone();
        ctx.spawn(Box::pin(
            self.find_peers(realm_id, group_id)
                .into_actor(self)
                .map(move |peers, agent, ctx| {
                    let peers = peers.expect("todo");
                    let futures = peers.iter().filter_map(|(hsm_id, address)| {
                        address.clone().map(|address| {
                            agent.read_captured(realm_id, group_id, *hsm_id, address)
                        })
                    });
                    ctx.spawn(Box::pin(join_all(futures).into_actor(agent).map(
                        move |captures, agent, ctx| {
                            let mut map: BTreeMap<
                                LogIndex,
                                (EntryHmac, Vec<(HsmId, CapturedStatement)>),
                            > = BTreeMap::new();
                            #[allow(clippy::manual_flatten)]
                            for capture in captures {
                                if let Ok(ReadCapturedResponse::Ok {
                                    hsm_id,
                                    index,
                                    entry_hmac,
                                    statement,
                                }) = capture
                                {
                                    match map.entry(index) {
                                        Occupied(mut entry) => {
                                            let value = entry.get_mut();
                                            if entry_hmac != value.0 {
                                                todo!();
                                            }
                                            value.1.push((hsm_id, statement));
                                        }
                                        Vacant(entry) => {
                                            entry.insert((
                                                entry_hmac,
                                                Vec::from([(hsm_id, statement)]),
                                            ));
                                        }
                                    }
                                }
                            }

                            let mut commit_request: Option<CommitRequest> = None;
                            for (index, (entry_hmac, captures)) in map.into_iter() {
                                if captures.len() >= (peers.len() + 1) / 2 {
                                    commit_request = Some(CommitRequest {
                                        realm: realm_id,
                                        group: group_id,
                                        index,
                                        entry_hmac,
                                        captures,
                                    });
                                }
                            }

                            ctx.spawn(Box::pin(
                                async move {
                                    if let Some(commit_request) = commit_request {
                                        trace!(
                                            agent = name,
                                            index = ?commit_request.index,
                                            num_captures = commit_request.captures.len(),
                                            "requesting HSM to commit index");
                                        let response = hsm.send(commit_request).await;
                                        match response {
                                            Ok(CommitResponse::Ok {
                                                committed,
                                                responses,
                                            }) => {
                                                trace!(
                                                    agent = name,
                                                    ?committed,
                                                    ?responses,
                                                    "HSM committed entry"
                                                );
                                                responses
                                            },
                                            Ok(CommitResponse::AlreadyCommitted { .. }) => {
                                                // TODO: this happens a lot now
                                                // because this doesn't remember
                                                // what it's already asked the HSM
                                                // to commit.
                                                trace!(
                                                    agent = name,
                                                    ?response,
                                                    "commit response not ok"
                                                );
                                                Vec::new()
                                            },
                                            _ =>{
                                                warn!(
                                                    agent = name,
                                                    ?response,
                                                    "commit response not ok"
                                                );
                                                Vec::new()
                                            }
                                        }
                                    } else {
                                        Vec::new()
                                    }
                                }
                                .into_actor(agent)
                                .then(
                                    move |responses, agent, _ctx| {
                                        if let Some(leader) =
                                            agent.leader.get_mut(&(realm_id, group_id))
                                        {
                                            for (hmac, client_response) in responses {
                                                if let Some(sender) =
                                                    leader.response_channels.remove(&hmac)
                                                {
                                                    if sender.send(client_response).is_err() {
                                                        warn!("dropping response on the floor: client no longer waiting");
                                                    }
                                                } else {
                                                    warn!("dropping response on the floor: client never waiting");
                                                }
                                            }
                                        } else if !responses.is_empty() {
                                            warn!("dropping responses on the floor: no leader state");
                                        }
                                    Box::pin(sleep(Duration::from_millis(10)).into_actor(agent))
                                })
                                .map(move |_, agent, ctx| {
                                    agent.collect_captures(realm_id, group_id, ctx)
                                })
                            ));
                        },
                    )));
                }),
        ));
    }

    fn find_peers(
        &mut self,
        realm_id: RealmId,
        group_id: GroupId,
    ) -> impl Future<Output = Result<HashMap<HsmId, Option<Addr<Agent>>>, ()>> {
        let name = self.name.clone();
        let hsm = self.hsm.clone();
        let store = self.store.clone();
        async move {
            let mut peers: HashMap<HsmId, Option<Addr<Agent>>> =
                match hsm.send(hsm_types::StatusRequest {}).await {
                    Err(_) => todo!(),
                    Ok(hsm_types::StatusResponse {
                        id: hsm_id,
                        realm: Some(realm),
                    }) => {
                        if realm.id != realm_id {
                            todo!();
                        }
                        match realm.groups.into_iter().find(|group| group.id == group_id) {
                            None => todo!(),
                            Some(group) => HashMap::from_iter(
                                group
                                    .configuration
                                    .0
                                    .into_iter()
                                    .filter(|id| *id != hsm_id)
                                    .map(|id| (id, None)),
                            ),
                        }
                    }
                    _ => todo!(),
                };
            trace!(agent = name, peer_hsms = ?peers.keys(), "found peer HSMs from configuration");

            match store.send(GetAddressesRequest {}).await {
                Err(_) => todo!(),
                Ok(GetAddressesResponse(addresses)) => {
                    for AddressEntry { hsm, address } in addresses {
                        peers.entry(hsm).and_modify(|e| *e = Some(address));
                    }
                }
            };
            trace!(
                agent = name,
                peers = ?peers
                    .iter()
                    .map(|(id, addr)| {
                         // Actix addresses aren't printable.
                        (id, addr.is_some())
                    })
                    .collect::<Vec<_>>(),
                "looked up peer agent addresses from store"
            );
            Ok(peers)
        }
    }

    fn read_captured(
        &mut self,
        realm_id: RealmId,
        group_id: GroupId,
        hsm_id: HsmId,
        address: Addr<Agent>,
    ) -> impl Future<Output = Result<ReadCapturedResponse, actix::MailboxError>> {
        async move {
            address
                .send(ReadCapturedRequest {
                    realm: realm_id,
                    group: group_id,
                })
                .await
                .map(|result| match result {
                    ReadCapturedResponse::Ok { hsm_id: id, .. } if id != hsm_id => {
                        ReadCapturedResponse::NoHsm
                    }
                    x => x,
                })
        }
    }
}

impl Actor for Agent {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        let hsm = self.hsm.clone();
        let store = self.store.clone();
        let address = ctx.address();
        ctx.spawn(
            async move {
                let hsm_id = match hsm.send(hsm_types::StatusRequest {}).await {
                    Err(_) => todo!(),
                    Ok(hsm_types::StatusResponse { id, .. }) => id,
                };

                match store
                    .send(SetAddressRequest {
                        hsm: hsm_id,
                        address,
                    })
                    .await
                {
                    Err(_) => todo!(),
                    Ok(SetAddressResponse::Ok) => {}
                }
            }
            .into_actor(self),
        );
    }
}

impl Handler<StatusRequest> for Agent {
    type Result = ResponseFuture<StatusResponse>;

    fn handle(&mut self, request: StatusRequest, _ctx: &mut Context<Self>) -> Self::Result {
        let name = self.name.clone();
        trace!(agent = name, ?request);
        let hsm = self.hsm.clone();
        Box::pin(async move {
            let hsm_status = hsm.send(hsm_types::StatusRequest {}).await;
            let response = StatusResponse {
                hsm: hsm_status.ok(),
            };
            trace!(agent = name, ?response);
            response
        })
    }
}

impl Handler<NewRealmRequest> for Agent {
    type Result = ResponseActFuture<Self, NewRealmResponse>;

    fn handle(&mut self, request: NewRealmRequest, _ctx: &mut Context<Self>) -> Self::Result {
        type Response = NewRealmResponse;
        let name = self.name.clone();
        trace!(agent = name, ?request);
        let hsm = self.hsm.clone();
        let store = self.store.clone();

        Box::pin(
            async move {
                let new_realm_response = match hsm
                    .send(hsm_types::NewRealmRequest {
                        configuration: request.configuration,
                    })
                    .await
                {
                    Err(_) => return Response::NoHsm,

                    Ok(hsm_types::NewRealmResponse::HaveRealm) => return Response::HaveRealm,

                    Ok(hsm_types::NewRealmResponse::InvalidConfiguration) => {
                        return Response::InvalidConfiguration
                    }

                    Ok(hsm_types::NewRealmResponse::Ok(response)) => response,
                };

                info!(
                    agent = name,
                    realm = ?new_realm_response.realm,
                    group = ?new_realm_response.group,
                    "appending log entry for new realm"
                );
                assert_eq!(new_realm_response.entry.index, LogIndex(1));
                match store
                    .send(AppendRequest {
                        realm: new_realm_response.realm,
                        group: new_realm_response.group,
                        entry: new_realm_response.entry,
                        data: match new_realm_response.data {
                            None => DataChange::None,
                            Some(data) => DataChange::Set(data),
                        },
                        transferring_out: DataChange::None,
                    })
                    .await
                {
                    Ok(AppendResponse::Ok) => Response::Ok {
                        realm: new_realm_response.realm,
                        group: new_realm_response.group,
                        statement: new_realm_response.statement,
                    },
                    Ok(AppendResponse::PreconditionFailed) => Response::StorePreconditionFailed,
                    Err(_) => Response::NoStore,
                }
            }
            .into_actor(self)
            .map(move |response, agent, ctx| {
                if let Response::Ok { realm, group, .. } = response {
                    finish_new_group(agent, realm, group, ctx);
                }
                trace!(agent = agent.name, ?response);
                response
            }),
        )
    }
}

fn finish_new_group(agent: &mut Agent, realm: RealmId, group: GroupId, ctx: &mut Context<Agent>) {
    let index = LogIndex(1);
    agent.start_watching(realm, group, index, ctx);
    let existing = agent.leader.insert(
        (realm, group),
        LeaderState {
            append_queue: HashMap::new(),
            appending: NotAppending { next: index.next() },
            response_channels: HashMap::new(),
        },
    );
    assert!(existing.is_none());
    agent.collect_captures(realm, group, ctx);
}

impl Handler<JoinRealmRequest> for Agent {
    type Result = ResponseFuture<JoinRealmResponse>;

    fn handle(&mut self, request: JoinRealmRequest, _ctx: &mut Context<Self>) -> Self::Result {
        type Response = JoinRealmResponse;
        type HsmResponse = hsm_types::JoinRealmResponse;
        let name = self.name.clone();
        trace!(agent = name, ?request);
        let hsm = self.hsm.clone();

        Box::pin(async move {
            let response = match hsm
                .send(hsm_types::JoinRealmRequest {
                    realm: request.realm,
                })
                .await
            {
                Err(_) => Response::NoHsm,
                Ok(HsmResponse::HaveOtherRealm) => Response::HaveOtherRealm,
                Ok(HsmResponse::Ok { hsm }) => Response::Ok { hsm },
            };
            trace!(agent = name, ?response);
            response
        })
    }
}

impl Handler<NewGroupRequest> for Agent {
    type Result = ResponseActFuture<Self, NewGroupResponse>;

    fn handle(&mut self, request: NewGroupRequest, _ctx: &mut Context<Self>) -> Self::Result {
        type Response = NewGroupResponse;
        let name = self.name.clone();
        trace!(agent = name, ?request);
        let hsm = self.hsm.clone();
        let store = self.store.clone();
        let realm = request.realm;

        Box::pin(
            async move {
                let new_group_response = match hsm
                    .send(hsm_types::NewGroupRequest {
                        realm,
                        configuration: request.configuration,
                    })
                    .await
                {
                    Err(_) => return Response::NoHsm,

                    Ok(hsm_types::NewGroupResponse::InvalidRealm) => return Response::InvalidRealm,

                    Ok(hsm_types::NewGroupResponse::InvalidConfiguration) => {
                        return Response::InvalidConfiguration
                    }

                    Ok(hsm_types::NewGroupResponse::Ok(response)) => response,
                };

                info!(
                    agent = name,
                    ?realm,
                    group = ?new_group_response.group,
                    "appending log entry for new group"
                );
                assert_eq!(new_group_response.entry.index, LogIndex(1));
                match store
                    .send(AppendRequest {
                        realm,
                        group: new_group_response.group,
                        entry: new_group_response.entry,
                        data: match new_group_response.data {
                            None => DataChange::None,
                            Some(data) => DataChange::Set(data),
                        },
                        transferring_out: DataChange::None,
                    })
                    .await
                {
                    Ok(AppendResponse::Ok) => Response::Ok {
                        group: new_group_response.group,
                        statement: new_group_response.statement,
                    },
                    Ok(AppendResponse::PreconditionFailed) => Response::StorePreconditionFailed,
                    Err(_) => Response::NoStore,
                }
            }
            .into_actor(self)
            .map(move |response, agent, ctx| {
                if let Response::Ok { group, .. } = response {
                    finish_new_group(agent, realm, group, ctx);
                }
                trace!(agent = agent.name, ?response);
                response
            }),
        )
    }
}

impl Handler<JoinGroupRequest> for Agent {
    type Result = ResponseActFuture<Self, JoinGroupResponse>;

    fn handle(&mut self, request: JoinGroupRequest, _ctx: &mut Context<Self>) -> Self::Result {
        type Response = JoinGroupResponse;
        type HsmResponse = hsm_types::JoinGroupResponse;
        trace!(agent = self.name, ?request);
        let hsm = self.hsm.clone();

        Box::pin(
            async move {
                hsm.send(hsm_types::JoinGroupRequest {
                    realm: request.realm,
                    group: request.group,
                    configuration: request.configuration,
                    statement: request.statement,
                })
                .await
            }
            .into_actor(self)
            .map(move |result, agent, ctx| {
                let response = match result {
                    Err(_) => Response::NoHsm,
                    Ok(HsmResponse::InvalidRealm) => Response::InvalidRealm,
                    Ok(HsmResponse::InvalidConfiguration) => Response::InvalidConfiguration,
                    Ok(HsmResponse::InvalidStatement) => Response::InvalidStatement,
                    Ok(HsmResponse::Ok) => {
                        agent.start_watching(request.realm, request.group, LogIndex(1), ctx);
                        Response::Ok
                    }
                };
                trace!(agent = agent.name, ?response);
                response
            }),
        )
    }
}

impl Handler<BecomeLeaderRequest> for Agent {
    type Result = ResponseFuture<BecomeLeaderResponse>;

    fn handle(&mut self, request: BecomeLeaderRequest, _ctx: &mut Context<Self>) -> Self::Result {
        type Response = BecomeLeaderResponse;
        type HsmResponse = hsm_types::BecomeLeaderResponse;
        let name = self.name.clone();
        trace!(agent = name, ?request);
        let hsm = self.hsm.clone();
        let store = self.store.clone();

        Box::pin(async move {
            let last_entry = match store
                .send(ReadLatestRequest {
                    realm: request.realm,
                    group: request.group,
                })
                .await
            {
                Err(_) => return Response::NoStore,
                Ok(ReadLatestResponse::Ok { entry, .. }) => entry,
                Ok(ReadLatestResponse::None) => todo!(),
            };

            let response = match hsm
                .send(hsm_types::BecomeLeaderRequest {
                    realm: request.realm,
                    group: request.group,
                    last_entry,
                })
                .await
            {
                Err(_) => Response::NoHsm,
                Ok(HsmResponse::Ok) => Response::Ok,
                Ok(HsmResponse::InvalidRealm) => Response::InvalidRealm,
                Ok(HsmResponse::InvalidGroup) => Response::InvalidGroup,
                Ok(HsmResponse::InvalidHmac) => panic!(),
                Ok(HsmResponse::NotCaptured { have }) => Response::NotCaptured { have },
            };
            trace!(agent = name, ?response);
            response
        })
    }
}

impl Handler<ReadCapturedRequest> for Agent {
    type Result = ResponseFuture<ReadCapturedResponse>;

    fn handle(&mut self, request: ReadCapturedRequest, _ctx: &mut Context<Self>) -> Self::Result {
        type Response = ReadCapturedResponse;
        type HsmResponse = hsm_types::ReadCapturedResponse;
        let name = self.name.clone();
        trace!(agent = name, ?request);
        let hsm = self.hsm.clone();

        Box::pin(async move {
            let response = match hsm
                .send(hsm_types::ReadCapturedRequest {
                    realm: request.realm,
                    group: request.group,
                })
                .await
            {
                Err(_) => Response::NoHsm,
                Ok(HsmResponse::Ok {
                    hsm_id,
                    index,
                    entry_hmac,
                    statement,
                }) => Response::Ok {
                    hsm_id,
                    index,
                    entry_hmac,
                    statement,
                },
                Ok(HsmResponse::InvalidRealm) => Response::InvalidRealm,
                Ok(HsmResponse::InvalidGroup) => Response::InvalidGroup,
                Ok(HsmResponse::None) => Response::None,
            };
            trace!(agent = name, ?response);
            response
        })
    }
}

impl Handler<TransferOutRequest> for Agent {
    type Result = ResponseActFuture<Self, TransferOutResponse>;

    fn handle(&mut self, request: TransferOutRequest, _ctx: &mut Context<Self>) -> Self::Result {
        type Response = TransferOutResponse;
        type HsmResponse = hsm_types::TransferOutResponse;
        let name = self.name.clone();
        trace!(agent = name, ?request);
        let realm = request.realm;
        let source = request.source;
        let hsm = self.hsm.clone();
        let store = self.store.clone();
        let store2 = self.store.clone();

        Box::pin(
            async move {
                let (entry, data) = match store
                    .send(ReadLatestRequest {
                        realm: request.realm,
                        group: request.source,
                    })
                    .await
                {
                    Err(_) => return Err(Response::NoStore),
                    Ok(ReadLatestResponse::Ok { entry, data, .. }) => (entry, data),
                    Ok(ReadLatestResponse::None) => todo!(),
                };

                match hsm
                    .send(hsm_types::TransferOutRequest {
                        realm: request.realm,
                        source: request.source,
                        destination: request.destination,
                        prefix: request.prefix,
                        index: entry.index,
                        data,
                    })
                    .await
                {
                    Err(_) => Err(Response::NoHsm),
                    Ok(HsmResponse::InvalidRealm) => Err(Response::InvalidRealm),
                    Ok(HsmResponse::InvalidGroup) => Err(Response::InvalidGroup),
                    Ok(HsmResponse::NotLeader) => Err(Response::NotLeader),
                    Ok(HsmResponse::NotOwner) => Err(Response::NotOwner),
                    Ok(HsmResponse::StaleIndex) => todo!(),
                    Ok(HsmResponse::InvalidData) => panic!(),
                    Ok(HsmResponse::Ok {
                        entry,
                        keeping,
                        transferring,
                    }) => Ok((entry, keeping, transferring)),
                }
            }
            .into_actor(self)
            .map(move |result, agent, ctx| match result {
                Err(response) => response,
                Ok((entry, keeping, transferring)) => {
                    let partition = entry.transferring_out.as_ref().unwrap().partition.clone();
                    append(
                        ctx,
                        store2,
                        agent,
                        AppendRequest {
                            realm,
                            group: source,
                            entry,
                            data: match keeping {
                                None => DataChange::None,
                                Some(d) => DataChange::Set(d),
                            },
                            transferring_out: DataChange::Set(transferring),
                        },
                    );
                    Response::Ok { partition }
                }
            })
            .map(|response, agent, _ctx| {
                trace!(agent = agent.name, ?response);
                response
            }),
        )
    }
}

impl Handler<TransferNonceRequest> for Agent {
    type Result = ResponseFuture<TransferNonceResponse>;

    fn handle(&mut self, request: TransferNonceRequest, _ctx: &mut Context<Self>) -> Self::Result {
        type Response = TransferNonceResponse;
        type HsmResponse = hsm_types::TransferNonceResponse;
        let name = self.name.clone();
        trace!(agent = name, ?request);
        let hsm = self.hsm.clone();

        Box::pin(async move {
            let response = match hsm
                .send(hsm_types::TransferNonceRequest {
                    realm: request.realm,
                    destination: request.destination,
                })
                .await
            {
                Err(_) => Response::NoHsm,
                Ok(HsmResponse::Ok(nonce)) => Response::Ok(nonce),
                Ok(HsmResponse::InvalidRealm) => Response::InvalidRealm,
                Ok(HsmResponse::InvalidGroup) => Response::InvalidGroup,
                Ok(HsmResponse::NotLeader) => Response::NotLeader,
            };
            trace!(agent = name, ?response);
            response
        })
    }
}

impl Handler<TransferStatementRequest> for Agent {
    type Result = ResponseFuture<TransferStatementResponse>;

    fn handle(
        &mut self,
        request: TransferStatementRequest,
        _ctx: &mut Context<Self>,
    ) -> Self::Result {
        type Response = TransferStatementResponse;
        type HsmResponse = hsm_types::TransferStatementResponse;
        let name = self.name.clone();
        trace!(agent = name, ?request);
        let hsm = self.hsm.clone();

        Box::pin(async move {
            let response = loop {
                break match hsm
                    .send(hsm_types::TransferStatementRequest {
                        realm: request.realm,
                        source: request.source,
                        destination: request.destination,
                        nonce: request.nonce,
                    })
                    .await
                {
                    Err(_) => Response::NoHsm,
                    Ok(HsmResponse::Ok(statement)) => Response::Ok(statement),
                    Ok(HsmResponse::InvalidRealm) => Response::InvalidRealm,
                    Ok(HsmResponse::InvalidGroup) => Response::InvalidGroup,
                    Ok(HsmResponse::NotLeader) => Response::NotLeader,
                    Ok(HsmResponse::NotTransferring) => Response::NotTransferring,
                    Ok(HsmResponse::Busy) => {
                        sleep(Duration::from_millis(1)).await;
                        continue;
                    }
                };
            };
            trace!(agent = name, ?response);
            response
        })
    }
}

impl Handler<TransferInRequest> for Agent {
    type Result = ResponseActFuture<Self, TransferInResponse>;

    fn handle(&mut self, request: TransferInRequest, _ctx: &mut Context<Self>) -> Self::Result {
        type Response = TransferInResponse;
        type HsmResponse = hsm_types::TransferInResponse;
        let name = self.name.clone();
        trace!(agent = name, ?request);
        let hsm = self.hsm.clone();
        let store = self.store.clone();
        let store2 = self.store.clone();

        Box::pin(
            async move {
                let data = match store
                    .send(ReadLatestRequest {
                        realm: request.realm,
                        group: request.source,
                    })
                    .await
                {
                    Err(_) => todo!(),
                    Ok(ReadLatestResponse::Ok {
                        entry,
                        transferring_out,
                        ..
                    }) => {
                        // we if don't have an existing partition, then that's fine
                        if let Some(p) = entry.partition {
                            if p.hash != request.partition.hash {
                                todo!("{:?}, {:?}", p, request.partition);
                            }
                        }
                        transferring_out.expect("TODO")
                    }
                    Ok(ReadLatestResponse::None) => todo!(),
                };

                match hsm
                    .send(hsm_types::TransferInRequest {
                        realm: request.realm,
                        destination: request.destination,
                        data,
                        partition: request.partition.clone(),
                        nonce: request.nonce,
                        statement: request.statement,
                    })
                    .await
                {
                    Err(_) => Err(Response::NoHsm),
                    Ok(HsmResponse::InvalidRealm) => Err(Response::InvalidRealm),
                    Ok(HsmResponse::InvalidGroup) => Err(Response::InvalidGroup),
                    Ok(HsmResponse::NotLeader) => Err(Response::NotLeader),
                    Ok(HsmResponse::UnacceptablePrefix) => Err(Response::UnacceptablePrefix),
                    Ok(HsmResponse::InvalidNonce) => Err(Response::InvalidNonce),
                    Ok(HsmResponse::InvalidStatement) => Err(Response::InvalidStatement),
                    Ok(HsmResponse::InvalidData) => panic!(),
                    Ok(HsmResponse::Ok { entry, data }) => Ok((entry, data)),
                }
            }
            .into_actor(self)
            .map(move |result, agent, ctx| match result {
                Err(response) => response,
                Ok((entry, data)) => {
                    append(
                        ctx,
                        store2,
                        agent,
                        AppendRequest {
                            realm: request.realm,
                            group: request.destination,
                            entry,
                            data: DataChange::Set(data),
                            transferring_out: DataChange::None,
                        },
                    );
                    Response::Ok
                }
            })
            .map(|response, agent, _ctx| {
                trace!(agent = agent.name, ?response);
                response
            }),
        )
    }
}

impl Handler<CompleteTransferRequest> for Agent {
    type Result = ResponseActFuture<Self, CompleteTransferResponse>;

    fn handle(
        &mut self,
        request: CompleteTransferRequest,
        _ctx: &mut Context<Self>,
    ) -> Self::Result {
        type Response = CompleteTransferResponse;
        type HsmResponse = hsm_types::CompleteTransferResponse;
        let name = self.name.clone();
        trace!(agent = name, ?request);
        let hsm = self.hsm.clone();
        let store = self.store.clone();

        Box::pin(
            hsm.send(hsm_types::CompleteTransferRequest {
                realm: request.realm,
                source: request.source,
                destination: request.destination,
                prefix: request.prefix,
            })
            .into_actor(self)
            .map(move |result, agent, ctx| match result {
                Err(_) => Response::NoHsm,
                Ok(HsmResponse::InvalidRealm) => Response::InvalidRealm,
                Ok(HsmResponse::InvalidGroup) => Response::InvalidGroup,
                Ok(HsmResponse::NotLeader) => Response::NotLeader,
                Ok(HsmResponse::NotTransferring) => Response::Ok,
                Ok(HsmResponse::Ok(entry)) => {
                    append(
                        ctx,
                        store,
                        agent,
                        AppendRequest {
                            realm: request.realm,
                            group: request.source,
                            entry,
                            data: DataChange::None,
                            transferring_out: DataChange::Delete,
                        },
                    );
                    Response::Ok
                }
            })
            .map(|response, agent, _ctx| {
                trace!(agent = agent.name, ?response);
                response
            }),
        )
    }
}

impl Handler<AppRequest> for Agent {
    type Result = ResponseActFuture<Self, AppResponse>;

    fn handle(&mut self, request: AppRequest, _ctx: &mut Context<Self>) -> Self::Result {
        type Response = AppResponse;
        let name = self.name.clone();
        trace!(agent = name, ?request);
        let realm = request.realm;
        let group = request.group;
        let hsm = self.hsm.clone();
        let store = self.store.clone();

        Box::pin(
            start_app_request(request, name, hsm, store.clone())
                .into_actor(self)
                .then(
                    move |result, agent, ctx| -> LocalBoxActorFuture<Self, AppResponse> {
                        match result {
                            Err(response) => Box::pin(future::ready(response)),
                            Ok(append_request) => {
                                let (sender, receiver) = oneshot::channel::<SecretsResponse>();
                                let Some(leader) = agent.leader.get_mut(&(realm, group)) else {
                                    todo!();
                                };
                                leader
                                    .response_channels
                                    .insert(append_request.entry.entry_hmac.clone(), sender);
                                append(ctx, store, agent, append_request);
                                Box::pin(
                                    async move {
                                        match receiver.await {
                                            Ok(response) => Response::Ok(response),
                                            Err(oneshot::Canceled) => Response::NotLeader,
                                        }
                                    }
                                    .into_actor(agent),
                                )
                            }
                        }
                    },
                )
                .map(|response, agent, _ctx| {
                    trace!(agent = agent.name, ?response);
                    response
                }),
        )
    }
}

async fn start_app_request(
    request: AppRequest,
    name: String,
    hsm: Addr<Hsm>,
    store: Addr<Store>,
) -> Result<AppendRequest, AppResponse> {
    type HsmResponse = hsm_types::AppResponse;
    type Response = AppResponse;

    loop {
        let (entry, data) = match store
            .send(ReadLatestRequest {
                realm: request.realm,
                group: request.group,
            })
            .await
        {
            Err(_) => return Err(Response::NoStore),
            Ok(ReadLatestResponse::Ok { entry, data, .. }) => (entry, data),
            Ok(ReadLatestResponse::None) => todo!(),
        };

        match hsm
            .send(hsm_types::AppRequest {
                realm: request.realm,
                group: request.group,
                rid: request.rid.clone(),
                request: request.request.clone(),
                index: entry.index,
                data,
            })
            .await
        {
            Err(_) => return Err(Response::NoHsm),
            Ok(HsmResponse::InvalidRealm) => return Err(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => return Err(Response::InvalidGroup),
            Ok(HsmResponse::StaleIndex) => continue,
            Ok(HsmResponse::Busy) => {
                sleep(Duration::from_millis(1)).await;
                continue;
            }
            Ok(HsmResponse::NotLeader | HsmResponse::NotOwner) => return Err(Response::NotLeader),
            Ok(HsmResponse::InvalidData) => panic!(),

            Ok(HsmResponse::Ok { entry, data }) => {
                trace!(
                    agent = name,
                    ?entry,
                    ?data,
                    "got new log entry and data updates from HSM"
                );
                return Ok(AppendRequest {
                    realm: request.realm,
                    group: request.group,
                    entry,
                    data: DataChange::Set(data),
                    transferring_out: DataChange::None,
                });
            }
        };
    }
}

/// Precondition: agent is leader.
fn append(
    ctx: &mut actix::Context<Agent>,
    store: Addr<Store>,
    agent: &mut Agent,
    append_request: AppendRequest,
) {
    let realm = append_request.realm;
    let group = append_request.group;

    let leader = agent.leader.get_mut(&(realm, group)).unwrap();
    let existing = leader
        .append_queue
        .insert(append_request.entry.index, append_request);
    assert!(existing.is_none());

    match leader.appending {
        NotAppending { next } => {
            leader.appending = Appending;
            keep_appending(ctx, store, agent, realm, group, next);
        }
        Appending => { /* do nothing */ }
    }
}

/// Precondition: `leader.appending` is Appending because this task is the one
/// doing the appending.
fn keep_appending(
    ctx: &mut actix::Context<Agent>,
    store: Addr<Store>,
    agent: &mut Agent,
    realm: RealmId,
    group: GroupId,
    next: LogIndex,
) {
    let Some(leader) = agent.leader.get_mut(&(realm, group)) else {
        return;
    };
    assert!(matches!(leader.appending, Appending));
    let Some(request) = leader.append_queue.remove(&next) else {
        leader.appending = NotAppending { next };
        return;
    };
    let store2 = store.clone();

    ctx.spawn(Box::pin(
        async move {
            match store2.send(request).await {
                Err(_) => todo!(),
                Ok(AppendResponse::PreconditionFailed) => {
                    todo!("stop leading")
                }
                Ok(AppendResponse::Ok) => {}
            }
        }
        .into_actor(agent)
        .map(move |_, agent, ctx| {
            keep_appending(ctx, store, agent, realm, group, next.next());
        }),
    ));
}
