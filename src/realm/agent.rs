use actix::prelude::*;
use bytes::Bytes;
use future::join_all;
use futures::channel::oneshot;
use futures::{future, Future};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use reqwest::Url;
use std::collections::btree_map::Entry::{Occupied, Vacant};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{info, trace, warn};

pub mod client;
pub mod types;

use super::hsm::types as hsm_types;
use super::hsm::Hsm;
use super::merkle::KeySlice;
use super::store::types::{
    AddressEntry, AppendRequest, AppendResponse, GetAddressesRequest, GetAddressesResponse,
    GetRecordProofRequest, GetRecordProofResponse, ReadEntryRequest, ReadEntryResponse,
    ReadLatestRequest, ReadLatestResponse, SetAddressRequest, SetAddressResponse,
};
use super::store::Store;
use client::{AgentClient, AgentClientError};
use hsm_types::{
    CaptureNextRequest, CaptureNextResponse, CapturedStatement, CommitRequest, CommitResponse,
    EntryHmac, GroupId, HsmId, LogIndex, RealmId, RecordId, SecretsResponse,
};
use types::{
    AppRequest, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse, CompleteTransferRequest,
    CompleteTransferResponse, JoinGroupRequest, JoinGroupResponse, JoinRealmRequest,
    JoinRealmResponse, NewGroupRequest, NewGroupResponse, NewRealmRequest, NewRealmResponse,
    ReadCapturedRequest, ReadCapturedResponse, Rpc, StatusRequest, StatusResponse,
    TransferInRequest, TransferInResponse, TransferNonceRequest, TransferNonceResponse,
    TransferOutRequest, TransferOutResponse, TransferStatementRequest, TransferStatementResponse,
};

#[derive(Clone, Debug)]
pub struct Agent(Arc<AgentInner>);

#[derive(Debug)]
struct AgentInner {
    name: String,
    hsm: Addr<Hsm>,
    store: Addr<Store>,
    peer_client: AgentClient,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
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
        Self(Arc::new(AgentInner {
            name,
            hsm,
            store,
            peer_client: AgentClient::new(),
            state: Mutex::new(State {
                leader: HashMap::new(),
            }),
        }))
    }

    fn start_watching(&self, realm: RealmId, group: GroupId, next_index: LogIndex) {
        let name = self.0.name.clone();
        let hsm = self.0.hsm.clone();
        let store = self.0.store.clone();
        trace!(agent = name, realm = ?realm, group = ?group, ?next_index, "start watching log");

        tokio::spawn(async move {
            let mut next_index = next_index;
            loop {
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
                                next_index = next_index.next();
                            }
                            Ok(r) => todo!("{r:#?}"),
                        }
                    }
                }
            }
        });
    }

    fn collect_captures(&self, realm_id: RealmId, group_id: GroupId) {
        let name = self.0.name.clone();
        let hsm = self.0.hsm.clone();
        let agent = self.clone();
        trace!(agent = name, realm = ?realm_id, group = ?group_id, "start collecting captures");

        tokio::spawn(Box::pin(async move {
            loop {
                let peers = agent.find_peers(realm_id, group_id).await.expect("todo");
                let futures = peers.iter().filter_map(|(hsm_id, address)| {
                    address
                        .as_ref()
                        .map(|address| agent.read_captured(realm_id, group_id, *hsm_id, address))
                });
                let captures = join_all(futures).await;
                let mut map: BTreeMap<LogIndex, (EntryHmac, Vec<(HsmId, CapturedStatement)>)> =
                    BTreeMap::new();
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
                                entry.insert((entry_hmac, Vec::from([(hsm_id, statement)])));
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

                let responses = if let Some(commit_request) = commit_request {
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
                            trace!(agent = name, ?committed, ?responses, "HSM committed entry");
                            responses
                        }
                        Ok(CommitResponse::AlreadyCommitted { .. }) => {
                            // TODO: this happens a lot now
                            // because this doesn't remember
                            // what it's already asked the HSM
                            // to commit.
                            trace!(agent = name, ?response, "commit response not ok");
                            Vec::new()
                        }
                        _ => {
                            warn!(agent = name, ?response, "commit response not ok");
                            Vec::new()
                        }
                    }
                } else {
                    Vec::new()
                };

                {
                    let mut locked = agent.0.state.lock().unwrap();
                    if let Some(leader) = locked.leader.get_mut(&(realm_id, group_id)) {
                        for (hmac, client_response) in responses {
                            if let Some(sender) = leader.response_channels.remove(&hmac) {
                                if sender.send(client_response).is_err() {
                                    warn!(
                                        "dropping response on the floor: client no longer waiting"
                                    );
                                }
                            } else {
                                warn!("dropping response on the floor: client never waiting");
                            }
                        }
                    } else if !responses.is_empty() {
                        warn!("dropping responses on the floor: no leader state");
                    }
                }
                sleep(Duration::from_millis(10)).await;
            }
        }));
    }

    async fn find_peers(
        &self,
        realm_id: RealmId,
        group_id: GroupId,
    ) -> Result<HashMap<HsmId, Option<Url>>, ()> {
        let name = &self.0.name;
        let hsm = &self.0.hsm;
        let store = &self.0.store;

        let mut peers: HashMap<HsmId, Option<Url>> =
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

    async fn read_captured(
        &self,
        realm_id: RealmId,
        group_id: GroupId,
        hsm_id: HsmId,
        address: &Url,
    ) -> Result<ReadCapturedResponse, AgentClientError> {
        self.0
            .peer_client
            .send(
                address,
                ReadCapturedRequest {
                    realm: realm_id,
                    group: group_id,
                },
            )
            .await
            .map(|result| match result {
                ReadCapturedResponse::Ok { hsm_id: id, .. } if id != hsm_id => {
                    ReadCapturedResponse::NoHsm
                }
                x => x,
            })
    }

    pub async fn listen(
        self,
        address: SocketAddr,
    ) -> Result<(Url, JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(address).await?;
        let url = Url::parse(&format!("http://{address}")).unwrap();

        let hsm = &self.0.hsm;
        let store = &self.0.store;

        let hsm_id = match hsm.send(hsm_types::StatusRequest {}).await {
            Err(_) => todo!(),
            Ok(hsm_types::StatusResponse { id, .. }) => id,
        };
        match store
            .send(SetAddressRequest {
                hsm: hsm_id,
                address: url.clone(),
            })
            .await
        {
            Err(_) => todo!(),
            Ok(SetAddressResponse::Ok) => {}
        }

        Ok((
            url,
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Err(e) => warn!("error accepting connection: {e:?}"),
                        Ok((stream, _)) => {
                            let agent = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(stream, agent.clone())
                                    .await
                                {
                                    warn!("error serving connection: {e:?}");
                                }
                            });
                        }
                    }
                }
            }),
        ))
    }
}

impl Service<Request<IncomingBody>> for Agent {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&mut self, request: Request<IncomingBody>) -> Self::Future {
        let agent = self.clone();
        Box::pin(async move {
            let Some(path) = request.uri().path().strip_prefix('/') else {
                return Ok(Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(Full::from(Bytes::new()))
                    .unwrap());
            };
            match path {
                AppRequest::PATH => agent.handle_rpc(request, Self::handle_app).await,
                BecomeLeaderRequest::PATH => {
                    agent.handle_rpc(request, Self::handle_become_leader).await
                }
                CompleteTransferRequest::PATH => {
                    agent
                        .handle_rpc(request, Self::handle_complete_transfer)
                        .await
                }
                JoinGroupRequest::PATH => agent.handle_rpc(request, Self::handle_join_group).await,
                JoinRealmRequest::PATH => agent.handle_rpc(request, Self::handle_join_realm).await,
                NewGroupRequest::PATH => agent.handle_rpc(request, Self::handle_new_group).await,
                NewRealmRequest::PATH => agent.handle_rpc(request, Self::handle_new_realm).await,
                ReadCapturedRequest::PATH => {
                    agent.handle_rpc(request, Self::handle_read_captured).await
                }
                StatusRequest::PATH => agent.handle_rpc(request, Self::handle_status).await,
                TransferInRequest::PATH => {
                    agent.handle_rpc(request, Self::handle_transfer_in).await
                }
                TransferNonceRequest::PATH => {
                    agent.handle_rpc(request, Self::handle_transfer_nonce).await
                }
                TransferOutRequest::PATH => {
                    agent.handle_rpc(request, Self::handle_transfer_out).await
                }
                TransferStatementRequest::PATH => {
                    agent
                        .handle_rpc(request, Self::handle_transfer_statement)
                        .await
                }
                _ => Ok(Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(Full::from(Bytes::new()))
                    .unwrap()),
            }
        })
    }
}

#[derive(Debug)]
enum HandlerError {
    // We'd use this if we wanted to return non-200 HTTP statuses or drop the
    // connection. For now, there's nothing here.
}

impl Agent {
    async fn handle_rpc<'a, H, R: Rpc, O>(
        &'a self,
        incoming_request: Request<IncomingBody>,
        handler: H,
    ) -> Result<Response<Full<Bytes>>, hyper::Error>
    where
        H: Fn(&'a Self, R) -> O,
        O: Future<Output = Result<R::Response, HandlerError>>,
    {
        let request_bytes = incoming_request.collect().await?.to_bytes();
        let request: R = match rmp_serde::from_slice(request_bytes.as_ref()) {
            Ok(request) => request,
            Err(e) => {
                warn!(error = ?e, "agent deserialization error");
                return Ok(Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .body(Full::from(Bytes::new()))
                    .unwrap());
            }
        };

        trace!(agent = self.0.name, ?request);
        let response = handler(self, request).await;
        trace!(agent = self.0.name, ?response);

        match response {
            Err(e) => match e { /* no possible errors */ },
            Ok(response) => {
                let response_bytes = match rmp_serde::to_vec(&response) {
                    Ok(response_bytes) => response_bytes,
                    Err(e) => {
                        warn!(error = ?e, ?response, "agent serialization error");
                        return Ok(Response::builder()
                            .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Full::from(Bytes::new()))
                            .unwrap());
                    }
                };
                Ok(Response::builder()
                    .body(Full::new(Bytes::from(response_bytes)))
                    .unwrap())
            }
        }
    }

    async fn handle_status(&self, _request: StatusRequest) -> Result<StatusResponse, HandlerError> {
        let hsm_status = self.0.hsm.send(hsm_types::StatusRequest {}).await;
        Ok(StatusResponse {
            hsm: hsm_status.ok(),
        })
    }

    async fn handle_new_realm(
        &self,
        request: NewRealmRequest,
    ) -> Result<NewRealmResponse, HandlerError> {
        type Response = NewRealmResponse;

        let hsm = &self.0.hsm;
        let store = &self.0.store;
        let name = &self.0.name;

        let new_realm_response = match hsm
            .send(hsm_types::NewRealmRequest {
                configuration: request.configuration,
            })
            .await
        {
            Err(_) => return Ok(Response::NoHsm),

            Ok(hsm_types::NewRealmResponse::HaveRealm) => return Ok(Response::HaveRealm),

            Ok(hsm_types::NewRealmResponse::InvalidConfiguration) => {
                return Ok(Response::InvalidConfiguration)
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
        let response = match store
            .send(AppendRequest {
                realm: new_realm_response.realm,
                group: new_realm_response.group,
                entry: new_realm_response.entry,
                delta: new_realm_response.delta,
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
        };

        if let Response::Ok { realm, group, .. } = response {
            self.finish_new_group(realm, group);
        }
        Ok(response)
    }

    fn finish_new_group(&self, realm: RealmId, group: GroupId) {
        let index = LogIndex(1);
        self.start_watching(realm, group, index);
        let existing = self.0.state.lock().unwrap().leader.insert(
            (realm, group),
            LeaderState {
                append_queue: HashMap::new(),
                appending: NotAppending { next: index.next() },
                response_channels: HashMap::new(),
            },
        );
        assert!(existing.is_none());
        self.collect_captures(realm, group);
    }

    async fn handle_join_realm(
        &self,
        request: JoinRealmRequest,
    ) -> Result<JoinRealmResponse, HandlerError> {
        type Response = JoinRealmResponse;
        type HsmResponse = hsm_types::JoinRealmResponse;

        match self
            .0
            .hsm
            .send(hsm_types::JoinRealmRequest {
                realm: request.realm,
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::HaveOtherRealm) => Ok(Response::HaveOtherRealm),
            Ok(HsmResponse::Ok { hsm }) => Ok(Response::Ok { hsm }),
        }
    }

    async fn handle_new_group(
        &self,
        request: NewGroupRequest,
    ) -> Result<NewGroupResponse, HandlerError> {
        type Response = NewGroupResponse;
        let name = &self.0.name;
        let hsm = &self.0.hsm;
        let store = &self.0.store;

        let realm = request.realm;

        let new_group_response = match hsm
            .send(hsm_types::NewGroupRequest {
                realm,
                configuration: request.configuration,
            })
            .await
        {
            Err(_) => return Ok(Response::NoHsm),

            Ok(hsm_types::NewGroupResponse::InvalidRealm) => return Ok(Response::InvalidRealm),

            Ok(hsm_types::NewGroupResponse::InvalidConfiguration) => {
                return Ok(Response::InvalidConfiguration)
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
                delta: new_group_response.delta,
            })
            .await
        {
            Ok(AppendResponse::Ok) => {
                self.finish_new_group(realm, new_group_response.group);
                Ok(Response::Ok {
                    group: new_group_response.group,
                    statement: new_group_response.statement,
                })
            }
            Ok(AppendResponse::PreconditionFailed) => Ok(Response::StorePreconditionFailed),
            Err(_) => Ok(Response::NoStore),
        }
    }

    async fn handle_join_group(
        &self,
        request: JoinGroupRequest,
    ) -> Result<JoinGroupResponse, HandlerError> {
        type Response = JoinGroupResponse;
        type HsmResponse = hsm_types::JoinGroupResponse;

        let result = self
            .0
            .hsm
            .send(hsm_types::JoinGroupRequest {
                realm: request.realm,
                group: request.group,
                configuration: request.configuration,
                statement: request.statement,
            })
            .await;

        match result {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidConfiguration) => Ok(Response::InvalidConfiguration),
            Ok(HsmResponse::InvalidStatement) => Ok(Response::InvalidStatement),
            Ok(HsmResponse::Ok) => {
                self.start_watching(request.realm, request.group, LogIndex(1));
                Ok(Response::Ok)
            }
        }
    }

    async fn handle_become_leader(
        &self,
        request: BecomeLeaderRequest,
    ) -> Result<BecomeLeaderResponse, HandlerError> {
        type Response = BecomeLeaderResponse;
        type HsmResponse = hsm_types::BecomeLeaderResponse;

        let hsm = &self.0.hsm;
        let store = &self.0.store;

        let last_entry = match store
            .send(ReadLatestRequest {
                realm: request.realm,
                group: request.group,
            })
            .await
        {
            Err(_) => return Ok(Response::NoStore),
            Ok(ReadLatestResponse::Ok { entry, .. }) => entry,
            Ok(ReadLatestResponse::None) => todo!(),
        };

        match hsm
            .send(hsm_types::BecomeLeaderRequest {
                realm: request.realm,
                group: request.group,
                last_entry,
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::Ok) => Ok(Response::Ok),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::InvalidHmac) => panic!(),
            Ok(HsmResponse::NotCaptured { have }) => Ok(Response::NotCaptured { have }),
        }
    }

    async fn handle_read_captured(
        &self,
        request: ReadCapturedRequest,
    ) -> Result<ReadCapturedResponse, HandlerError> {
        type Response = ReadCapturedResponse;
        type HsmResponse = hsm_types::ReadCapturedResponse;
        match self
            .0
            .hsm
            .send(hsm_types::ReadCapturedRequest {
                realm: request.realm,
                group: request.group,
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::Ok {
                hsm_id,
                index,
                entry_hmac,
                statement,
            }) => Ok(Response::Ok {
                hsm_id,
                index,
                entry_hmac,
                statement,
            }),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::None) => Ok(Response::None),
        }
    }

    async fn handle_transfer_out(
        &self,
        request: TransferOutRequest,
    ) -> Result<TransferOutResponse, HandlerError> {
        type Response = TransferOutResponse;
        type HsmResponse = hsm_types::TransferOutResponse;
        let realm = request.realm;
        let source = request.source;

        let hsm = &self.0.hsm;
        let store = &self.0.store;

        // This loop handles retries if the read from the store is stale. It's
        // expected to run just once.
        loop {
            let entry = match store
                .send(ReadLatestRequest {
                    realm: request.realm,
                    group: request.source,
                })
                .await
            {
                Err(_) => return Ok(Response::NoStore),
                Ok(ReadLatestResponse::Ok { entry, .. }) => entry,
                Ok(ReadLatestResponse::None) => todo!(),
            };
            let Some(partition) = entry.partition else {
                return Ok(Response::NotOwner);
            };

            // Make a recordId that is owned by the partition. We need a read proof
            // to split the merkle tree.
            let mut rec_id = RecordId([0u8; 32]);
            let bs = KeySlice::from_slice_mut(&mut rec_id.0);
            bs[..partition.prefix.0.len()].copy_from_bitslice(&partition.prefix.0);

            let proof = match store
                .send(GetRecordProofRequest {
                    realm: request.realm,
                    group: request.source,
                    record: rec_id,
                })
                .await
            {
                Err(_) => return Ok(Response::NoStore),
                Ok(GetRecordProofResponse::Ok { proof, .. }) => proof,
                Ok(GetRecordProofResponse::StoreMissingNode) => todo!(),
                Ok(GetRecordProofResponse::UnknownGroup) => todo!(),
                Ok(GetRecordProofResponse::NotOwner) => return Ok(Response::NotOwner),
            };

            return match hsm
                .send(hsm_types::TransferOutRequest {
                    realm: request.realm,
                    source: request.source,
                    destination: request.destination,
                    prefix: request.prefix.clone(),
                    index: entry.index,
                    proof,
                })
                .await
            {
                Err(_) => Ok(Response::NoHsm),
                Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
                Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
                Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
                Ok(HsmResponse::NotOwner) => Ok(Response::NotOwner),
                Ok(HsmResponse::StaleIndex) => todo!(),
                Ok(HsmResponse::InvalidProof) => Ok(Response::InvalidProof),
                Ok(HsmResponse::StaleProof) => {
                    trace!("hsm said stale proof, will retry");
                    sleep(Duration::from_millis(1)).await;
                    continue;
                }
                Ok(HsmResponse::Ok { entry, delta }) => {
                    let transferring_partition = match &entry.transferring_out {
                        Some(t) => t.partition.clone(),
                        None => panic!("Log entry missing TransferringOut section"),
                    };
                    self.append(
                        store.clone(),
                        AppendRequest {
                            realm,
                            group: source,
                            entry,
                            delta,
                        },
                    );
                    Ok(Response::Ok {
                        transferring: transferring_partition,
                    })
                }
            };
        }
    }

    async fn handle_transfer_nonce(
        &self,
        request: TransferNonceRequest,
    ) -> Result<TransferNonceResponse, HandlerError> {
        type Response = TransferNonceResponse;
        type HsmResponse = hsm_types::TransferNonceResponse;

        match self
            .0
            .hsm
            .send(hsm_types::TransferNonceRequest {
                realm: request.realm,
                destination: request.destination,
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::Ok(nonce)) => Ok(Response::Ok(nonce)),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
        }
    }

    async fn handle_transfer_statement(
        &self,
        request: TransferStatementRequest,
    ) -> Result<TransferStatementResponse, HandlerError> {
        type Response = TransferStatementResponse;
        type HsmResponse = hsm_types::TransferStatementResponse;
        loop {
            return match self
                .0
                .hsm
                .send(hsm_types::TransferStatementRequest {
                    realm: request.realm,
                    source: request.source,
                    destination: request.destination,
                    nonce: request.nonce,
                })
                .await
            {
                Err(_) => Ok(Response::NoHsm),
                Ok(HsmResponse::Ok(statement)) => Ok(Response::Ok(statement)),
                Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
                Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
                Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
                Ok(HsmResponse::NotTransferring) => Ok(Response::NotTransferring),
                Ok(HsmResponse::Busy) => {
                    sleep(Duration::from_millis(1)).await;
                    continue;
                }
            };
        }
    }

    async fn handle_transfer_in(
        &self,
        request: TransferInRequest,
    ) -> Result<TransferInResponse, HandlerError> {
        type Response = TransferInResponse;
        type HsmResponse = hsm_types::TransferInResponse;

        let hsm = &self.0.hsm;
        let store = &self.0.store;

        match hsm
            .send(hsm_types::TransferInRequest {
                realm: request.realm,
                destination: request.destination,
                transferring: request.transferring.clone(),
                nonce: request.nonce,
                statement: request.statement,
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
            Ok(HsmResponse::UnacceptablePrefix) => Ok(Response::UnacceptablePrefix),
            Ok(HsmResponse::InvalidNonce) => Ok(Response::InvalidNonce),
            Ok(HsmResponse::InvalidStatement) => Ok(Response::InvalidStatement),
            Ok(HsmResponse::Ok { entry }) => {
                self.append(
                    store.clone(),
                    AppendRequest {
                        realm: request.realm,
                        group: request.destination,
                        entry,
                        delta: None,
                    },
                );
                Ok(Response::Ok)
            }
        }
    }

    async fn handle_complete_transfer(
        &self,
        request: CompleteTransferRequest,
    ) -> Result<CompleteTransferResponse, HandlerError> {
        type Response = CompleteTransferResponse;
        type HsmResponse = hsm_types::CompleteTransferResponse;
        let hsm = &self.0.hsm;
        let store = &self.0.store;

        let result = hsm
            .send(hsm_types::CompleteTransferRequest {
                realm: request.realm,
                source: request.source,
                destination: request.destination,
                prefix: request.prefix,
            })
            .await;
        match result {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
            Ok(HsmResponse::NotTransferring) => Ok(Response::Ok),
            Ok(HsmResponse::Ok(entry)) => {
                self.append(
                    store.clone(),
                    AppendRequest {
                        realm: request.realm,
                        group: request.source,
                        entry,
                        delta: None,
                    },
                );
                Ok(Response::Ok)
            }
        }
    }

    async fn handle_app(&self, request: AppRequest) -> Result<AppResponse, HandlerError> {
        type Response = AppResponse;
        let realm = request.realm;
        let group = request.group;

        let name = &self.0.name;
        let hsm = &self.0.hsm;
        let store = &self.0.store;

        let result = start_app_request(request, name.clone(), hsm.clone(), store.clone()).await;
        match result {
            Err(response) => Ok(response),
            Ok(append_request) => {
                let (sender, receiver) = oneshot::channel::<SecretsResponse>();

                {
                    let mut locked = self.0.state.lock().unwrap();
                    let Some(leader) = locked.leader.get_mut(&(realm, group)) else {
                        todo!();
                    };
                    leader
                        .response_channels
                        .insert(append_request.entry.entry_hmac.clone(), sender);
                }

                self.append(store.clone(), append_request);
                match receiver.await {
                    Ok(response) => Ok(Response::Ok(response)),
                    Err(oneshot::Canceled) => Ok(Response::NotLeader),
                }
            }
        }
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
        let (proof, index) = match store
            .send(GetRecordProofRequest {
                realm: request.realm,
                group: request.group,
                record: request.rid.clone(),
            })
            .await
        {
            Ok(GetRecordProofResponse::Ok { proof, index }) => (proof, index),
            Ok(GetRecordProofResponse::StoreMissingNode) => todo!(),
            Ok(GetRecordProofResponse::UnknownGroup) => todo!(),
            Ok(GetRecordProofResponse::NotOwner) => todo!(),
            Err(_) => return Err(Response::NoStore),
        };

        match hsm
            .send(hsm_types::AppRequest {
                realm: request.realm,
                group: request.group,
                rid: request.rid.clone(),
                request: request.request.clone(),
                index,
                proof,
            })
            .await
        {
            Err(_) => return Err(Response::NoHsm),
            Ok(HsmResponse::InvalidRealm) => return Err(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => return Err(Response::InvalidGroup),
            Ok(HsmResponse::StaleProof) => continue,
            Ok(HsmResponse::NotLeader | HsmResponse::NotOwner) => return Err(Response::NotLeader),
            Ok(HsmResponse::InvalidData) => panic!(),

            Ok(HsmResponse::Ok { entry, delta }) => {
                trace!(
                    agent = name,
                    ?entry,
                    ?delta,
                    "got new log entry and data updates from HSM"
                );
                return Ok(AppendRequest {
                    realm: request.realm,
                    group: request.group,
                    entry,
                    delta,
                });
            }
        };
    }
}

impl Agent {
    /// Precondition: agent is leader.
    fn append(&self, store: Addr<Store>, append_request: AppendRequest) {
        let realm = append_request.realm;
        let group = append_request.group;

        let appending = {
            let mut locked = self.0.state.lock().unwrap();
            let leader = locked.leader.get_mut(&(realm, group)).unwrap();
            let existing = leader
                .append_queue
                .insert(append_request.entry.index, append_request);
            assert!(existing.is_none());
            std::mem::replace(&mut leader.appending, Appending)
        };

        if let NotAppending { next } = appending {
            let agent = self.clone();
            tokio::spawn(async move { agent.keep_appending(store, realm, group, next).await });
        }
    }

    /// Precondition: `leader.appending` is Appending because this task is the one
    /// doing the appending.
    async fn keep_appending(
        &self,
        store: Addr<Store>,
        realm: RealmId,
        group: GroupId,
        next: LogIndex,
    ) {
        let mut next = next;
        loop {
            let request = {
                let mut locked = self.0.state.lock().unwrap();
                let Some(leader) = locked.leader.get_mut(&(realm, group)) else {
                    return;
                };
                assert!(matches!(leader.appending, Appending));
                let Some(request) = leader.append_queue.remove(&next) else {
                    leader.appending = NotAppending { next };
                    return;
                };
                request
            };
            let store2 = store.clone();

            match store2.send(request).await {
                Err(_) => todo!(),
                Ok(AppendResponse::PreconditionFailed) => {
                    todo!("stop leading")
                }
                Ok(AppendResponse::Ok) => {
                    next = next.next();
                }
            }
        }
    }
}
