use bytes::Bytes;
use future::join_all;
use futures::channel::oneshot;
use futures::{future, Future};
use hsmcore::hsm::types::{DataHash, LogEntry, PersistStateRequest, PersistStateResponse};
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use opentelemetry_http::HeaderExtractor;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{info, instrument, trace, warn, Instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use url::Url;

pub mod types;

use super::super::http_client::{Client, ClientOptions};
use super::hsm::client::{HsmClient, Transport};
use super::merkle;
use super::rpc::{handle_rpc, HandlerError};
use super::store::bigtable::{self};
use hsm_types::{
    CaptureNextRequest, CaptureNextResponse, Captured, CommitRequest, CommitResponse,
    Configuration, EntryHmac, GroupId, HsmId, LogIndex, TransferInProofs,
};
use hsmcore::hsm::{types as hsm_types, HsmElection};
use hsmcore::merkle::agent::{StoreDelta, TreeStoreError};
use hsmcore::merkle::Dir;
use loam_sdk_core::requests::{ClientRequestKind, NoiseRequest, NoiseResponse};
use loam_sdk_core::types::RealmId;
use loam_sdk_networking::rpc::{self, Rpc};
use types::{
    AgentService, AppRequest, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse,
    CompleteTransferRequest, CompleteTransferResponse, JoinGroupRequest, JoinGroupResponse,
    JoinRealmRequest, JoinRealmResponse, NewGroupRequest, NewGroupResponse, NewRealmRequest,
    NewRealmResponse, ReadCapturedRequest, ReadCapturedResponse, StatusRequest, StatusResponse,
    TransferInRequest, TransferInResponse, TransferNonceRequest, TransferNonceResponse,
    TransferOutRequest, TransferOutResponse, TransferStatementRequest, TransferStatementResponse,
};

#[derive(Debug)]
pub struct Agent<T>(Arc<AgentInner<T>>);

#[derive(Debug)]
struct AgentInner<T> {
    name: String,
    hsm: HsmClient<T>,
    store: bigtable::StoreClient,
    store_admin: bigtable::StoreAdminClient,
    peer_client: Client<AgentService>,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    leader: HashMap<(RealmId, GroupId), LeaderState>,
    // Captures that have been persisted to NVRAM in the HSM.
    captures: Vec<Captured>,
}

#[derive(Debug)]
struct LeaderState {
    /// Log entries may be received out of order from the HSM. They are buffered
    /// here until they can be appended to the log in order.
    append_queue: HashMap<LogIndex, Append>,
    /// This serves as a mutex to prevent multiple concurrent appends to the
    /// store.
    appending: AppendingState,
    response_channels: HashMap<EntryHmac, oneshot::Sender<NoiseResponse>>,
}

#[derive(Debug)]
pub struct Append {
    pub entry: LogEntry,
    pub delta: StoreDelta<DataHash>,
}

#[derive(Debug)]
enum AppendingState {
    NotAppending { next: LogIndex },
    Appending,
}
use AppendingState::{Appending, NotAppending};

impl<T> Clone for Agent<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[derive(Debug, Eq, PartialEq)]
enum CommitterStatus {
    Committing { committed: Option<LogIndex> },
    NoLongerLeader,
}

impl<T: Transport + 'static> Agent<T> {
    pub fn new(
        name: String,
        hsm: HsmClient<T>,
        store: bigtable::StoreClient,
        store_admin: bigtable::StoreAdminClient,
    ) -> Self {
        Self(Arc::new(AgentInner {
            name,
            hsm,
            store,
            store_admin,
            peer_client: Client::new(ClientOptions::default()),
            state: Mutex::new(State {
                leader: HashMap::new(),
                captures: Vec::new(),
            }),
        }))
    }

    /// Called at service startup, start watching for any groups that the HSM is already a member of.
    async fn restart_watching(&self) {
        let status = self.0.hsm.send(hsm_types::StatusRequest {}).await;
        if let Ok(sr) = status {
            if let Some(realm) = sr.realm {
                for g in &realm.groups {
                    let idx = match g.captured {
                        Some((index, _)) => index.next(),
                        None => LogIndex::FIRST,
                    };
                    info!(agent=?self.0.name, realm=?realm.id, group=?g.id, index=?idx, "restarted watching log");
                    self.start_watching(realm.id, g.id, idx);
                }
            }
        }
    }

    fn start_watching(&self, realm: RealmId, group: GroupId, next_index: LogIndex) {
        let state = self.0.clone();

        trace!(agent = state.name, realm = ?realm, group = ?group, ?next_index, "start watching log");

        tokio::spawn(async move {
            let mut it = state.store.read_log_entries_iter(
                realm,
                group,
                next_index,
                (Self::MAX_APPEND_BATCH_SIZE * 2).try_into().unwrap(),
            );
            loop {
                match it.next().await {
                    Err(e) => {
                        warn!(err=?e, "error reading log");
                        sleep(Duration::from_millis(25)).await;
                    }
                    Ok(entries) if entries.is_empty() => {
                        // TODO: how would we tell if the log was truncated?
                        sleep(Duration::from_millis(1)).await;
                    }
                    Ok(entries) => {
                        let index = entries[0].index;
                        trace!(
                            agent = state.name,
                            ?realm,
                            ?group,
                            first_index=?index,
                            num=?entries.len(),
                            "found log entries"
                        );
                        match state
                            .hsm
                            .send(CaptureNextRequest {
                                realm,
                                group,
                                entries,
                            })
                            .await
                        {
                            Err(_) => todo!(),
                            Ok(CaptureNextResponse::Ok { hsm_id, .. }) => {
                                trace!(agent = state.name, ?realm, ?group, hsm=?hsm_id, ?index,
                                    "HSM captured entries");
                            }
                            Ok(r) => todo!("{r:#?}"),
                        }
                    }
                }
            }
        });
    }

    fn start_nvram_writer(&self) {
        trace!(agent = self.0.name, "starting nvram writer task");
        let agent = self.clone();

        tokio::spawn(async move {
            const WRITE_INTERVAL_MILLIS: u32 = 100;
            loop {
                // We want to do the write/commit at the same time on each
                // agent/hsm in the cluster so that we can commit as many log
                // entries as possible.
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap();
                let wait = Duration::from_millis(u64::from(
                    WRITE_INTERVAL_MILLIS - (now.subsec_millis() % WRITE_INTERVAL_MILLIS),
                ));
                sleep(wait).await;
                match agent.0.hsm.send(PersistStateRequest {}).await {
                    Err(err) => {
                        warn!(?err, "failed to request HSM to write to NVRAM");
                    }
                    Ok(PersistStateResponse::Ok { captured, .. }) => {
                        agent.0.state.lock().unwrap().captures = captured
                    }
                };
            }
        });
    }

    fn start_group_committer(&self, realm: RealmId, group: GroupId, config: Configuration) {
        info!(?realm, ?group, "Starting group committer");

        let agent = self.clone();

        tokio::spawn(async move {
            let interval = Duration::from_millis(2);
            let mut committed: Option<LogIndex> = None;
            loop {
                committed = match agent.commit_maybe(realm, group, &config, committed).await {
                    CommitterStatus::NoLongerLeader => {
                        info!(?realm, ?group, "No longer leader, stopping committer");
                        return;
                    }
                    CommitterStatus::Committing { committed: c } => c,
                };
                sleep(interval).await;
            }
        });
    }

    async fn commit_maybe(
        &self,
        realm: RealmId,
        group: GroupId,
        config: &Configuration,
        committed: Option<LogIndex>,
    ) -> CommitterStatus {
        if self
            .0
            .state
            .lock()
            .unwrap()
            .leader
            .get(&(realm, group))
            .is_none()
        {
            return CommitterStatus::NoLongerLeader;
        }

        // We're still leader for this group, go collect up all the capture results from all the group members.
        let peers = config.0.iter().collect::<HashSet<_>>();

        // TODO, we need to cache the peer mapping
        let addresses = match self.0.store.get_addresses().await {
            Err(e) => {
                warn!(err=?e, "failed to get peer addresses from service discovery");
                return CommitterStatus::Committing { committed };
            }
            Ok(addresses) => addresses,
        };

        // Go get the captures, and filter them down to just this realm/group.
        let captures = join_all(
            addresses
                .iter()
                .filter(|(id, _)| peers.contains(id))
                .map(|(_, url)| rpc::send(&self.0.peer_client, url, ReadCapturedRequest {})),
        )
        .await
        .into_iter()
        // skip network failures
        .filter_map(|r| r.ok())
        .flat_map(|r| match r {
            ReadCapturedResponse::Ok { groups } => groups.into_iter(),
        })
        .filter(|c| c.group == group && c.realm == realm)
        .collect::<Vec<_>>();

        // Calculate a commit index.
        let Some(target_index) = majority_index(
            config.0.len(),
            captures.iter().map(|c| c.index).collect(),
        ) else {
            return CommitterStatus::Committing{committed};
        };
        if let Some(commit) = committed {
            // We've already committed this.
            if target_index <= commit {
                return CommitterStatus::Committing { committed };
            }
        }
        let mut election = HsmElection::new(&config.0);
        for c in &captures {
            if c.index >= target_index {
                election.vote(c.hsm);
            }
        }
        if !election.outcome().has_quorum {
            return CommitterStatus::Committing { committed };
        }
        trace!(?group, index=?target_index, "election has quorum");
        let commit_request = CommitRequest {
            realm,
            group,
            commit_index: target_index,
            captures,
        };

        // Ask the HSM to do the commit
        let response = self.0.hsm.send(commit_request).await;
        let (new_committed, responses) = match response {
            Ok(CommitResponse::Ok {
                committed,
                responses,
            }) => {
                trace!(
                    agent = self.0.name,
                    ?committed,
                    num_responses=?responses.len(),
                    "HSM committed entry"
                );
                (committed, responses)
            }
            Ok(CommitResponse::AlreadyCommitted { committed: c }) => {
                info!(
                    agent = self.0.name,
                    ?response,
                    "commit response already committed"
                );
                return CommitterStatus::Committing { committed: Some(c) };
            }
            _ => {
                warn!(agent = self.0.name, ?response, "commit response not ok");
                return CommitterStatus::Committing { committed };
            }
        };
        // Release responses to the clients.
        let mut released_count = 0;
        let mut locked = self.0.state.lock().unwrap();
        if let Some(leader) = locked.leader.get_mut(&(realm, group)) {
            for (hmac, client_response) in responses {
                if let Some(sender) = leader.response_channels.remove(&hmac) {
                    if sender.send(client_response).is_err() {
                        warn!("dropping response on the floor: client no longer waiting");
                    }
                    released_count += 1;
                } else {
                    warn!("dropping response on the floor: client never waiting");
                }
            }
        } else if !responses.is_empty() {
            warn!("dropping responses on the floor: no leader state");
        }
        Span::current().record("released_count", released_count);
        CommitterStatus::Committing {
            committed: Some(new_committed),
        }
    }
}

fn majority_index(members: usize, mut indexes: Vec<LogIndex>) -> Option<LogIndex> {
    assert!(indexes.len() <= members);
    indexes.sort_by(|a, b| b.cmp(a));
    let m = members / 2;
    if indexes.len() > m {
        Some(indexes[m])
    } else {
        None
    }
}

impl<T: Transport + 'static> Agent<T> {
    #[instrument(level = "trace", skip(self))]
    async fn find_peers(
        &self,
        realm_id: RealmId,
        group_id: GroupId,
    ) -> Result<(Configuration, HashMap<HsmId, Option<Url>>), ()> {
        let name = &self.0.name;
        let hsm = &self.0.hsm;
        let store = &self.0.store;

        let (configuration, mut peers): (_, HashMap<HsmId, Option<Url>>) =
            match hsm.send(hsm_types::StatusRequest {}).await {
                Err(_) => todo!(),
                Ok(hsm_types::StatusResponse {
                    id: hsm_id,
                    realm: Some(realm),
                    public_key: _,
                }) => {
                    if realm.id != realm_id {
                        todo!();
                    }
                    match realm.groups.into_iter().find(|group| group.id == group_id) {
                        None => todo!(),
                        Some(group) => {
                            let peers = HashMap::from_iter(
                                group
                                    .configuration
                                    .0
                                    .iter()
                                    .filter(|id| **id != hsm_id)
                                    .map(|id| (*id, None)),
                            );
                            (group.configuration, peers)
                        }
                    }
                }
                _ => todo!(),
            };
        trace!(agent = name, peer_hsms = ?peers.keys(), "found peer HSMs from configuration");

        match store.get_addresses().await {
            Err(_) => todo!(),
            Ok(addresses) => {
                for (hsm, address) in addresses {
                    peers.entry(hsm).and_modify(|e| *e = Some(address));
                }
            }
        };
        trace!(
            agent = name,
            ?peers,
            "looked up peer agent addresses from store"
        );
        Ok((configuration, peers))
    }

    pub async fn listen(
        self,
        address: SocketAddr,
    ) -> Result<(Url, JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(address).await?;
        let url = Url::parse(&format!("http://{address}")).unwrap();

        self.start_service_registration(url.clone());
        self.restart_watching().await;
        self.start_nvram_writer();

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

    fn start_service_registration(&self, url: Url) {
        let agent = self.0.clone();
        tokio::spawn(async move {
            let fn_hsm_id = || async {
                loop {
                    match agent.hsm.send(hsm_types::StatusRequest {}).await {
                        Err(e) => {
                            warn!(err=?e, "failed to connect to HSM");
                            sleep(Duration::from_millis(10)).await;
                        }
                        Ok(hsm_types::StatusResponse { id, .. }) => return id,
                    }
                }
            };
            let hsm_id = fn_hsm_id().await;
            info!(hsm=?hsm_id, url=%url, "registering agent with service discovery");
            loop {
                if let Err(e) = agent
                    .store
                    .set_address(&hsm_id, &url, SystemTime::now())
                    .await
                {
                    warn!(err = ?e, "failed to register with service discovery");
                    sleep(bigtable::DISCOVERY_REGISTER_INTERVAL / 10).await;
                } else {
                    sleep(bigtable::DISCOVERY_REGISTER_INTERVAL).await;
                }
            }
        });
    }
}

impl<T: Transport + 'static> Service<Request<IncomingBody>> for Agent<T> {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[instrument(level = "trace", skip(self, request))]
    fn call(&mut self, request: Request<IncomingBody>) -> Self::Future {
        let parent_context = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(request.headers()))
        });
        Span::current().set_parent(parent_context);

        let agent = self.clone();
        Box::pin(
            async move {
                let Some(path) = request.uri().path().strip_prefix('/') else {
                    return Ok(Response::builder()
                        .status(http::StatusCode::NOT_FOUND)
                        .body(Full::from(Bytes::new()))
                        .unwrap());
                };
                match path {
                    AppRequest::PATH => handle_rpc(&agent, request, Self::handle_app).await,
                    BecomeLeaderRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_become_leader).await
                    }
                    CompleteTransferRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_complete_transfer).await
                    }
                    JoinGroupRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_join_group).await
                    }
                    JoinRealmRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_join_realm).await
                    }
                    NewGroupRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_new_group).await
                    }
                    NewRealmRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_new_realm).await
                    }
                    ReadCapturedRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_read_captured).await
                    }
                    StatusRequest::PATH => handle_rpc(&agent, request, Self::handle_status).await,
                    TransferInRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_transfer_in).await
                    }
                    TransferNonceRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_transfer_nonce).await
                    }
                    TransferOutRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_transfer_out).await
                    }
                    TransferStatementRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_transfer_statement).await
                    }
                    _ => Ok(Response::builder()
                        .status(http::StatusCode::NOT_FOUND)
                        .body(Full::from(Bytes::new()))
                        .unwrap()),
                }
            }
            // This doesn't look like it should do anything, but it seems to be
            // critical to connecting these spans to the parent.
            .instrument(Span::current()),
        )
    }
}

impl<T: Transport + 'static> Agent<T> {
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
                configuration: request.configuration.clone(),
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
            "creating tables for new realm"
        );
        self.0
            .store_admin
            .initialize_realm(&new_realm_response.realm)
            .await
            .expect("TODO");

        info!(
            agent = name,
            realm = ?new_realm_response.realm,
            group = ?new_realm_response.group,
            "appending log entry for new realm"
        );
        assert_eq!(new_realm_response.entry.index, LogIndex::FIRST);

        match store
            .append(
                &new_realm_response.realm,
                &new_realm_response.group,
                &[new_realm_response.entry],
                new_realm_response.delta,
            )
            .await
        {
            Ok(()) => {
                self.finish_new_group(
                    new_realm_response.realm,
                    new_realm_response.group,
                    request.configuration,
                );
                Ok(Response::Ok {
                    realm: new_realm_response.realm,
                    group: new_realm_response.group,
                    statement: new_realm_response.statement,
                })
            }
            Err(bigtable::AppendError::Grpc(_)) => Ok(Response::NoStore),
            Err(bigtable::AppendError::MerkleWrites(_)) => todo!(),
            Err(bigtable::AppendError::LogPrecondition) => Ok(Response::StorePreconditionFailed),
            Err(bigtable::AppendError::MerkleDeletes(_)) => todo!(),
        }
    }

    fn finish_new_group(&self, realm: RealmId, group: GroupId, config: Configuration) {
        self.start_watching(realm, group, LogIndex::FIRST);
        self.start_leading(realm, group, config, LogIndex::FIRST);
    }

    fn start_leading(
        &self,
        realm: RealmId,
        group: GroupId,
        config: Configuration,
        starting_index: LogIndex,
    ) {
        let existing = self.0.state.lock().unwrap().leader.insert(
            (realm, group),
            LeaderState {
                append_queue: HashMap::new(),
                appending: NotAppending {
                    next: starting_index.next(),
                },
                response_channels: HashMap::new(),
            },
        );
        assert!(existing.is_none());
        self.start_group_committer(realm, group, config);
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
                configuration: request.configuration.clone(),
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
        assert_eq!(new_group_response.entry.index, LogIndex::FIRST);

        match store
            .append(
                &realm,
                &new_group_response.group,
                &[new_group_response.entry],
                new_group_response.delta,
            )
            .await
        {
            Ok(()) => {
                self.finish_new_group(realm, new_group_response.group, request.configuration);
                Ok(Response::Ok {
                    group: new_group_response.group,
                    statement: new_group_response.statement,
                })
            }
            Err(bigtable::AppendError::Grpc(_)) => Ok(Response::NoStore),
            Err(bigtable::AppendError::MerkleWrites(_)) => todo!(),
            Err(bigtable::AppendError::LogPrecondition) => Ok(Response::StorePreconditionFailed),
            Err(bigtable::AppendError::MerkleDeletes(_)) => todo!(),
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
                self.start_watching(request.realm, request.group, LogIndex::FIRST);
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
            .read_last_log_entry(&request.realm, &request.group)
            .await
        {
            Err(_) => return Ok(Response::NoStore),
            Ok(Some(entry)) => entry,
            Ok(None) => todo!(),
        };
        let last_entry_index = last_entry.index;

        match hsm
            .send(hsm_types::BecomeLeaderRequest {
                realm: request.realm,
                group: request.group,
                last_entry,
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::Ok(config)) => {
                self.start_leading(request.realm, request.group, config, last_entry_index);
                Ok(Response::Ok)
            }
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::InvalidHmac) => panic!(),
            Ok(HsmResponse::NotCaptured { have }) => Ok(Response::NotCaptured { have }),
        }
    }

    async fn handle_read_captured(
        &self,
        _request: ReadCapturedRequest,
    ) -> Result<ReadCapturedResponse, HandlerError> {
        type Response = ReadCapturedResponse;

        let state = self.0.state.lock().unwrap();
        Ok(Response::Ok {
            groups: state.captures.clone(),
        })
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
                .read_last_log_entry(&request.realm, &request.source)
                .await
            {
                Err(_) => return Ok(Response::NoStore),
                Ok(Some(entry)) => entry,
                Ok(None) => todo!(),
            };
            let Some(partition) = entry.partition else {
                return Ok(Response::NotOwner);
            };

            // If we're moving everything then any proof from the partition is fine.
            // if we're splitting, then we need the proof for the split point.
            let rec_id = if partition.range == request.range {
                request.range.start.clone()
            } else {
                match partition.range.split_at(&request.range) {
                    Some(id) => id,
                    None => return Ok(Response::NotOwner),
                }
            };

            let proof = match merkle::agent::read(
                &request.realm,
                store,
                &partition.range,
                &partition.root_hash,
                &rec_id,
            )
            .await
            {
                Ok(proof) => proof,
                Err(TreeStoreError::MissingNode) => todo!(),
                Err(TreeStoreError::Network(e)) => {
                    warn!(error = ?e, "handle_transfer_out: error reading proof");
                    return Ok(Response::NoStore);
                }
            };

            return match hsm
                .send(hsm_types::TransferOutRequest {
                    realm: request.realm,
                    source: request.source,
                    destination: request.destination,
                    range: request.range.clone(),
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
                    self.append(realm, source, Append { entry, delta });
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

        // This loop handles retries if the read from the store is stale. It's
        // expected to run just once.
        loop {
            let entry = match store
                .read_last_log_entry(&request.realm, &request.destination)
                .await
            {
                Err(_) => return Ok(Response::NoStore),
                Ok(Some(entry)) => entry,
                Ok(None) => todo!(),
            };

            let proofs = match entry.partition {
                None => None,
                Some(partition) => {
                    let proof_dir = match partition.range.join(&request.transferring.range) {
                        None => return Ok(Response::UnacceptableRange),
                        Some(jr) => {
                            if jr.start == request.transferring.range.start {
                                Dir::Right
                            } else {
                                Dir::Left
                            }
                        }
                    };

                    let transferring_in_proof_req = merkle::agent::read_tree_side(
                        &request.realm,
                        store,
                        &request.transferring.range,
                        &request.transferring.root_hash,
                        proof_dir,
                    );
                    let owned_range_proof_req = merkle::agent::read_tree_side(
                        &request.realm,
                        store,
                        &partition.range,
                        &partition.root_hash,
                        proof_dir.opposite(),
                    );
                    let transferring_in_proof = match transferring_in_proof_req.await {
                        Err(TreeStoreError::Network(_)) => return Ok(Response::NoStore),
                        Err(TreeStoreError::MissingNode) => todo!(),
                        Ok(proof) => proof,
                    };
                    let owned_range_proof = match owned_range_proof_req.await {
                        Err(TreeStoreError::Network(_)) => return Ok(Response::NoStore),
                        Err(TreeStoreError::MissingNode) => todo!(),
                        Ok(proof) => proof,
                    };
                    Some(TransferInProofs {
                        owned: owned_range_proof,
                        transferring: transferring_in_proof,
                    })
                }
            };

            return match hsm
                .send(hsm_types::TransferInRequest {
                    realm: request.realm,
                    destination: request.destination,
                    transferring: request.transferring.clone(),
                    proofs,
                    nonce: request.nonce,
                    statement: request.statement.clone(),
                })
                .await
            {
                Err(_) => Ok(Response::NoHsm),
                Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
                Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
                Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
                Ok(HsmResponse::UnacceptableRange) => Ok(Response::UnacceptableRange),
                Ok(HsmResponse::InvalidNonce) => Ok(Response::InvalidNonce),
                Ok(HsmResponse::InvalidStatement) => Ok(Response::InvalidStatement),
                Ok(HsmResponse::InvalidProof) => todo!(),
                Ok(HsmResponse::MissingProofs) => todo!(),
                Ok(HsmResponse::StaleProof) => {
                    trace!(?hsm, "hsm said stale proof, will retry");
                    continue;
                }
                Ok(HsmResponse::Ok { entry, delta }) => {
                    let index = entry.index;
                    self.append(request.realm, request.destination, Append { entry, delta });
                    Ok(Response::Ok(index))
                }
            };
        }
    }

    async fn handle_complete_transfer(
        &self,
        request: CompleteTransferRequest,
    ) -> Result<CompleteTransferResponse, HandlerError> {
        type Response = CompleteTransferResponse;
        type HsmResponse = hsm_types::CompleteTransferResponse;
        let hsm = &self.0.hsm;

        let result = hsm
            .send(hsm_types::CompleteTransferRequest {
                realm: request.realm,
                source: request.source,
                destination: request.destination,
                range: request.range,
            })
            .await;
        match result {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
            Ok(HsmResponse::NotTransferring) => Ok(Response::NotTransferring),
            Ok(HsmResponse::Ok(entry)) => {
                let index = entry.index;
                self.append(
                    request.realm,
                    request.source,
                    Append {
                        entry,
                        delta: StoreDelta::default(),
                    },
                );
                Ok(Response::Ok(index))
            }
        }
    }

    /// Called by `handle_app` to process [`AppRequest`]s of type Handshake
    /// that don't have a payload. Unlike other [`AppRequest`]s, these don't
    /// require dealing with the log or Merkle tree.
    async fn handle_handshake(&self, request: AppRequest) -> Result<AppResponse, HandlerError> {
        type Response = AppResponse;
        type HsmResponse = hsm_types::HandshakeResponse;

        match self
            .0
            .hsm
            .send(hsm_types::HandshakeRequest {
                realm: request.realm,
                group: request.group,
                record_id: request.record_id,
                session_id: request.session_id,
                handshake: match request.encrypted {
                    NoiseRequest::Handshake { handshake } => handshake,
                    NoiseRequest::Transport { .. } => {
                        unreachable!("handle_handshake shouldn't be used for Transport requests");
                    }
                },
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::NotLeader | HsmResponse::NotOwner) => Ok(Response::NotLeader),
            Ok(HsmResponse::MissingSession) => Ok(Response::MissingSession),
            Ok(HsmResponse::SessionError) => Ok(Response::SessionError),
            Ok(HsmResponse::DecodingError) => Ok(Response::DecodingError),
            Ok(HsmResponse::Ok {
                noise,
                session_lifetime,
            }) => Ok(Response::Ok(NoiseResponse::Handshake {
                handshake: noise,
                session_lifetime,
            })),
        }
    }

    /// The top-level handler for all [`AppRequest`]s. This deals with requests
    /// of type Transport and of type Handshake that have a payload. It
    /// delegates requests of type Handshake that don't have a payload, since
    /// those can be handled more efficiently without dealing with the log or
    /// Merkle tree.
    async fn handle_app(&self, request: AppRequest) -> Result<AppResponse, HandlerError> {
        type Response = AppResponse;

        match request.kind {
            ClientRequestKind::HandshakeOnly => return self.handle_handshake(request).await,
            ClientRequestKind::SecretsRequest => { /* handled here, below */ }
        }

        let realm = request.realm;
        let group = request.group;

        let name = &self.0.name;
        let hsm = &self.0.hsm;
        let store = &self.0.store;

        let result = start_app_request(request, name.clone(), hsm, store).await;
        match result {
            Err(response) => Ok(response),
            Ok(append_request) => {
                let (sender, receiver) = oneshot::channel::<NoiseResponse>();

                {
                    let mut locked = self.0.state.lock().unwrap();
                    let Some(leader) = locked.leader.get_mut(&(realm, group)) else {
                        return Ok(Response::NotLeader);
                    };
                    leader
                        .response_channels
                        .insert(append_request.entry.entry_hmac.clone(), sender);
                }

                self.append(realm, group, append_request);
                match receiver.await {
                    Ok(response) => Ok(Response::Ok(response)),
                    Err(oneshot::Canceled) => Ok(Response::NotLeader),
                }
            }
        }
    }
}

async fn start_app_request<T: Transport>(
    request: AppRequest,
    name: String,
    hsm: &HsmClient<T>,
    store: &bigtable::StoreClient,
) -> Result<Append, AppResponse> {
    type HsmResponse = hsm_types::AppResponse;
    type Response = AppResponse;

    for attempt in 0..100 {
        let entry = match store
            .read_last_log_entry(&request.realm, &request.group)
            .await
        {
            Err(_) => return Err(Response::NoStore),
            Ok(Some(entry)) => entry,
            Ok(None) => return Err(Response::InvalidGroup),
        };

        let Some(partition) = entry.partition else {
            return Err(Response::NotLeader); // TODO: is that the right error?
        };

        let proof = match merkle::agent::read(
            &request.realm,
            store,
            &partition.range,
            &partition.root_hash,
            &request.record_id,
        )
        .await
        {
            Ok(proof) => proof,
            Err(TreeStoreError::MissingNode) => {
                warn!(
                    agent = name,
                    attempt,
                    index = ?entry.index,
                    "missing node, retrying"
                );
                continue;
            }
            Err(TreeStoreError::Network(e)) => {
                warn!(error = ?e, "start_app_request: error reading proof");
                return Err(Response::NoStore);
            }
        };

        match hsm
            .send(hsm_types::AppRequest {
                realm: request.realm,
                group: request.group,
                record_id: request.record_id.clone(),
                session_id: request.session_id,
                encrypted: request.encrypted.clone(),
                index: entry.index,
                proof,
            })
            .await
        {
            Err(_) => return Err(Response::NoHsm),
            Ok(HsmResponse::InvalidRealm) => return Err(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => return Err(Response::InvalidGroup),
            Ok(HsmResponse::StaleProof) => {
                warn!(
                    agent = name,
                    attempt, index = ?entry.index,
                    "stale proof, retrying"
                );
                continue;
            }
            Ok(HsmResponse::NotLeader | HsmResponse::NotOwner) => return Err(Response::NotLeader),
            Ok(HsmResponse::InvalidProof) => return Err(Response::InvalidProof),
            // TODO, is this right? if we can't decrypt the leaf, then the proof is likely bogus.
            Ok(HsmResponse::InvalidRecordData) => return Err(Response::InvalidProof),
            Ok(HsmResponse::MissingSession) => return Err(Response::MissingSession),
            Ok(HsmResponse::SessionError) => return Err(Response::SessionError),
            Ok(HsmResponse::DecodingError) => return Err(Response::DecodingError),

            Ok(HsmResponse::Ok { entry, delta }) => {
                trace!(
                    agent = name,
                    ?entry,
                    ?delta,
                    "got new log entry and data updates from HSM"
                );
                return Ok(Append { entry, delta });
            }
        };
    }
    panic!("too slow to make progress");
}

impl<T: Transport + 'static> Agent<T> {
    /// Precondition: agent is leader.
    fn append(&self, realm: RealmId, group: GroupId, append_request: Append) {
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

            tokio::spawn(async move { agent.keep_appending(realm, group, next).await });
        }
    }

    const MAX_APPEND_BATCH_SIZE: usize = 100;

    /// Precondition: `leader.appending` is Appending because this task is the one
    /// doing the appending.
    async fn keep_appending(&self, realm: RealmId, group: GroupId, next: LogIndex) {
        let mut next = next;
        let mut batch = Vec::new();

        loop {
            let mut delta = StoreDelta::default();
            batch.clear();
            {
                let mut locked = self.0.state.lock().unwrap();
                let Some(leader) = locked.leader.get_mut(&(realm, group)) else {
                    return;
                };
                assert!(matches!(leader.appending, Appending));
                while let Some(request) = leader.append_queue.remove(&next) {
                    batch.push(request.entry);
                    if delta.is_empty() {
                        delta = request.delta;
                    } else {
                        delta.squash(request.delta);
                    }
                    next = next.next();
                    if batch.len() >= Self::MAX_APPEND_BATCH_SIZE {
                        break;
                    }
                }
                if batch.is_empty() {
                    leader.appending = NotAppending { next };
                    return;
                }
            }

            match self.0.store.append(&realm, &group, &batch, delta).await {
                Err(bigtable::AppendError::LogPrecondition) => {
                    todo!("stop leading")
                }
                Err(_) => todo!(),
                Ok(()) => {}
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::majority_index;
    use hsmcore::hsm::types::LogIndex;

    #[test]
    fn majority_index_calc() {
        let indexes = |i: Vec<u64>| i.into_iter().map(LogIndex).collect::<Vec<_>>();
        assert_eq!(
            Some(LogIndex(15)),
            majority_index(5, indexes(vec![15, 15, 15, 14, 13]))
        );
        assert_eq!(
            Some(LogIndex(14)),
            majority_index(5, indexes(vec![15, 13, 15, 14, 13]))
        );
        assert_eq!(
            Some(LogIndex(13)),
            majority_index(5, indexes(vec![13, 15, 14]))
        );
        assert_eq!(None, majority_index(5, indexes(vec![15, 15])));
        assert_eq!(
            Some(LogIndex(14)),
            majority_index(3, indexes(vec![15, 14, 13]))
        );
        assert_eq!(
            Some(LogIndex(13)),
            majority_index(4, indexes(vec![15, 14, 13, 12]))
        );
        assert_eq!(Some(LogIndex(13)), majority_index(2, indexes(vec![15, 13])));
    }
}
