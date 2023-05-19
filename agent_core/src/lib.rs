use anyhow::Context;
use bytes::Bytes;
use futures::channel::oneshot;
use futures::Future;
use hsmcore::hsm::types::{DataHash, LogEntry};
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use loam_mvp::metrics::Warn;
use opentelemetry_http::HeaderExtractor;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{info, instrument, trace, warn, Instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use url::Url;

mod commit;

pub use loam_mvp::realm::agent::types;

use hsm_types::{
    CaptureNextRequest, CaptureNextResponse, Captured, Configuration, EntryHmac, GroupId, HsmId,
    LogIndex, TransferInProofs,
};
use hsmcore::hsm::types as hsm_types;
use hsmcore::merkle::agent::{StoreDelta, TreeStoreError};
use hsmcore::merkle::Dir;
use loam_mvp::http_client::{Client, ClientOptions};
use loam_mvp::realm::hsm::client::{HsmClient, Transport};
use loam_mvp::realm::merkle;
use loam_mvp::realm::rpc::{handle_rpc, HandlerError};
use loam_mvp::realm::store::bigtable;
use loam_sdk_core::requests::{ClientRequestKind, NoiseRequest, NoiseResponse};
use loam_sdk_core::types::RealmId;
use loam_sdk_networking::rpc::Rpc;
use types::{
    AgentService, AppRequest, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse,
    CompleteTransferRequest, CompleteTransferResponse, JoinGroupRequest, JoinGroupResponse,
    JoinRealmRequest, JoinRealmResponse, NewGroupRequest, NewGroupResponse, NewRealmRequest,
    NewRealmResponse, ReadCapturedRequest, ReadCapturedResponse, StatusRequest, StatusResponse,
    StepDownRequest, StepDownResponse, TransferInRequest, TransferInResponse, TransferNonceRequest,
    TransferNonceResponse, TransferOutRequest, TransferOutResponse, TransferStatementRequest,
    TransferStatementResponse,
};

#[derive(Debug)]
pub struct Agent<T>(Arc<AgentInner<T>>);

#[derive(Debug)]
struct AgentInner<T> {
    name: String,
    boot_time: Instant,
    hsm: HsmClient<T>,
    store: bigtable::StoreClient,
    store_admin: bigtable::StoreAdminClient,
    peer_client: Client<AgentService>,
    state: Mutex<State>,
    metrics: dogstatsd::Client,
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
    /// When set the leader is stepping down, and should stop processing once
    /// this log entry is complete.
    stepdown_at: Option<LogIndex>,
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

impl<T: Transport + 'static> Agent<T> {
    pub fn new(
        name: String,
        hsm: HsmClient<T>,
        store: bigtable::StoreClient,
        store_admin: bigtable::StoreAdminClient,
    ) -> Self {
        Self(Arc::new(AgentInner {
            name,
            boot_time: Instant::now(),
            hsm,
            store,
            store_admin,
            peer_client: Client::new(ClientOptions::default()),
            state: Mutex::new(State {
                leader: HashMap::new(),
                captures: Vec::new(),
            }),
            metrics: dogstatsd::Client::new(
                dogstatsd::OptionsBuilder::new()
                    .default_tag(String::from("service:agent"))
                    .build(),
            )
            .unwrap(),
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

    pub async fn listen(self, address: SocketAddr) -> Result<(Url, JoinHandle<()>), anyhow::Error> {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("failed to bind to {address}"))?;
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

    /// Attempt a graceful shutdown, this includes having the HSM stepdown as leader
    /// if its leading and wait for all the pending responses to be sent to the
    /// client. Blocks until the shutdown is complete.
    pub async fn shutdown(&self, timeout: Duration) {
        let leading = {
            let state = self.0.state.lock().unwrap();
            if state.leader.is_empty() {
                // easy case, we're not leader, job done.
                return;
            }
            state.leader.keys().copied().collect::<Vec<_>>()
        };
        info!("Starting graceful agent shutdown");
        let start = Instant::now();
        for (realm, group) in leading {
            if let Err(err) = self
                .handle_stepdown_as_leader(StepDownRequest { realm, group })
                .await
            {
                warn!(
                    ?group,
                    ?realm,
                    ?err,
                    "failed to request leadership stepdown"
                )
            }
        }
        // now wait til we're done stepping down.
        info!("Waiting for leadership stepdown(s) to complete.");
        loop {
            if self.0.state.lock().unwrap().leader.is_empty() {
                return;
            }
            if start.elapsed() > timeout {
                warn!("Timed out waiting for stepdown to complete.");
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
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
                    sleep(bigtable::discovery::REGISTER_FAILURE_DELAY).await;
                } else {
                    sleep(bigtable::discovery::REGISTER_INTERVAL).await;
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

        // If the client disconnects while the request processing is still in
        // flight the future we return from this function gets dropped and it
        // won't progress any further than its next .await point. This is
        // bad(tm). This can lead to situations where the HSM has generated a
        // log entry but it never makes it to the append queue. At which point
        // the group is stalled until something forces a leader change. To
        // prevent this we tokio::spawn the work we want to do to ensure it runs
        // to completion. The returned future is then a simple future waiting on
        // the tokio join handle. Tokio ensures that the task runs to completion
        // even if the join handle is dropped.
        let agent = self.clone();
        let join_handle = tokio::spawn(
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
                    StepDownRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_stepdown_as_leader).await
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
        );
        Box::pin(
            async move {
                match join_handle.await {
                    Ok(r) => r,
                    Err(err) => {
                        warn!(?err, "Agent task failed with error");
                        Ok(Response::builder()
                            .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Full::from(Bytes::new()))
                            .unwrap())
                    }
                }
            }
            .instrument(Span::current()),
        )
    }
}

impl<T: Transport + 'static> Agent<T> {
    async fn handle_status(&self, _request: StatusRequest) -> Result<StatusResponse, HandlerError> {
        let hsm_status = self.0.hsm.send(hsm_types::StatusRequest {}).await;
        Ok(StatusResponse {
            hsm: hsm_status.ok(),
            uptime: self.0.boot_time.elapsed(),
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
                stepdown_at: None,
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

        let last_entry = match request.last {
            None => match store
                .read_last_log_entry(&request.realm, &request.group)
                .await
            {
                Err(_) => return Ok(Response::NoStore),
                Ok(Some(entry)) => entry,
                Ok(None) => todo!(),
            },
            // If the cluster manager is doing a coordinated leadership handoff it
            // knows what the last log index of the stepping down leader owned,
            // we'll wait for that to be available.
            Some(idx) => {
                let entry: LogEntry;
                let start = Instant::now();
                loop {
                    entry = match store
                        .read_log_entry(&request.realm, &request.group, idx)
                        .await
                    {
                        Err(_) => return Ok(Response::NoStore),
                        Ok(Some(entry)) => entry,
                        Ok(None) => {
                            if start.elapsed() > Duration::from_secs(5) {
                                return Ok(Response::TimeoutWaitForLogIndex);
                            }
                            sleep(Duration::from_millis(2)).await;
                            continue;
                        }
                    };
                    break;
                }
                entry
            }
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
            Ok(HsmResponse::Ok { config }) => {
                self.start_leading(request.realm, request.group, config, last_entry_index);
                Ok(Response::Ok)
            }
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::StepdownInProgress) => Ok(Response::StepdownInProgress),
            Ok(HsmResponse::InvalidHmac) => panic!(),
            Ok(HsmResponse::NotCaptured { have }) => Ok(Response::NotCaptured { have }),
        }
    }

    async fn handle_stepdown_as_leader(
        &self,
        request: StepDownRequest,
    ) -> Result<StepDownResponse, HandlerError> {
        type Response = StepDownResponse;
        type HsmResponse = hsm_types::StepDownResponse;

        if self
            .0
            .state
            .lock()
            .unwrap()
            .leader
            .get(&(request.realm, request.group))
            .is_none()
        {
            return Ok(Response::NotLeader);
        }
        match self
            .0
            .hsm
            .send(hsm_types::StepDownRequest {
                realm: request.realm,
                group: request.group,
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::Complete { last }) => {
                info!(group=?request.group, realm=?request.realm, "HSM Stepped down as leader");
                let leader_state = self
                    .0
                    .state
                    .lock()
                    .unwrap()
                    .leader
                    .remove(&(request.realm, request.group));

                if let Some(ls) = leader_state {
                    assert!(ls.append_queue.is_empty());
                }
                Ok(Response::Ok { last })
            }
            Ok(HsmResponse::InProgress { last }) => {
                info!(group=?request.group, realm=?request.realm, index=?last, "HSM will stepdown as leader");
                // This is not as racy as it may appear as the HSM will only
                // return Complete or InProgress when it atomically steps down
                // as leader. So even if a bunch of step down requests came in
                // at once, only one of them would get here. (or Complete)
                self.0
                    .state
                    .lock()
                    .unwrap()
                    .leader
                    .get_mut(&(request.realm, request.group))
                    .unwrap()
                    .stepdown_at = Some(last);
                Ok(Response::Ok { last })
            }
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::NotLeader) => Ok(Response::NotLeader),
        }
    }

    async fn handle_read_captured(
        &self,
        request: ReadCapturedRequest,
    ) -> Result<ReadCapturedResponse, HandlerError> {
        type Response = ReadCapturedResponse;

        let state = self.0.state.lock().unwrap();
        let c = state
            .captures
            .iter()
            .find(|c| c.group == request.group && c.realm == request.realm)
            .cloned();
        Ok(Response::Ok(c))
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
    #[instrument(level = "trace", skip(self))]
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
    #[instrument(level = "trace", skip(self, request))]
    async fn handle_app(&self, request: AppRequest) -> Result<AppResponse, HandlerError> {
        match request.kind {
            ClientRequestKind::HandshakeOnly => return self.handle_handshake(request).await,
            ClientRequestKind::SecretsRequest => { /* handled here, below */ }
        }

        let realm = request.realm;
        let group = request.group;

        match start_app_request(request, self.0.name.clone(), &self.0.hsm, &self.0.store).await {
            Err(response) => Ok(response),
            Ok(append_request) => self.finish_app_request(realm, group, append_request).await,
        }
    }

    #[instrument(level = "trace", skip(realm, group, append_request))]
    async fn finish_app_request(
        &self,
        realm: RealmId,
        group: GroupId,
        append_request: Append,
    ) -> Result<AppResponse, HandlerError> {
        type Response = AppResponse;

        let (sender, receiver) = oneshot::channel::<NoiseResponse>();
        let start = Instant::now();

        {
            let mut locked = self.0.state.lock().unwrap();
            let leader = locked.leader.get_mut(&(realm, group))
                        .expect("The HSM thought it was leader and generated a response, but the agent has no leader state");

            leader
                .response_channels
                .insert(append_request.entry.entry_hmac.clone(), sender);
        }

        self.append(realm, group, append_request);
        match receiver.await {
            Ok(response) => {
                self.0
                    .metrics
                    .timing(
                        "agent.commit.latency.ms",
                        start.elapsed().as_millis() as i64,
                        [&format!("realm:{:?}", realm), &format!("group:{:?}", group)],
                    )
                    .warn_err();

                Ok(Response::Ok(response))
            }
            Err(oneshot::Canceled) => Ok(Response::NotLeader),
        }
    }
}

#[instrument(level = "trace")]
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
        let metric_tags = &[&format!("realm:{:?}", realm), &format!("group:{:?}", group)];
        let mut queue_depth: usize;

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
                queue_depth = leader.append_queue.len();
            }

            let start = Instant::now();
            match self.0.store.append(&realm, &group, &batch, delta).await {
                Err(bigtable::AppendError::LogPrecondition) => {
                    warn!(
                        name = self.0.name,
                        "detected dueling leaders, stepping down"
                    );
                    {
                        let mut locked = self.0.state.lock().unwrap();
                        // Empty the queue so we don't try and append anything else.
                        if let Some(ls) = locked.leader.get_mut(&(realm, group)) {
                            ls.append_queue.clear();
                            ls.appending = NotAppending {
                                next: LogIndex(u64::MAX),
                            };
                        }
                    }
                    self.handle_stepdown_as_leader(StepDownRequest { realm, group })
                        .await
                        .expect("error during leader stepdown");
                    return;
                }
                Err(err) => todo!("{err:?}"),
                Ok(()) => {
                    self.record_append_metrics(
                        start.elapsed(),
                        batch.len(),
                        queue_depth,
                        metric_tags,
                    );
                }
            }
        }
    }

    fn record_append_metrics(
        &self,
        elapsed: Duration,
        batch_size: usize,
        queue_depth: usize,
        tags: &[&String],
    ) {
        self.0
            .metrics
            .timing("bigtable.append.time.ms", elapsed.as_millis() as i64, tags)
            .warn_err();

        self.0
            .metrics
            .histogram("bigtable.append.batch.size", batch_size.to_string(), tags)
            .warn_err();

        self.0
            .metrics
            .histogram("bigtable.append.queue.size", queue_depth.to_string(), tags)
            .warn_err();
    }
}
