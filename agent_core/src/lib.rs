use anyhow::Context;
use bytes::Bytes;
use futures::channel::oneshot;
use futures::Future;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use opentelemetry_http::HeaderExtractor;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{info, instrument, span, trace, warn, Instrument, Level, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use url::Url;

mod append;
mod commit;
pub mod hsm;
pub mod merkle;
mod tenants;

use agent_api::merkle::TreeStoreError;
use agent_api::{
    AgentService, AppRequest, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse,
    CompleteTransferRequest, CompleteTransferResponse, JoinGroupRequest, JoinGroupResponse,
    JoinRealmRequest, JoinRealmResponse, NewGroupRequest, NewGroupResponse, NewRealmRequest,
    NewRealmResponse, ReadCapturedRequest, ReadCapturedResponse, StatusRequest, StatusResponse,
    StepDownRequest, StepDownResponse, TransferInRequest, TransferInResponse, TransferNonceRequest,
    TransferNonceResponse, TransferOutRequest, TransferOutResponse, TransferStatementRequest,
    TransferStatementResponse,
};
use append::{Append, AppendingState};
use cluster_api::ClusterService;
use hsm::{HsmClient, Transport};
use hsm_api::merkle::{Dir, StoreDelta};
use hsm_api::{
    AppRequestType, CaptureNextRequest, CaptureNextResponse, Captured, EntryMac, GroupId, HsmId,
    LogEntry, LogIndex, TransferInProofs,
};
use juicebox_networking::reqwest::{self, Client, ClientOptions};
use juicebox_networking::rpc::{self, Rpc};
use juicebox_realm_api::requests::{ClientRequestKind, NoiseRequest, NoiseResponse};
use juicebox_realm_api::types::RealmId;
use observability::logging::TracingSource;
use observability::metrics::{self};
use observability::metrics_tag as tag;
use service_core::rpc::{handle_rpc, HandlerError};
use store::{self, discovery, LogEntriesIter, ServiceKind};
use tenants::UserAccountingManager;

#[derive(Debug)]
pub struct Agent<T>(Arc<AgentInner<T>>);

#[derive(Debug)]
struct AgentInner<T> {
    name: String,
    boot_time: Instant,
    hsm: HsmClient<T>,
    store: store::StoreClient,
    store_admin: store::StoreAdminClient,
    peer_client: Client<AgentService>,
    state: Mutex<State>,
    metrics: metrics::Client,
    accountant: UserAccountingManager,
}

#[derive(Debug)]
struct State {
    /// State about a group that's needed while the HSM is Leader or SteppingDown.
    leader: HashMap<(RealmId, GroupId), LeaderState>,
    // Captures that have been persisted to NVRAM in the HSM.
    captures: Vec<Captured>,
    // Set after being successfully registered with service discovery.
    registered: bool,
}

// State about a group that is used in the Leader or SteppingDown state.
#[derive(Debug)]
struct LeaderState {
    /// Log entries may be received out of order from the HSM. They are buffered
    /// here until they can be appended to the log in order.
    append_queue: HashMap<LogIndex, Append>,

    /// This serves as a mutex to prevent multiple concurrent appends to the
    /// store.
    appending: append::AppendingState,

    /// A copy of the last log entry that was acknowledged by the store.
    ///
    /// This is used in the read path to avoid reading the last log entry in
    /// the common case.
    last_appended: Option<LogEntry>,

    /// Used to route responses back to the right client after the HSM commits
    /// a batch of log entries and releases the responses.
    response_channels: HashMap<HashableEntryMac, oneshot::Sender<NoiseResponse>>,
}

#[derive(Debug, PartialEq, Eq)]
struct HashableEntryMac(EntryMac);

impl From<EntryMac> for HashableEntryMac {
    fn from(value: EntryMac) -> Self {
        HashableEntryMac(value)
    }
}

impl std::hash::Hash for HashableEntryMac {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state);
    }
}

impl<T> Clone for Agent<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Transport + 'static> Agent<T> {
    pub fn new(
        name: String,
        hsm: HsmClient<T>,
        store: store::StoreClient,
        store_admin: store::StoreAdminClient,
        metrics: metrics::Client,
    ) -> Self {
        Self(Arc::new(AgentInner {
            name,
            boot_time: Instant::now(),
            hsm,
            store: store.clone(),
            store_admin,
            peer_client: Client::new(ClientOptions::default()),
            state: Mutex::new(State {
                leader: HashMap::new(),
                captures: Vec::new(),
                registered: false,
            }),
            metrics: metrics.clone(),
            accountant: UserAccountingManager::new(store, metrics),
        }))
    }

    /// Called at service startup, start watching for any groups that the HSM is already a member of.
    async fn restart_watching(&self) {
        let status = self.0.hsm.send(hsm_api::StatusRequest {}).await;
        if let Ok(sr) = status {
            if let Some(realm) = sr.realm {
                for g in &realm.groups {
                    let idx = match g.captured {
                        Some((index, _)) => index.next(),
                        None => LogIndex::FIRST,
                    };
                    self.start_watching(realm.id, g.id, idx);
                }
            }
        }
    }

    fn start_watching(&self, realm: RealmId, group: GroupId, next_index: LogIndex) {
        let state = self.0.clone();

        info!(
            agent = state.name,
            ?realm,
            ?group,
            ?next_index,
            "start watching log"
        );

        tokio::spawn(async move {
            let mut it = state.store.read_log_entries_iter(
                realm,
                group,
                next_index,
                (Self::MAX_APPEND_BATCH_SIZE * 2).try_into().unwrap(),
            );
            let cx = opentelemetry::Context::new().with_value(TracingSource::BackgroundJob);

            loop {
                let span = span!(Level::TRACE, "log_watcher_loop");
                span.set_parent(cx.clone());

                Self::watch_log_one(state.clone(), &mut it, realm, group)
                    .instrument(span)
                    .await;
            }
        });
    }

    #[instrument(
        level = "trace",
        skip(state, it),
        fields(num_log_entries_read, num_captured, index)
    )]
    async fn watch_log_one(
        state: Arc<AgentInner<T>>,
        it: &mut LogEntriesIter,
        realm: RealmId,
        group: GroupId,
    ) {
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
                let span = Span::current();
                let num_entries = entries.len();
                span.record("num_log_entries_read", num_entries);
                span.record("index", entries[0].index.0);

                match state
                    .hsm
                    .send(CaptureNextRequest {
                        realm,
                        group,
                        entries,
                    })
                    .await
                {
                    Err(err) => todo!("{err:?}"),
                    Ok(CaptureNextResponse::Ok(role)) => {
                        Span::current().record("num_captured", num_entries);
                        state.maybe_role_changed(realm, group, role);
                    }
                    Ok(r) => todo!("{r:#?}"),
                }
            }
        }
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
    /// if its leading and waiting for all the pending responses to be sent to the
    /// client. Blocks until the shutdown is complete or timeout expires.
    pub async fn shutdown(&self) {
        let get_leading = || {
            let state = self.0.state.lock().unwrap();
            state.leader.keys().copied().collect::<Vec<_>>()
        };
        let leading = get_leading();
        if leading.is_empty() {
            // easy case, we're not leader, job done.
            return;
        }
        info!("Starting graceful agent shutdown");

        let maybe_hsm_id = self
            .0
            .hsm
            .send(hsm_api::StatusRequest {})
            .await
            .ok()
            .map(|s| s.id);

        // If there's a cluster manager available via service discovery, ask
        // that to perform the step down. The cluster manager can handle the
        // hand-off such that clients don't see an availability gap. If there
        // isn't one we'll step down gracefully but there may be an availability
        // gap until a new leader is appointed.
        if let Some(hsm_id) = maybe_hsm_id {
            self.stepdown_with_cluster_manager(hsm_id).await;
        }
        let leading = get_leading();
        if !leading.is_empty() {
            // We're still leader after trying with the cluster manager, force a local stepdown.
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
        }
        // now wait til we're done stepping down.
        info!("Waiting for leadership stepdown(s) to complete.");
        loop {
            if self.0.state.lock().unwrap().leader.is_empty() {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    }

    // Find a cluster manager and ask it to stepdown all the groups we're leading.
    async fn stepdown_with_cluster_manager(&self, id: HsmId) {
        match self
            .0
            .store
            .get_addresses(Some(ServiceKind::ClusterManager))
            .await
        {
            Ok(managers) if !managers.is_empty() => {
                let mc = reqwest::Client::<ClusterService>::new(ClientOptions::default());
                for manager in &managers {
                    let req = cluster_api::StepDownRequest::Hsm(id);
                    match rpc::send(&mc, &manager.0, req).await {
                        Ok(cluster_api::StepDownResponse::Ok) => return,
                        Ok(res) => {
                            warn!(?res, url=%manager.0, "stepdown not ok");
                        }
                        Err(err) => {
                            warn!(?err, url=%manager.0, "stepdown reported error");
                        }
                    }
                }
            }
            Ok(_) => {
                warn!("Unable to find cluster manager in service discovery.");
            }
            Err(err) => {
                warn!(?err, "error reading from service discovery.")
            }
        }
    }

    fn start_service_registration(&self, url: Url) {
        let agent = self.0.clone();
        tokio::spawn(async move {
            let fn_hsm_id = || async {
                loop {
                    match agent.hsm.send(hsm_api::StatusRequest {}).await {
                        Err(e) => {
                            warn!(err=?e, "failed to connect to HSM");
                            sleep(Duration::from_millis(10)).await;
                        }
                        Ok(hsm_api::StatusResponse { id, .. }) => return id,
                    }
                }
            };
            let hsm_id = fn_hsm_id().await;
            info!(hsm=?hsm_id, %url, "registering agent with service discovery");
            let mut first_registration = true;
            loop {
                if let Err(e) = agent
                    .store
                    .set_address(&url, ServiceKind::Agent, SystemTime::now())
                    .await
                {
                    warn!(err = ?e, "failed to register with service discovery");
                    sleep(discovery::REGISTER_FAILURE_DELAY).await;
                } else {
                    if first_registration {
                        agent.state.lock().unwrap().registered = true;
                        first_registration = false;
                    }
                    sleep(discovery::REGISTER_INTERVAL).await;
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
                    StatusRequest::PATH => handle_rpc(&agent, request, Self::handle_status).await,
                    "livez" => Ok(agent.handle_livez(request).await),
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
        let hsm_status = self.0.hsm.send(hsm_api::StatusRequest {}).await;
        Ok(StatusResponse {
            hsm: hsm_status.ok(),
            uptime: self.0.boot_time.elapsed(),
        })
    }

    async fn handle_livez(&self, _request: Request<IncomingBody>) -> Response<Full<Bytes>> {
        if !self.0.state.lock().unwrap().registered {
            return Response::builder()
                .status(http::StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::from(Bytes::from(
                    "not yet registered with service discovery",
                )))
                .unwrap();
        }
        match tokio::time::timeout(
            Duration::from_secs(1),
            self.0.hsm.send(hsm_api::StatusRequest {}),
        )
        .await
        {
            Ok(Ok(status)) => Response::builder()
                .status(http::StatusCode::OK)
                .body(Full::from(Bytes::from(format!("hsm id: {:?}", status.id))))
                .unwrap(),

            Ok(Err(transport_error)) => Response::builder()
                .status(http::StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::from(Bytes::from(format!(
                    "error: {transport_error:?}"
                ))))
                .unwrap(),

            Err(elapsed) => Response::builder()
                .status(http::StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::from(Bytes::from(format!("timeout: {elapsed:?}"))))
                .unwrap(),
        }
    }

    async fn handle_new_realm(
        &self,
        _request: NewRealmRequest,
    ) -> Result<NewRealmResponse, HandlerError> {
        type Response = NewRealmResponse;
        let name = &self.0.name;

        // Get the HSM ID (which is used as the new group's Configuration
        // below). This also checks if a realm already exists, because it might
        // as well.
        let hsm_id = match self.0.hsm.send(hsm_api::StatusRequest {}).await {
            Err(_) => return Ok(Response::NoHsm),
            Ok(hsm_api::StatusResponse { realm: Some(_), .. }) => return Ok(Response::HaveRealm),
            Ok(hsm_api::StatusResponse { id, .. }) => id,
        };

        info!(agent = name, ?hsm_id, "creating new realm");
        let (realm, group, entry, delta) = match self.0.hsm.send(hsm_api::NewRealmRequest {}).await
        {
            Err(_) => return Ok(Response::NoHsm),
            Ok(hsm_api::NewRealmResponse::HaveRealm) => return Ok(Response::HaveRealm),
            Ok(hsm_api::NewRealmResponse::Ok {
                realm,
                group,
                entry,
                delta,
            }) => (realm, group, entry, delta),
        };

        info!(
            agent = name,
            ?realm,
            ?group,
            "creating tables for new realm"
        );
        self.0
            .store_admin
            .initialize_realm(&realm)
            .await
            .expect("TODO");

        info!(
            agent = name,
            ?realm,
            ?group,
            "appending log entry for new realm"
        );
        assert_eq!(entry.index, LogIndex::FIRST);

        match self.0.store.append(&realm, &group, &[entry], delta).await {
            Ok(()) => {
                self.finish_new_group(realm, group, vec![hsm_id]);
                Ok(Response::Ok { realm, group })
            }
            Err(store::AppendError::Grpc(_)) => Ok(Response::NoStore),
            Err(store::AppendError::MerkleWrites(_)) => todo!(),
            Err(store::AppendError::LogPrecondition) => Ok(Response::StorePreconditionFailed),
            Err(store::AppendError::MerkleDeletes(_)) => {
                unreachable!("no merkle nodes to delete")
            }
        }
    }

    fn finish_new_group(&self, realm: RealmId, group: GroupId, config: Vec<HsmId>) {
        self.start_watching(realm, group, LogIndex::FIRST);
        self.start_leading(realm, group, config, LogIndex::FIRST);
    }

    fn start_leading(
        &self,
        realm: RealmId,
        group: GroupId,
        config: Vec<HsmId>,
        starting_index: LogIndex,
    ) {
        // The HSM will return Ok to become_leader if its already leader.
        // When we get here we might already be leading.
        let start = if let Entry::Vacant(entry) =
            self.0.state.lock().unwrap().leader.entry((realm, group))
        {
            entry.insert(LeaderState {
                append_queue: HashMap::new(),
                appending: AppendingState::NotAppending {
                    next: starting_index.next(),
                },
                last_appended: None,
                response_channels: HashMap::new(),
            });
            true
        } else {
            false
        };
        if start {
            self.start_group_committer(realm, group, config);
        }
    }

    async fn handle_join_realm(
        &self,
        request: JoinRealmRequest,
    ) -> Result<JoinRealmResponse, HandlerError> {
        type Response = JoinRealmResponse;
        type HsmResponse = hsm_api::JoinRealmResponse;

        match self
            .0
            .hsm
            .send(hsm_api::JoinRealmRequest {
                realm: request.realm,
                peer: request.peer,
                statement: request.statement,
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::HaveOtherRealm) => Ok(Response::HaveOtherRealm),
            Ok(HsmResponse::InvalidStatement) => Ok(Response::InvalidStatement),
            Ok(HsmResponse::Ok { hsm }) => Ok(Response::Ok { hsm }),
        }
    }

    async fn handle_new_group(
        &self,
        request: NewGroupRequest,
    ) -> Result<NewGroupResponse, HandlerError> {
        type Response = NewGroupResponse;
        type HsmResponse = hsm_api::NewGroupResponse;

        let name = &self.0.name;
        let hsm = &self.0.hsm;
        let store = &self.0.store;

        let realm = request.realm;

        let configuration: Vec<HsmId> = request.members.iter().map(|(id, _)| *id).collect();

        let (group, statement, entry) = match hsm
            .send(hsm_api::NewGroupRequest {
                realm,
                members: request.members,
            })
            .await
        {
            Err(_) => return Ok(Response::NoHsm),
            Ok(HsmResponse::InvalidRealm) => return Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidConfiguration) => return Ok(Response::InvalidConfiguration),
            Ok(HsmResponse::InvalidStatement) => return Ok(Response::InvalidStatement),
            Ok(HsmResponse::TooManyGroups) => return Ok(Response::TooManyGroups),
            Ok(HsmResponse::Ok {
                group,
                statement,
                entry,
            }) => (group, statement, entry),
        };

        info!(
            agent = name,
            ?realm,
            ?group,
            "appending log entry for new group"
        );
        assert_eq!(entry.index, LogIndex::FIRST);

        match store
            .append(&realm, &group, &[entry], StoreDelta::default())
            .await
        {
            Ok(()) => {
                self.finish_new_group(realm, group, configuration);
                Ok(Response::Ok { group, statement })
            }
            Err(store::AppendError::Grpc(_)) => Ok(Response::NoStore),
            Err(store::AppendError::MerkleWrites(_)) => unreachable!("no merkle writes"),
            Err(store::AppendError::LogPrecondition) => Ok(Response::StorePreconditionFailed),
            Err(store::AppendError::MerkleDeletes(_)) => unreachable!("no merkle deletes"),
        }
    }

    async fn handle_join_group(
        &self,
        request: JoinGroupRequest,
    ) -> Result<JoinGroupResponse, HandlerError> {
        type Response = JoinGroupResponse;
        type HsmResponse = hsm_api::JoinGroupResponse;

        let result = self
            .0
            .hsm
            .send(hsm_api::JoinGroupRequest {
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
            Ok(HsmResponse::TooManyGroups) => Ok(Response::TooManyGroups),
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
        type HsmResponse = hsm_api::BecomeLeaderResponse;

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
            .send(hsm_api::BecomeLeaderRequest {
                realm: request.realm,
                group: request.group,
                last_entry,
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::Ok { configuration }) => {
                self.start_leading(
                    request.realm,
                    request.group,
                    configuration,
                    last_entry_index,
                );
                Ok(Response::Ok)
            }
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::StepdownInProgress) => {
                info!(realm=?request.realm, group=?request.group, state=?self.0.state.lock().unwrap(), "didn't become leader because still stepping down");
                Ok(Response::StepdownInProgress)
            }
            Ok(HsmResponse::InvalidMac) => panic!(),
            Ok(HsmResponse::NotCaptured { have }) => Ok(Response::NotCaptured { have }),
        }
    }

    async fn handle_stepdown_as_leader(
        &self,
        request: StepDownRequest,
    ) -> Result<StepDownResponse, HandlerError> {
        type Response = StepDownResponse;
        type HsmResponse = hsm_api::StepDownResponse;

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
            .send(hsm_api::StepDownRequest {
                realm: request.realm,
                group: request.group,
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::Complete { last }) => {
                info!(group=?request.group, realm=?request.realm, "HSM Stepped down as leader");
                self.0.maybe_role_changed(
                    request.realm,
                    request.group,
                    hsm_api::GroupMemberRole::Witness,
                );
                Ok(Response::Ok { last })
            }
            Ok(HsmResponse::InProgress { last }) => {
                info!(group=?request.group, realm=?request.realm, index=?last, "HSM will stepdown as leader");
                self.0.maybe_role_changed(
                    request.realm,
                    request.group,
                    hsm_api::GroupMemberRole::SteppingDown,
                );
                Ok(Response::Ok { last })
            }
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::NotLeader(role)) => {
                self.0
                    .maybe_role_changed(request.realm, request.group, role);
                Ok(Response::NotLeader)
            }
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
        type HsmResponse = hsm_api::TransferOutResponse;
        let realm = request.realm;
        let source = request.source;

        let hsm = &self.0.hsm;
        let store = &self.0.store;

        // This loop handles retries if the read from the store is stale. It's
        // expected to run just once.
        //
        // TODO: put some retry limit on this
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

            // if we're splitting, then we need the proof for the split point.
            let proof = if partition.range == request.range {
                None
            } else {
                let rec_id = match partition.range.split_at(&request.range) {
                    Some(id) => id,
                    None => return Ok(Response::NotOwner),
                };
                match merkle::read(
                    &request.realm,
                    store,
                    &partition.range,
                    &partition.root_hash,
                    &rec_id,
                    &self.0.metrics,
                    &[tag!(?realm), tag!(group: "{source:?}")],
                )
                .await
                {
                    Ok(proof) => Some(proof),
                    Err(TreeStoreError::MissingNode) => todo!(),
                    Err(TreeStoreError::Network(e)) => {
                        warn!(error = ?e, "handle_transfer_out: error reading proof");
                        return Ok(Response::NoStore);
                    }
                }
            };

            return match hsm
                .send(hsm_api::TransferOutRequest {
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
                Ok(HsmResponse::MissingProof) => todo!(),
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
        type HsmResponse = hsm_api::TransferNonceResponse;

        match self
            .0
            .hsm
            .send(hsm_api::TransferNonceRequest {
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
        type HsmResponse = hsm_api::TransferStatementResponse;
        loop {
            return match self
                .0
                .hsm
                .send(hsm_api::TransferStatementRequest {
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
        type HsmResponse = hsm_api::TransferInResponse;

        let hsm = &self.0.hsm;
        let store = &self.0.store;
        let tags = [
            tag!(realm: "{:?}", request.realm),
            tag!(group: "{:?}", request.destination),
        ];

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

                    let transferring_in_proof_req = merkle::read_tree_side(
                        &request.realm,
                        store,
                        &request.transferring.range,
                        &request.transferring.root_hash,
                        proof_dir,
                        &tags,
                    );
                    let owned_range_proof_req = merkle::read_tree_side(
                        &request.realm,
                        store,
                        &partition.range,
                        &partition.root_hash,
                        proof_dir.opposite(),
                        &tags,
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
                .send(hsm_api::TransferInRequest {
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
                    // TODO: slow down and/or limit attempts
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
        type HsmResponse = hsm_api::CompleteTransferResponse;
        let hsm = &self.0.hsm;

        let result = hsm
            .send(hsm_api::CompleteTransferRequest {
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
        type HsmResponse = hsm_api::HandshakeResponse;

        match self
            .0
            .hsm
            .send(hsm_api::HandshakeRequest {
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
            Ok(HsmResponse::SessionError) => Ok(Response::SessionError),
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
        let tags = [tag!(?realm), tag!(?group)];
        let tenant_tag = tag!(tenant: "{}",request.tenant);
        let tenant = request.tenant.clone();
        let record_id = request.record_id.clone();

        let start_result = self
            .0
            .metrics
            .async_time("agent.start_app_request.time", &tags, || {
                self.start_app_request(request, &tags)
            })
            .await;

        match start_result {
            Err(response) => Ok(response),
            Ok((append_request, request_type)) => {
                let has_delta = !append_request.delta.is_empty();
                let res = self
                    .0
                    .metrics
                    .async_time("agent.commit.latency", &tags, || {
                        self.finish_app_request(realm, group, append_request)
                    })
                    .await;
                if res.is_ok() {
                    // This metric is used for tenant accounting. The metric
                    // name, tag names & values are aligned with what the
                    // software realm generates for accounting. Future tools
                    // that export this data from Datadog will be dependant on
                    // these being stable.
                    let req_type_name = match request_type {
                        AppRequestType::Register1 => "register1",
                        AppRequestType::Register2 => "register2",
                        AppRequestType::Recover1 => "recover1",
                        AppRequestType::Recover2 => "recover2",
                        AppRequestType::Recover3 => "recover3",
                        AppRequestType::Delete => "delete",
                    };
                    self.0.metrics.incr(
                        "realm.request.count",
                        [tag!(?realm), tenant_tag, tag!(type: "{}", req_type_name)],
                    );
                    if has_delta {
                        match request_type {
                            AppRequestType::Register2 => {
                                self.0
                                    .accountant
                                    .secret_registered(realm, tenant, record_id)
                                    .await
                            }
                            AppRequestType::Delete => {
                                self.0
                                    .accountant
                                    .secret_deleted(realm, tenant, record_id)
                                    .await
                            }
                            _ => {}
                        }
                    }
                }
                res
            }
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

        {
            let mut locked = self.0.state.lock().unwrap();
            match locked.leader.get_mut(&(realm, group)) {
                None => {
                    // Its possible for start_app_request to succeed, but to
                    // have subsequently lost leadership due to a background
                    // capture_next or commit operation.
                    return Ok(Response::NotLeader);
                }
                Some(leader) => {
                    leader
                        .response_channels
                        .insert(append_request.entry.entry_mac.clone().into(), sender);
                }
            }
        }

        self.append(realm, group, append_request);
        match receiver.await {
            Ok(response) => Ok(Response::Ok(response)),
            Err(oneshot::Canceled) => Ok(Response::NotLeader),
        }
    }

    #[instrument(level = "trace")]
    async fn start_app_request(
        &self,
        request: AppRequest,
        tags: &[metrics::Tag],
    ) -> Result<(Append, AppRequestType), AppResponse> {
        type HsmResponse = hsm_api::AppResponse;
        type Response = AppResponse;

        for attempt in 0..100 {
            let cached_entry: Option<LogEntry> = {
                let mut locked = self.0.state.lock().unwrap();
                let Some(leader) = locked.leader.get_mut(&(request.realm, request.group)) else {
                    return Err(Response::NotLeader);
                };
                leader.last_appended.clone()
            };

            let entry: LogEntry = match cached_entry {
                Some(entry) => entry,
                None => match self
                    .0
                    .store
                    .read_last_log_entry(&request.realm, &request.group)
                    .await
                {
                    Err(_) => return Err(Response::NoStore),
                    Ok(Some(entry)) => entry,
                    Ok(None) => return Err(Response::InvalidGroup),
                },
            };

            let Some(partition) = entry.partition else {
                return Err(Response::NotLeader); // TODO: is that the right error?
            };

            let proof = match merkle::read(
                &request.realm,
                &self.0.store,
                &partition.range,
                &partition.root_hash,
                &request.record_id,
                &self.0.metrics,
                tags,
            )
            .await
            {
                Ok(proof) => proof,
                Err(TreeStoreError::MissingNode) => {
                    warn!(
                        agent = self.0.name,
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

            match self
                .0
                .hsm
                .send(hsm_api::AppRequest {
                    realm: request.realm,
                    group: request.group,
                    record_id: request.record_id.clone(),
                    session_id: request.session_id,
                    encrypted: request.encrypted.clone(),
                    proof,
                    index: entry.index,
                })
                .await
            {
                Err(_) => return Err(Response::NoHsm),
                Ok(HsmResponse::InvalidRealm) => return Err(Response::InvalidRealm),
                Ok(HsmResponse::InvalidGroup) => return Err(Response::InvalidGroup),
                Ok(HsmResponse::StaleProof) => {
                    warn!(
                        agent = self.0.name,
                        attempt, index = ?entry.index,
                        "stale proof, retrying"
                    );
                    continue;
                }
                Ok(HsmResponse::NotLeader(role)) => {
                    self.0
                        .maybe_role_changed(request.realm, request.group, role);
                    return Err(Response::NotLeader);
                }
                Ok(HsmResponse::NotOwner) => return Err(Response::NotLeader),
                Ok(HsmResponse::InvalidProof) => return Err(Response::InvalidProof),
                // TODO, is this right? if we can't decrypt the leaf, then the proof is likely bogus.
                Ok(HsmResponse::InvalidRecordData) => return Err(Response::InvalidProof),
                Ok(HsmResponse::MissingSession) => return Err(Response::MissingSession),
                Ok(HsmResponse::SessionError) => return Err(Response::SessionError),
                Ok(HsmResponse::DecodingError) => return Err(Response::DecodingError),

                Ok(HsmResponse::Ok {
                    entry,
                    delta,
                    request_type,
                }) => {
                    trace!(
                        agent = self.0.name,
                        ?entry,
                        ?delta,
                        "got new log entry and data updates from HSM"
                    );
                    return Ok((Append { entry, delta }, request_type));
                }
            };
        }
        panic!("too slow to make progress");
    }
}

impl<T> AgentInner<T> {
    fn maybe_role_changed(&self, realm: RealmId, group: GroupId, role: hsm_api::GroupMemberRole) {
        // If we've transitioned to witness from leader/stepdown we need to cleanup our leader state.
        if role == hsm_api::GroupMemberRole::Witness
            && self
                .state
                .lock()
                .unwrap()
                .leader
                .remove(&(realm, group))
                .is_some()
        {
            info!(?realm, ?group, "HSM transitioned to Witness");
        }
    }
}
