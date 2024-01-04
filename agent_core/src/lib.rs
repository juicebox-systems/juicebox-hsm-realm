use anyhow::Context;
use bytes::Bytes;
use futures::channel::oneshot;
use futures::future::join_all;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use observability::tracing::TracingMiddleware;
use serde_json::json;
use service_core::http::ReqwestClientMetrics;
use std::cmp::Ordering;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::fmt::Arguments;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, instrument, span, trace, warn, Instrument, Level, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use url::Url;

mod append;
mod commit;
pub mod hsm;
pub mod merkle;
pub mod service;
mod tenants;

use agent_api::merkle::TreeStoreError;
use agent_api::{
    AppRequest, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse, CompleteTransferRequest,
    CompleteTransferResponse, HashedUserId, JoinGroupRequest, JoinGroupResponse, JoinRealmRequest,
    JoinRealmResponse, NewGroupRequest, NewGroupResponse, NewRealmRequest, NewRealmResponse,
    ReadCapturedRequest, ReadCapturedResponse, StatusRequest, StatusResponse, StepDownRequest,
    StepDownResponse, TransferInRequest, TransferInResponse, TransferNonceRequest,
    TransferNonceResponse, TransferOutRequest, TransferOutResponse, TransferStatementRequest,
    TransferStatementResponse,
};
use append::{Append, AppendingState};
use build_info::BuildInfo;
use cluster_core::discover_hsm_ids;
use hsm::{HsmClient, Transport};
use hsm_api::merkle::{Dir, StoreDelta};
use hsm_api::{
    AppResultType, CaptureJumpRequest, CaptureJumpResponse, CaptureNextRequest,
    CaptureNextResponse, Captured, EntryMac, GroupId, GroupMemberRole, HsmId, LogEntry, LogIndex,
    TransferInProofs,
};
use juicebox_networking::reqwest::ClientOptions;
use juicebox_networking::rpc::{self, Rpc, SendOptions};
use juicebox_realm_api::requests::{ClientRequestKind, NoiseRequest, NoiseResponse};
use juicebox_realm_api::types::RealmId;
use observability::logging::TracingSource;
use observability::metrics::{self};
use observability::metrics_tag as tag;
use pubsub_api::{Message, Publisher};
use service_core::rpc::{handle_rpc, HandlerError};
use store::{
    self, discovery, LogEntriesIter, LogEntriesIterError, LogRow, ReadLastLogEntryError,
    ServiceKind,
};
use tenants::UserAccountingWriter;

#[derive(Debug)]
pub struct Agent<T>(Arc<AgentInner<T>>);

#[derive(Debug)]
struct AgentInner<T> {
    name: String,
    build_info: BuildInfo,
    boot_time: Instant,
    hsm: HsmClient<T>,
    store: store::StoreClient,
    store_admin: store::StoreAdminClient,
    peer_client: ReqwestClientMetrics,
    state: Mutex<State>,
    metrics: metrics::Client,
    accountant: UserAccountingWriter,
    event_publisher: Box<dyn Publisher>,
}

#[derive(Debug)]
struct State {
    /// State about a group that's needed while the HSM is Leader or SteppingDown.
    leader: HashMap<(RealmId, GroupId), LeaderState>,
    /// Captures that have been persisted to NVRAM in the HSM.
    captures: Vec<Captured>,
    /// Set after being successfully registered with service discovery.
    registered: bool,
    /// The local HSM's ID is available before the agent is registered with
    /// service discovery. It's always available for leaders. It will never go
    /// from `Some` to `None`.
    hsm_id: Option<HsmId>,
}

// State about a group that is used in the Leader or SteppingDown state.
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

    /// The rows that eventually need to be compacted in the log.
    ///
    /// Any time this is modified, use [`commit::UncompactedRowStats`] to
    /// report metrics.
    ///
    /// The rows are sorted in increasing index order and unique.
    ///
    /// As the leader appends new rows of entries to the log, it pushes to the
    /// back of this. After the leader commits entries, the compactor task pops
    /// from the front of this and overwrites rows with tombstones.
    ///
    /// Upon becoming leader, this will be empty. Before it compacts anything,
    /// the compactor task reads from the log and prepends all previously
    /// existing log entry rows and possibly some tombstone rows. (Those
    /// tombstone rows are tracked here to maintain a store invariant that only
    /// a fixed window of the log may mix tombstones and log entries.)
    uncompacted_rows: VecDeque<LogRow>,

    /// Used to route responses back to the right client after the HSM commits
    /// a batch of log entries and releases the responses.
    response_channels: HashMap<HashableEntryMac, oneshot::Sender<(NoiseResponse, AppResultType)>>,
}

impl std::fmt::Debug for LeaderState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaderState")
            .field("append_queue", &self.append_queue.len())
            .field("appending", &self.appending)
            .field("last_appended", &self.last_appended)
            .field("uncompacted_rows", &self.uncompacted_rows.len())
            .field("response_channels", &self.response_channels.len())
            .finish()
    }
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

/// Error type returned by [`Agent::watch_log_one`].
#[derive(Debug)]
enum WatchingError {
    Compacted(LogIndex),
}

impl<T> Clone for Agent<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Transport + 'static> Agent<T> {
    pub fn new(
        name: String,
        build_info: BuildInfo,
        hsm: HsmClient<T>,
        store: store::StoreClient,
        store_admin: store::StoreAdminClient,
        event_publisher: Box<dyn Publisher>,
        metrics: metrics::Client,
    ) -> Self {
        Self(Arc::new(AgentInner {
            name,
            build_info,
            boot_time: Instant::now(),
            hsm,
            store: store.clone(),
            store_admin,
            peer_client: ReqwestClientMetrics::new(metrics.clone(), ClientOptions::default()),
            state: Mutex::new(State {
                leader: HashMap::new(),
                captures: Vec::new(),
                registered: false,
                hsm_id: None,
            }),
            metrics: metrics.clone(),
            accountant: UserAccountingWriter::new(store, metrics),
            event_publisher,
        }))
    }

    /// Called at service startup, start watching for any groups that the HSM is already a member of.
    async fn restart_watching(&self) {
        loop {
            match self.0.hsm.send(hsm_api::StatusRequest {}).await {
                Err(err) => {
                    warn!(?err, "failed to get HSM status, log watching delayed");
                    sleep(Duration::from_secs(1)).await
                }
                Ok(sr) => {
                    if let Some(realm) = sr.realm {
                        for g in realm.groups {
                            let idx = match g.captured {
                                Some((index, _)) => index.next(),
                                None => LogIndex::FIRST,
                            };
                            self.start_watching(realm.id, g.id, g.configuration, idx);
                        }
                    }
                    return;
                }
            }
        }
    }

    fn start_watching(
        &self,
        realm: RealmId,
        group: GroupId,
        configuration: Vec<HsmId>,
        next_index: LogIndex,
    ) {
        tokio::spawn(
            self.clone()
                .watching_main(realm, group, configuration, next_index),
        );
    }

    async fn watching_main(
        self,
        realm: RealmId,
        group: GroupId,
        configuration: Vec<HsmId>,
        mut next_index: LogIndex,
    ) {
        let cx = opentelemetry::Context::new().with_value(TracingSource::BackgroundJob);
        loop {
            info!(
                agent = self.0.name,
                ?realm,
                ?group,
                ?next_index,
                "start watching log"
            );
            let mut it = self.0.store.read_log_entries_iter(
                realm,
                group,
                next_index,
                (Self::MAX_APPEND_BATCH_SIZE * 2).try_into().unwrap(),
            );

            next_index = loop {
                let span = span!(Level::TRACE, "log_watcher_loop");
                span.set_parent(cx.clone());

                match self
                    .watch_log_one(&mut it, realm, group)
                    .instrument(span.clone())
                    .await
                {
                    Ok(()) => {}
                    Err(WatchingError::Compacted(index)) => {
                        break self
                            .catchup(realm, group, &configuration, index)
                            .instrument(span)
                            .await
                            .next();
                    }
                }
            };
        }
    }

    /// Reads the next batch of log entries from the store and sends them to
    /// the HSM.
    #[instrument(
        level = "trace",
        skip(self, it),
        fields(num_log_entries_read, num_captured, index)
    )]
    async fn watch_log_one(
        &self,
        it: &mut LogEntriesIter,
        realm: RealmId,
        group: GroupId,
    ) -> Result<(), WatchingError> {
        match it.next().await {
            Err(LogEntriesIterError::Grpc(err)) => {
                warn!(?err, "error reading log");
                sleep(Duration::from_millis(25)).await;
                Ok(())
            }
            Err(ref err @ LogEntriesIterError::Compacted(index)) => {
                warn!(?err, ?index, "fell behind on watching log");
                Err(WatchingError::Compacted(index))
            }
            Ok(entries) if entries.is_empty() => {
                sleep(Duration::from_millis(1)).await;
                Ok(())
            }
            Ok(entries) => {
                let span = Span::current();
                let num_entries = entries.len();
                span.record("num_log_entries_read", num_entries);
                span.record("index", entries[0].index.0);

                match self
                    .0
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
                        self.0.maybe_role_changed(realm, group, role);
                        Ok(())
                    }
                    Ok(r) => todo!("{r:#?}"),
                }
            }
        }
    }

    /// Called when the log watcher task encounters a tombstone or gap in the
    /// log. It queries peers for updated `CapturedStatements` and adopts them.
    async fn catchup(
        &self,
        realm: RealmId,
        group: GroupId,
        configuration: &[HsmId],
        past: LogIndex,
    ) -> LogIndex {
        let local_hsm_id: Option<HsmId> = self.0.state.lock().unwrap().hsm_id;

        loop {
            // TODO: There's some code duplication between this and the commit
            // path.
            let urls: Vec<Url> = match discover_hsm_ids(&self.0.store, &self.0.peer_client).await {
                Ok(it) => it
                    .filter(|(hsm, _)| Some(hsm) != local_hsm_id.as_ref())
                    .filter(|(hsm, _)| configuration.contains(hsm))
                    .map(|(_, url)| url)
                    .collect(),
                Err(err) => {
                    warn!(?err, "failed to discover peer agents to catch up from");
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            let captures = join_all(urls.iter().map(|url| {
                rpc::send_with_options(
                    &self.0.peer_client,
                    url,
                    ReadCapturedRequest { realm, group },
                    SendOptions::default().with_timeout(Duration::from_millis(500)),
                )
            }))
            .await
            .into_iter()
            // skip network failures
            .filter_map(|r| r.ok())
            .filter_map(|r| match r {
                ReadCapturedResponse::Ok(captured) => captured,
            })
            .filter(|captured| captured.index > past);

            let Some(jump) = captures.max_by_key(|captured| captured.index) else {
                warn!("no peer agent returned usable capture to jump forward to");
                sleep(Duration::from_millis(500)).await;
                continue;
            };

            let jump_index = jump.index;
            match self.0.hsm.send(CaptureJumpRequest { jump }).await {
                Err(err) => todo!("{err:?}"),
                Ok(CaptureJumpResponse::Ok) => return jump_index,
                Ok(CaptureJumpResponse::NotWitness(role)) => {
                    // We don't expect to get here because:
                    // - As a leader, we don't compact entries that beyond our
                    //   own captured index.
                    // - A new leader will wait until all its peers are
                    //   reporting a Witness role or enough time has passed
                    //   before starting to compact entries.
                    //
                    // If the stepdown succeeds, the next iteration should be
                    // able to do the CaptureJump. If it somehow fails, we'll
                    // end up back here and retry.
                    warn!(
                        ?role,
                        "CaptureJump got NotWitness response, which shouldn't \
                        normally happen. Forcing HSM to step down."
                    );
                    self.force_stepdown(realm, group).await;
                    continue;
                }
                Ok(r) => todo!("{r:#?}"),
            };
        }
    }

    async fn force_stepdown(&self, realm: RealmId, group: GroupId) {
        match self
            .0
            .hsm
            .send(hsm_api::StepDownRequest {
                realm,
                group,
                force: true,
            })
            .await
        {
            Err(err) => todo!("{err:?}"),
            Ok(hsm_api::StepDownResponse::Complete { .. }) => {
                self.0
                    .maybe_role_changed(realm, group, GroupMemberRole::Witness);
            }
            Ok(hsm_api::StepDownResponse::NotLeader(role)) => {
                self.0.maybe_role_changed(realm, group, role);
            }
            Ok(r) => todo!("{r:?}"),
        }
    }

    // Routinely looks for the agent/hsm being out of sync WRT to leadership and
    // panics if so.
    async fn watchdog(&self) {
        let mut suspect_counts: HashMap<GroupId, isize> = HashMap::new();
        loop {
            match self.0.hsm.send(hsm_api::StatusRequest {}).await {
                Err(err) => {
                    warn!(?err, "failed to get status from HSM");
                }
                Ok(hsm_status) => {
                    if let Some(hsm_realm_status) = hsm_status.realm {
                        let realm = hsm_realm_status.id;
                        let agent_state = self.0.state.lock().unwrap();
                        for hsm_group_status in hsm_realm_status.groups {
                            let group = hsm_group_status.id;
                            // During new_realm & new_group we can be in this
                            // state for a while as the agent leader state isn't
                            // set until its finished creating the bigtable
                            // tables and has appended the first log entry &
                            // merkle tree nodes. The check on the captured
                            // index stops us from treating that as a bad state.
                            let is_suspect = hsm_group_status.role == GroupMemberRole::Leader
                                && hsm_group_status
                                    .captured
                                    .is_some_and(|(index, _)| index > LogIndex::FIRST)
                                && !agent_state.leader.contains_key(&(realm, group));
                            if is_suspect {
                                let count = suspect_counts.entry(group).or_default();
                                *count += 1;
                                warn!(
                                    ?group,
                                    check_count = count,
                                    "group in suspect state (hsm is leader, agent is not)"
                                );
                                if *count >= 5 {
                                    self.0.metrics.event(
                                        "Agent watchdog triggered",
                                        "group in suspect state (hsm is leader, agent is not)",
                                        [tag!(?realm), tag!(?group)],
                                    );
                                    panic!(
                                        "group {group:?} in suspect state (hsm is leader, agent is not)"
                                    )
                                }
                            } else {
                                suspect_counts.remove(&hsm_group_status.id);
                            }
                        }
                    };
                }
            }
            debug!(?suspect_counts, "agent/hsm leadership state suspects");
            tokio::time::sleep(Duration::from_secs(1)).await;
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
        let wd = self.clone();
        tokio::spawn(async move { wd.watchdog().await });

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
                                    .serve_connection(stream, TracingMiddleware::new(agent.clone()))
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

        // If there's a cluster manager available via service discovery, ask
        // that to perform the step down. The cluster manager can handle the
        // hand-off such that clients don't see an availability gap. If there
        // isn't one we'll step down gracefully but there may be an availability
        // gap until a new leader is appointed.
        let maybe_hsm_id: Option<HsmId> = {
            let locked = self.0.state.lock().unwrap();
            locked.hsm_id
        };
        if let Some(hsm_id) = maybe_hsm_id {
            info!(
                ?hsm_id,
                "Starting graceful agent shutdown with cluster manager"
            );
            self.stepdown_with_cluster_manager(hsm_id).await;
        } else {
            info!("Starting graceful agent shutdown without cluster manager");
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
                let mc =
                    ReqwestClientMetrics::new(self.0.metrics.clone(), ClientOptions::default());
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
            agent.state.lock().unwrap().hsm_id = Some(hsm_id);

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

    fn call(&mut self, request: Request<IncomingBody>) -> Self::Future {
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
        if let Ok(hsm_status) = &hsm_status {
            // The ID is cached before service discovery registration, but we
            // set it here too in case others call this before that happens.
            self.0.state.lock().unwrap().hsm_id = Some(hsm_status.id);
        }
        Ok(StatusResponse {
            hsm: hsm_status.ok(),
            uptime: self.0.boot_time.elapsed(),
        })
    }

    async fn handle_livez(&self, _request: Request<IncomingBody>) -> Response<Full<Bytes>> {
        let unavailable_response = |message: Arguments| -> Response<Full<Bytes>> {
            Response::builder()
                .status(http::StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::from(Bytes::from(format!(
                    "{}\n{}",
                    message,
                    self.0.build_info.livez()
                ))))
                .unwrap()
        };

        {
            let locked = self.0.state.lock().unwrap();
            if !locked.registered || locked.hsm_id.is_none() {
                // The HSM ID is cached before registration, so the message
                // only mentions service discovery.
                return unavailable_response(format_args!(
                    "not yet registered with service discovery"
                ));
            }
        }

        // Note: As this is a liveness check, we want to send a real
        // StatusRequest and not use the cached local HSM ID.
        match tokio::time::timeout(
            Duration::from_secs(1),
            self.0.hsm.send(hsm_api::StatusRequest {}),
        )
        .await
        {
            Ok(Ok(status)) => Response::builder()
                .status(http::StatusCode::OK)
                .body(Full::from(Bytes::from(format!(
                    "hsm id: {:?}\n{}",
                    status.id,
                    self.0.build_info.livez()
                ))))
                .unwrap(),

            Ok(Err(transport_error)) => {
                unavailable_response(format_args!("error: {transport_error:?}"))
            }

            Err(elapsed) => unavailable_response(format_args!("timeout: {elapsed:?}")),
        }
    }

    async fn handle_new_realm(
        &self,
        _request: NewRealmRequest,
    ) -> Result<NewRealmResponse, HandlerError> {
        type Response = NewRealmResponse;
        let name = &self.0.name;

        let Some(hsm_id) = self.0.state.lock().unwrap().hsm_id else {
            return Ok(Response::NoHsm);
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
            .unwrap_or_else(|err| {
                panic!("failed to create Bigtable tables for new realm ({realm:?}): {err}")
            });

        info!(
            agent = name,
            ?realm,
            ?group,
            "appending log entry for new realm"
        );
        assert_eq!(entry.index, LogIndex::FIRST);

        match self.0.store.append(&realm, &group, &[entry], delta).await {
            Ok(_row) => {
                self.finish_new_group(realm, group, vec![hsm_id]);
                Ok(Response::Ok { realm, group })
            }
            Err(store::AppendError::Grpc(_)) => Ok(Response::NoStore),
            Err(err @ store::AppendError::MerkleWrites(_)) => todo!("{err:?}"),
            Err(store::AppendError::LogPrecondition) => Ok(Response::StorePreconditionFailed),
            Err(store::AppendError::MerkleDeletes(_)) => {
                unreachable!("no merkle nodes to delete")
            }
        }
    }

    fn finish_new_group(&self, realm: RealmId, group: GroupId, config: Vec<HsmId>) {
        self.start_watching(realm, group, config.clone(), LogIndex::FIRST);
        self.start_leading(realm, group, config, LogIndex::FIRST.next());
    }

    fn start_leading(
        &self,
        realm: RealmId,
        group: GroupId,
        config: Vec<HsmId>,
        starting_index: LogIndex,
    ) {
        // The HSM will return Ok to become_leader if it's already leader.
        // When we get here we might already be leading.
        let start = {
            let mut locked = self.0.state.lock().unwrap();

            // All paths into this function make sure we know the HSM ID first.
            // This is useful so that any leadership-related code can safely
            // unwrap the ID.
            assert!(locked.hsm_id.is_some());

            if let Entry::Vacant(entry) = locked.leader.entry((realm, group)) {
                entry.insert(LeaderState {
                    append_queue: HashMap::new(),
                    appending: AppendingState::NotAppending {
                        next: starting_index,
                    },
                    last_appended: None,
                    uncompacted_rows: VecDeque::new(),
                    response_channels: HashMap::new(),
                });
                true
            } else {
                false
            }
        };
        if start {
            info!(name=?self.0.name, ?realm, ?group, "Starting group committer");
            tokio::spawn(
                self.clone()
                    .group_committer(realm, group, config, starting_index),
            );
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
        let realm = request.realm;

        if self.0.state.lock().unwrap().hsm_id.is_none() {
            // The HSM should be up by now, and we don't want to start
            // leadership without knowing its ID.
            return Ok(Response::NoHsm);
        }

        let configuration: Vec<HsmId> = request.members.iter().map(|(id, _)| *id).collect();

        let (group, statement, entry) = match self
            .0
            .hsm
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
            agent = self.0.name,
            ?realm,
            ?group,
            "appending log entry for new group"
        );
        assert_eq!(entry.index, LogIndex::FIRST);

        match self
            .0
            .store
            .append(&realm, &group, &[entry], StoreDelta::default())
            .await
        {
            Ok(_row) => {
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
                configuration: request.configuration.clone(),
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
                self.start_watching(
                    request.realm,
                    request.group,
                    request.configuration,
                    LogIndex::FIRST,
                );
                Ok(Response::Ok)
            }
        }
    }

    async fn handle_become_leader(
        &self,
        request: BecomeLeaderRequest,
    ) -> Result<BecomeLeaderResponse, HandlerError> {
        info!(
            realm=?request.realm,
            group=?request.group,
            last=?request.last,
            "requested to become leader",
        );
        match timeout(
            Duration::from_secs(5),
            self.handle_become_leader_inner(&request),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => {
                warn!(
                    realm=?request.realm,
                    group=?request.group,
                    last=?request.last,
                    "timeout trying to become leader",
                );
                Ok(BecomeLeaderResponse::Timeout)
            }
        }
    }

    async fn handle_become_leader_inner(
        &self,
        request: &BecomeLeaderRequest,
    ) -> Result<BecomeLeaderResponse, HandlerError> {
        type Response = BecomeLeaderResponse;
        type HsmResponse = hsm_api::BecomeLeaderResponse;

        let hsm = &self.0.hsm;
        let store = &self.0.store;

        if self.0.state.lock().unwrap().hsm_id.is_none() {
            // The HSM should be up by now, and we don't want to start
            // leadership without knowing its ID.
            return Ok(Response::NoHsm);
        }

        let last_entry: LogEntry = loop {
            let entry = match store
                .read_last_log_entry(&request.realm, &request.group)
                .await
            {
                Ok(entry) => entry,
                Err(ReadLastLogEntryError::EmptyLog) => {
                    panic!(
                        "store says log is empty for realm {:?} group {:?}",
                        request.realm, request.group
                    );
                }
                Err(ReadLastLogEntryError::Grpc(err)) => {
                    warn!(?err, "failed to read last log entry from store");
                    return Ok(Response::NoStore);
                }
            };

            break match request.last {
                None => entry,

                // If the cluster manager is doing a coordinated leadership
                // handoff, it knows what the last log index of the stepping
                // down leader owned.
                Some(expected) => match entry.index.cmp(&expected) {
                    Ordering::Less => {
                        // The last leader probably hasn't quite written the
                        // entry to the store yet. Wait for it.
                        sleep(Duration::from_millis(2)).await;
                        continue;
                    }
                    Ordering::Equal => entry,
                    Ordering::Greater => {
                        // The log is beyond this point, so a new leader
                        // starting here would be unable to append anything.
                        warn!(
                            found = %entry.index,
                            %expected,
                            "found log entry beyond BecomeLeaderRequest index",
                        );
                        return Ok(Response::StaleIndex);
                    }
                },
            };
        };

        let last_entry_index = last_entry.index;
        info!(
            index=?last_entry_index,
            "read log entry, asking HSM to become leader"
        );

        loop {
            match hsm
                .send(hsm_api::BecomeLeaderRequest {
                    realm: request.realm,
                    group: request.group,
                    last_entry: last_entry.clone(),
                })
                .await
            {
                Err(_) => return Ok(Response::NoHsm),
                Ok(HsmResponse::Ok { configuration }) => {
                    self.start_leading(
                        request.realm,
                        request.group,
                        configuration,
                        last_entry_index.next(),
                    );
                    return Ok(Response::Ok);
                }
                Ok(HsmResponse::InvalidRealm) => return Ok(Response::InvalidRealm),
                Ok(HsmResponse::InvalidGroup) => return Ok(Response::InvalidGroup),
                Ok(HsmResponse::StepdownInProgress) => {
                    info!(
                        realm=?request.realm,
                        group=?request.group,
                        state=?self.0.state.lock().unwrap(),
                        "didn't become leader because still stepping down",
                    );
                    return Ok(Response::StepdownInProgress);
                }
                Ok(HsmResponse::InvalidMac) => panic!(),
                Ok(HsmResponse::NotCaptured { have }) => match have {
                    // On an active group it's possible that the index that the
                    // HSM has captured up to is behind the log entry we just
                    // read. Wait around a little to let it catch up.
                    // Particularly for cluster rebalance operations, it's
                    // better to wait slightly here so that the selected agent
                    // becomes leader, rather then ending up trying to undo the
                    // leadership move.
                    Some(have_idx)
                        if LogIndex(have_idx.0.saturating_add(1000)) >= last_entry_index =>
                    {
                        // Its close, give it chance to catch up.
                        sleep(Duration::from_millis(5)).await;
                    }
                    Some(_) | None => return Ok(Response::NotCaptured { have }),
                },
            }
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
                force: false,
            })
            .await
        {
            Err(_) => Ok(Response::NoHsm),
            Ok(HsmResponse::Complete { last }) => {
                info!(
                    group=?request.group,
                    realm=?request.realm,
                    "HSM stepped down as leader",
                );
                self.0.maybe_role_changed(
                    request.realm,
                    request.group,
                    hsm_api::GroupMemberRole::Witness,
                );
                Ok(Response::Ok { last })
            }
            Ok(HsmResponse::InProgress { last }) => {
                info!(
                    group=?request.group,
                    realm=?request.realm,
                    index=?last,
                    "HSM will step down as leader"
                );
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

    #[instrument(level = "trace")]
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
                Ok(entry) => entry,
                Err(err @ ReadLastLogEntryError::EmptyLog) => todo!("{err}"),
                Err(ReadLastLogEntryError::Grpc(_)) => return Ok(Response::NoStore),
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
                    &[tag!(?realm), tag!("group": ?source)],
                )
                .await
                {
                    Ok(proof) => Some(proof),
                    Err(err @ TreeStoreError::MissingNode) => todo!("{err:?}"),
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
                Ok(r @ HsmResponse::StaleIndex) => todo!("{r:?}"),
                Ok(r @ HsmResponse::MissingProof) => todo!("{r:?}"),
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
            tag!("realm": ?request.realm),
            tag!("group": ?request.destination),
        ];

        // This loop handles retries if the read from the store is stale. It's
        // expected to run just once.
        loop {
            let entry = match store
                .read_last_log_entry(&request.realm, &request.destination)
                .await
            {
                Ok(entry) => entry,
                Err(err @ ReadLastLogEntryError::EmptyLog) => todo!("{err}"),
                Err(ReadLastLogEntryError::Grpc(_)) => return Ok(Response::NoStore),
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
                        Err(err @ TreeStoreError::MissingNode) => todo!("{err:?}"),
                        Ok(proof) => proof,
                    };
                    let owned_range_proof = match owned_range_proof_req.await {
                        Err(TreeStoreError::Network(_)) => return Ok(Response::NoStore),
                        Err(err @ TreeStoreError::MissingNode) => todo!("{err:?}"),
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
                Ok(r @ HsmResponse::InvalidProof) => todo!("{r:?}"),
                Ok(r @ HsmResponse::MissingProofs) => todo!("{r:?}"),
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
        let tenant_tag = tag!("tenant": request.tenant);
        let tenant = request.tenant.clone();
        let user = request.user.clone();
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
            Ok(append_request) => {
                let has_delta = !append_request.delta.is_empty();
                let (app_response, request_type) = self
                    .0
                    .metrics
                    .async_time("agent.commit.latency", &tags, || {
                        self.finish_app_request(realm, group, append_request)
                    })
                    .await?;

                if let Some(request_type) = &request_type {
                    if let Some(msg) = create_tenant_event_msg(request_type, &user) {
                        if let Err(err) = self.0.event_publisher.publish(realm, &tenant, msg).await
                        {
                            warn!(?err, "error publishing event");
                            return Ok(AppResponse::NoPubSub);
                        }
                    }

                    // This metric is used for tenant accounting. The metric
                    // name, tag names & values are aligned with what the
                    // software realm generates for accounting. Future tools
                    // that export this data from Datadog will be dependant on
                    // these being stable.
                    let req_type_name = match request_type {
                        AppResultType::Register1 => "register1",
                        AppResultType::Register2 => "register2",
                        AppResultType::Recover1 => "recover1",
                        AppResultType::Recover2 { .. } => "recover2",
                        AppResultType::Recover3 { .. } => "recover3",
                        AppResultType::Delete => "delete",
                    };
                    self.0.metrics.incr(
                        "realm.request.count",
                        [tag!(?realm), tenant_tag, tag!("type": req_type_name)],
                    );
                    if has_delta {
                        match request_type {
                            AppResultType::Register2 => {
                                self.0
                                    .accountant
                                    .secret_registered(realm, tenant, record_id)
                                    .await
                            }
                            AppResultType::Delete => {
                                self.0
                                    .accountant
                                    .secret_deleted(realm, tenant, record_id)
                                    .await
                            }
                            _ => {}
                        }
                    }
                }
                Ok(app_response)
            }
        }
    }

    #[instrument(level = "trace", skip(self, append_request))]
    async fn finish_app_request(
        &self,
        realm: RealmId,
        group: GroupId,
        append_request: Append,
    ) -> Result<(AppResponse, Option<AppResultType>), HandlerError> {
        type Response = AppResponse;

        let (sender, receiver) = oneshot::channel::<(NoiseResponse, AppResultType)>();

        {
            let mut locked = self.0.state.lock().unwrap();
            match locked.leader.get_mut(&(realm, group)) {
                None => {
                    // Its possible for start_app_request to succeed, but to
                    // have subsequently lost leadership due to a background
                    // capture_next or commit operation.
                    return Ok((Response::NotLeader, None));
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
            Ok((response, res_type)) => Ok((Response::Ok(response), Some(res_type))),
            Err(oneshot::Canceled) => Ok((Response::NotLeader, None)),
        }
    }

    #[instrument(level = "trace", skip(self))]
    async fn start_app_request(
        &self,
        request: AppRequest,
        tags: &[metrics::Tag],
    ) -> Result<Append, AppResponse> {
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
                    Ok(entry) => entry,
                    Err(ReadLastLogEntryError::Grpc(_)) => return Err(Response::NoStore),
                    Err(ReadLastLogEntryError::EmptyLog) => return Err(Response::InvalidGroup),
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

                Ok(HsmResponse::Ok { entry, delta }) => {
                    trace!(
                        agent = self.0.name,
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

fn create_tenant_event_msg(r: &AppResultType, u: &HashedUserId) -> Option<Message> {
    match r {
        AppResultType::Register1 => None,
        AppResultType::Register2 => Some(json!({
            "user":u.to_string(),
            "event":"registered"
        })),
        AppResultType::Recover1 => None,
        AppResultType::Recover2 { updated: None } => None,
        AppResultType::Recover2 { updated: Some(g) } => Some(json!({
            "user":u.to_string(),
            "event":"guess_used",
            "num_guesses":g.num_guesses,
            "guess_count":g.guess_count
        })),
        AppResultType::Recover3 { recovered: true } => Some(json!({
            "user":u.to_string(),
            "event":"share_recovered"
        })),
        AppResultType::Recover3 { recovered: false } => None,
        AppResultType::Delete => Some(json!({
            "user":u.to_string(),
            "event":"deleted"
        })),
    }
    .map(Message)
}

#[cfg(test)]
mod tests {
    use super::create_tenant_event_msg;
    use agent_api::HashedUserId;
    use hsm_api::{AppResultType, GuessState};
    use pubsub_api::Message;
    use serde_json::json;

    #[test]
    fn create_tenant_event_messages() {
        let user = HashedUserId::new("test", "121314");

        assert!(create_tenant_event_msg(&AppResultType::Register1, &user).is_none());
        assert!(create_tenant_event_msg(&AppResultType::Recover1, &user).is_none());
        assert!(
            create_tenant_event_msg(&AppResultType::Recover2 { updated: None }, &user).is_none()
        );
        assert!(
            create_tenant_event_msg(&AppResultType::Recover3 { recovered: false }, &user).is_none()
        );

        let m = create_tenant_event_msg(&AppResultType::Register2, &user);
        assert_eq!(
            Some(Message(
                json!({"event":"registered","user":"447ddec5f08c757d40e7acb9f1bc10ed44a960683bb991f5e4ed17498f786ff8"})
            )),
            m
        );

        let m = create_tenant_event_msg(
            &AppResultType::Recover2 {
                updated: Some(GuessState {
                    num_guesses: 42,
                    guess_count: 4,
                }),
            },
            &user,
        );
        assert_eq!(
            Some(Message(
                json!({"event":"guess_used","num_guesses":42,"guess_count":4,"user":"447ddec5f08c757d40e7acb9f1bc10ed44a960683bb991f5e4ed17498f786ff8"})
            )),
            m
        );

        let m = create_tenant_event_msg(&AppResultType::Recover3 { recovered: true }, &user);
        assert_eq!(
            Some(Message(
                json!({"event":"share_recovered","user":"447ddec5f08c757d40e7acb9f1bc10ed44a960683bb991f5e4ed17498f786ff8"})
            )),
            m
        );

        let m = create_tenant_event_msg(&AppResultType::Delete, &user);
        assert_eq!(
            Some(Message(
                json!({"event":"deleted","user":"447ddec5f08c757d40e7acb9f1bc10ed44a960683bb991f5e4ed17498f786ff8"})
            )),
            m
        );
    }
}
