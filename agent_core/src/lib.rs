use anyhow::Context;
use bytes::Bytes;
use futures::channel::oneshot;
use futures::future::join_all;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::cmp::Ordering;
use std::collections::{HashMap, VecDeque};
use std::fmt::Arguments;
use std::future::Future;
use std::mem;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::{sleep, sleep_until};
use tracing::{debug, info, instrument, span, trace, warn, Instrument, Level, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

mod append;
mod commit;
pub mod hsm;
pub mod merkle;
mod peers;
mod rate;
pub mod service;
mod tenants;
mod transfer;

use agent_api::merkle::TreeStoreError;
use agent_api::{
    AgentGroupLeaderStatus, AgentGroupStatus, AgentStatus, AppRequest, AppResponse,
    BecomeLeaderRequest, BecomeLeaderResponse, CancelPreparedTransferRequest,
    CompleteTransferRequest, GroupOwnsRangeRequest, HashedUserId, JoinGroupRequest,
    JoinGroupResponse, JoinRealmRequest, JoinRealmResponse, NewGroupRequest, NewGroupResponse,
    NewRealmRequest, NewRealmResponse, PrepareTransferRequest, RateLimitStateRequest,
    RateLimitStateResponse, ReadCapturedRequest, ReadCapturedResponse,
    ReloadTenantConfigurationRequest, ReloadTenantConfigurationResponse, StatusRequest,
    StatusResponse, StepDownRequest, StepDownResponse, TenantRateLimitState, TransferInRequest,
    TransferOutRequest,
};
use append::{Append, AppendingState};
use build_info::BuildInfo;
use cluster_core::discover_hsm_ids;
use hsm::{HsmClient, Transport};
use hsm_api::merkle::StoreDelta;
use hsm_api::{
    AppResultType, CaptureJumpRequest, CaptureJumpResponse, CaptureNextRequest,
    CaptureNextResponse, Captured, EntryMac, GroupId, GroupMemberRole, HsmId, LogEntry, LogIndex,
    RoleLogicalClock, RoleStatus,
};
use jburl::Url;
use juicebox_marshalling as marshalling;
use juicebox_networking::reqwest::ClientOptions;
use juicebox_networking::rpc::{self, Rpc, SendOptions};
use juicebox_realm_api::requests::{ClientRequestKind, NoiseRequest, NoiseResponse};
use juicebox_realm_api::types::RealmId;
use observability::logging::TracingSource;
use observability::tracing::TracingMiddleware;
use observability::{metrics, metrics_tag as tag};
use peers::DiscoveryWatcher;
use pubsub_api::{Message, Publisher};
use rate::{PeerId, RateLimiter, Time};
use retry_loop::{retry_logging, retry_logging_debug, AttemptError, Retry, RetryError};
use service_core::http::ReqwestClientMetrics;
use service_core::rpc::{handle_rpc, HandlerError};
use store::log::{LogEntriesIter, LogEntriesIterError, LogRow, ReadLastLogEntryFatal};
use store::tenant_config::TenantConfiguration;
use store::{discovery, store_retries, ServiceKind};
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
    discovery: DiscoveryWatcher,
    state: Mutex<State>,
    tenant_limiters: RateLimiters,
    metrics: metrics::Client,
    accountant: UserAccountingWriter,
    event_publisher: Box<dyn Publisher>,
    default_rate_limiter_rate: usize,
}

#[derive(Debug)]
struct State {
    /// State for a specific group. There is an entry in here for every group
    /// the HSM is a member of.
    groups: HashMap<(RealmId, GroupId), GroupState>,
    /// Captures that have been persisted to NVRAM in the HSM.
    captures: Vec<Captured>,
    /// Set after being successfully registered with service discovery.
    registered: bool,
    /// The local HSM's ID is available before the agent is registered with
    /// service discovery. It's always available for leaders. It will never go
    /// from `Some` to `None`.
    hsm_id: Option<HsmId>,
}

impl State {
    fn is_leader(&self, realm: RealmId, group: GroupId) -> bool {
        self.groups
            .get(&(realm, group))
            .is_some_and(|g| g.leader.is_some())
    }
}

#[derive(Debug)]
struct GroupState {
    /// The list of group members, including the local HSM.
    configuration: Vec<HsmId>,
    /// The last recorded role that the HSM is in for this group along with when
    /// the transition to this role was.
    role: RoleStatus,
    /// Contains state needed while in the Leader or SteppingDown roles.
    leader: Option<LeaderState>,
}

fn group_state(
    groups: &HashMap<(RealmId, GroupId), GroupState>,
    realm: RealmId,
    group: GroupId,
) -> &GroupState {
    let Some(state) = groups.get(&(realm, group)) else {
        panic!("Missing group state for realm:{realm:?} group:{group:?}");
    };
    state
}

fn group_state_mut(
    groups: &mut HashMap<(RealmId, GroupId), GroupState>,
    realm: RealmId,
    group: GroupId,
) -> &mut GroupState {
    let Some(state) = groups.get_mut(&(realm, group)) else {
        panic!("Missing group state for realm:{realm:?} group:{group:?}");
    };
    state
}

// State about a group that is used in the Leader or SteppingDown state.
struct LeaderState {
    /// Log entries may be received out of order from the HSM. They are buffered
    /// here until they can be appended to the log in order.
    append_queue: HashMap<LogIndex, Append>,

    /// This serves as a mutex to prevent multiple concurrent appends to the
    /// store.
    appending: append::AppendingState,

    /// The most recent log entry confirmed to be committed by the HSM.
    ///
    /// This index refers to an entry that the HSM marked as committed during
    /// this leadership role: either it was in the log when the leader started
    /// or this HSM appended it.
    committed: Option<LogIndex>,

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

#[derive(Clone, Debug)]
struct RateLimiters(Arc<RateLimitersInner>);

#[derive(Debug)]
struct RateLimitersInner {
    last_state: Mutex<Vec<TenantRateLimitState>>,
    tenants: Mutex<HashMap<String, RateLimiter>>,
}

impl RateLimiters {
    fn new(metric: metrics::Client) -> Self {
        let r = Self(Arc::new(RateLimitersInner {
            last_state: Mutex::new(Vec::new()),
            tenants: Mutex::new(HashMap::with_capacity(8)),
        }));
        tokio::spawn(r.clone().state_updater(metric));
        r
    }

    async fn state_updater(self, mc: metrics::Client) {
        loop {
            let start = Instant::now();
            let now = Time::now();
            let new_state: Vec<_> = with_lock!(&self.0.tenants, |tenants_locked| {
                tenants_locked
                    .iter_mut()
                    .map(|(t, b)| (t.clone(), b.state(now)))
                    .collect()
            });
            let serialized: Vec<_> = new_state
                .into_iter()
                .map(|(t, s)| TenantRateLimitState {
                    tenant: t,
                    state: marshalling::to_vec(&s).unwrap(),
                })
                .collect();

            let prev = with_lock!(&self.0.last_state, |cache_locked| {
                mem::replace(cache_locked, serialized)
            });
            drop(prev);
            mc.timing(
                "agent.rate_limiter.state_update",
                start.elapsed(),
                metrics::NO_TAGS,
            );
            sleep_until(tokio::time::Instant::from_std(
                start + Duration::from_millis(5),
            ))
            .await;
        }
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

fn hsm_retries(retry: Retry) -> Retry {
    retry
        .with_exponential_backoff(Duration::from_millis(1), 2.0, Duration::from_secs(1))
        .with_max_attempts(usize::MAX)
        .with_timeout(Duration::from_secs(60))
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

pub struct AgentConfiguration {
    pub name: String,
    pub build_info: BuildInfo,
    pub store: store::StoreClient,
    pub store_admin: store::StoreAdminClient,
    pub event_publisher: Box<dyn Publisher>,
    pub metrics: metrics::Client,
    pub default_rate_limiter_rate: usize,
}

#[cfg(not(feature = "lock_instr"))]
macro_rules! with_lock {
    ($mutex:expr, $op:expr) => {{
        $crate::with_lock_plain($mutex, $op)
    }};
}

#[inline]
#[cfg(not(feature = "lock_instr"))]
pub(crate) fn with_lock_plain<T, R>(m: &Mutex<T>, op: impl FnOnce(&mut T) -> R) -> R {
    let mut locked = m.lock().unwrap();
    op(&mut locked)
}

#[cfg(feature = "lock_instr")]
macro_rules! with_lock {
    ($mutex:expr, $op:expr) => {{
        let (result, lock_wait, lock_held) = $crate::with_lock_instr($mutex, $op);
        if lock_wait > Duration::from_millis(1) {
            tracing::info!(duration=?lock_wait, lock=stringify!($mutex), "waiting for lock");
        }
        if lock_held > Duration::from_millis(1) {
            tracing::info!(duration=?lock_held, lock=stringify!($mutex), "holding the lock");
        }
        result
    }}
}

#[cfg(feature = "lock_instr")]
pub(crate) fn with_lock_instr<T, R>(
    m: &Mutex<T>,
    op: impl FnOnce(&mut T) -> R,
) -> (R, Duration, Duration) {
    let start = Instant::now();
    let locked_when: Instant;
    let result = {
        let mut locked = m.lock().unwrap();
        locked_when = Instant::now();
        op(&mut locked)
    };
    let locked_time = locked_when.elapsed();
    let lock_wait = locked_when - start;
    (result, lock_wait, locked_time)
}

pub(crate) use with_lock;

impl<T: Transport + 'static> Agent<T> {
    pub fn new(config: AgentConfiguration, hsm: HsmClient<T>) -> Self {
        Self(Arc::new(AgentInner {
            name: config.name,
            build_info: config.build_info,
            boot_time: Instant::now(),
            hsm,
            store: config.store.clone(),
            store_admin: config.store_admin,
            peer_client: ReqwestClientMetrics::new(
                config.metrics.clone(),
                ClientOptions::default(),
            ),
            discovery: DiscoveryWatcher::new(config.store.clone()),
            state: Mutex::new(State {
                captures: Vec::new(),
                registered: false,
                hsm_id: None,
                groups: HashMap::new(),
            }),
            tenant_limiters: RateLimiters::new(config.metrics.clone()),
            metrics: config.metrics.clone(),
            accountant: UserAccountingWriter::new(config.store, config.metrics),
            event_publisher: config.event_publisher,
            default_rate_limiter_rate: config.default_rate_limiter_rate,
        }))
    }

    /// Called at service startup, start watching for any groups that the HSM is already a member of.
    async fn restart_watching(&self) {
        let status = Retry::new("getting HSM status to start watching logs")
            .with(hsm_retries)
            .with_metrics(&self.0.metrics, "agent.restart_watching.hsm_status", &[])
            .retry(
                |_| self.0.hsm.send(hsm_api::StatusRequest {}),
                retry_logging_debug!(),
            )
            .await
            .expect("failed to get HSM status");

        let Some(realm) = status.realm else {
            warn!("HSM does not have a realm");
            return;
        };

        {
            let mut locked = self.0.state.lock().unwrap();
            locked.groups = realm
                .groups
                .iter()
                .map(|g| {
                    (
                        (realm.id, g.id),
                        GroupState {
                            configuration: g.configuration.clone(),
                            role: g.role.clone(),
                            leader: None,
                        },
                    )
                })
                .collect();
        }

        for g in realm.groups {
            let idx = match g.captured {
                Some((index, _)) => index.next(),
                None => LogIndex::FIRST,
            };
            self.start_watching(realm.id, g.id, idx);
        }
    }

    fn start_watching(&self, realm: RealmId, group: GroupId, next_index: LogIndex) {
        tokio::spawn(self.clone().watching_main(realm, group, next_index));
    }

    async fn watching_main(self, realm: RealmId, group: GroupId, mut next_index: LogIndex) {
        let configuration = group_state(&self.0.state.lock().unwrap().groups, realm, group)
            .configuration
            .clone();

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
            Err(RetryError::Fatal {
                error: ref err @ LogEntriesIterError::Compacted(index),
            }) => {
                warn!(?err, ?index, "fell behind on watching log");
                Err(WatchingError::Compacted(index))
            }
            Err(err) => {
                panic!("error watching log: {err:?}");
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
                        self.maybe_role_changed(realm, group, role);
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
        #[derive(Debug, thiserror::Error)]
        enum FatalError<T: Transport> {
            #[error("HSM transport error: {0:?}")]
            HsmTransport(T::FatalError),
        }

        #[derive(Debug, thiserror::Error)]
        enum RetryableError<T: Transport> {
            #[error("failed to discover peer agents to catch up from: {0}")]
            Discovery(RetryError<tonic::Status>),
            #[error("no peer agent returned usable capture to jump forward to")]
            NoUsableCapture,
            #[error("HSM transport error: {0:?}")]
            HsmTransport(T::RetryableError),
            #[error("HSM was not a witness but has been stepped down")]
            NotWitness,
        }

        impl<T: Transport> From<RetryableError<T>> for AttemptError<FatalError<T>, RetryableError<T>> {
            fn from(error: RetryableError<T>) -> Self {
                let kind = match error {
                    RetryableError::Discovery(_) => "discovery",
                    RetryableError::NoUsableCapture => "no_usable_capture",
                    RetryableError::HsmTransport(_) => "hsm_transport",
                    RetryableError::NotWitness => "not_witness",
                };
                AttemptError::Retryable {
                    error,
                    tags: vec![tag!(kind)],
                }
            }
        }

        let local_hsm_id: Option<HsmId> = self.0.state.lock().unwrap().hsm_id;

        let run = |_| async {
            // TODO: There's some code duplication between this and the commit
            // path.
            let urls: Vec<Url> = discover_hsm_ids(&self.0.store, &self.0.peer_client)
                .await
                .map_err(RetryableError::<T>::Discovery)?
                .filter(|(hsm, _)| Some(hsm) != local_hsm_id.as_ref())
                .filter(|(hsm, _)| configuration.contains(hsm))
                .map(|(_, url)| url)
                .collect();

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
                return Err(RetryableError::NoUsableCapture.into());
            };

            let jump_index = jump.index;
            match self.0.hsm.send(CaptureJumpRequest { jump }).await {
                Err(err) => Err(err
                    .map_fatal_err(FatalError::HsmTransport)
                    .map_retryable_err(RetryableError::HsmTransport)),
                Ok(CaptureJumpResponse::Ok) => Ok(jump_index),
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
                    Err(RetryableError::NotWitness.into())
                }
                Ok(
                    r @ (CaptureJumpResponse::InvalidRealm
                    | CaptureJumpResponse::InvalidGroup
                    | CaptureJumpResponse::InvalidStatement
                    | CaptureJumpResponse::StaleIndex),
                ) => panic!("unexpected CaptureJump response: {r:?}"),
            }
        };

        match Retry::new("catching up HSM from a peer")
            .with(store_retries)
            .with_timeout(Duration::from_secs(30))
            .with_metrics(
                &self.0.metrics,
                "agent.catchup",
                &[tag!(?realm), tag!(?group)],
            )
            .retry(run, retry_logging!())
            .await
        {
            Ok(jump_index) => jump_index,
            Err(error) => panic!("failed to catch up HSM from a peer: {error}"),
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
            Ok(hsm_api::StepDownResponse::Ok { role, .. }) => {
                self.maybe_role_changed(realm, group, role);
            }
            Ok(hsm_api::StepDownResponse::NotLeader(role)) => {
                self.maybe_role_changed(realm, group, role);
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
                        with_lock!(&self.0.state, |agent_state| {
                            for hsm_group_status in hsm_realm_status.groups {
                                let group = hsm_group_status.id;
                                // During new_realm & new_group we can be in this
                                // state for a while as the agent leader state isn't
                                // set until its finished creating the bigtable
                                // tables and has appended the first log entry &
                                // merkle tree nodes. The check on the captured
                                // index stops us from treating that as a bad state.
                                let is_suspect = matches!(
                                    hsm_group_status.role.role,
                                    GroupMemberRole::Leader { .. }
                                ) && hsm_group_status
                                    .captured
                                    .is_some_and(|(index, _)| index > LogIndex::FIRST)
                                    && !agent_state.is_leader(realm, group);
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
                        });
                    }
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
        self.start_ratelimit_fetcher(url.clone());
        self.start_tenant_config_fetcher().await;
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
                            let io = TokioIo::new(stream);
                            let agent = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(io, TracingMiddleware::new(agent.clone()))
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
            state
                .groups
                .iter()
                .filter(|g| g.1.leader.is_some())
                .map(|(k, _v)| k)
                .copied()
                .collect::<Vec<_>>()
        };
        let leading = get_leading();
        if leading.is_empty() {
            // easy case, we're not leader, job done.
        } else {
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
            while !get_leading().is_empty() {
                sleep(Duration::from_millis(20)).await;
            }
        }
        // now all the leadership work is done, we can shutdown the merkle delete queue
        self.0.store.shutdown_delete_queue().await;
    }

    // Find a cluster manager and ask it to stepdown all the groups we're leading.
    async fn stepdown_with_cluster_manager(&self, id: HsmId) {
        match self.0.discovery.urls(ServiceKind::ClusterManager) {
            managers if !managers.0.is_empty() => {
                for manager in &managers.0 {
                    let req = cluster_api::StepDownRequest::Hsm(id);
                    match rpc::send(&self.0.peer_client, manager, req).await {
                        Ok(cluster_api::StepDownResponse::Ok) => return,
                        Ok(res) => {
                            warn!(?res, url=%manager, "stepdown not ok");
                        }
                        Err(err) => {
                            warn!(?err, url=%manager, "stepdown reported error");
                        }
                    }
                }
            }
            _ => {
                warn!("Unable to find cluster manager in service discovery.");
            }
        }
    }

    fn start_service_registration(&self, url: Url) {
        let agent = self.0.clone();
        tokio::spawn(async move {
            let hsm_api::StatusResponse { id: hsm_id, .. } =
                Retry::new("getting HSM status to start service registration")
                    .with(hsm_retries)
                    .with_metrics(&agent.metrics, "agent.service_registration.hsm_status", &[])
                    .retry(
                        |_| agent.hsm.send(hsm_api::StatusRequest {}),
                        retry_logging_debug!(),
                    )
                    .await
                    .expect("failed to get HSM status");

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

    fn start_ratelimit_fetcher(&self, our_url: Url) {
        let agent = self.0.clone();
        let mut disco_rx = self.0.discovery.subscribe(ServiceKind::Agent);
        tokio::spawn(async move {
            let mut urls = disco_rx.borrow_and_update().excluding(&our_url);
            let mut tenant_states: HashMap<String, rate::PeerStates> = HashMap::new();
            info!(peers=?urls, "starting rate limit collector");
            loop {
                if matches!(disco_rx.has_changed(), Ok(true)) {
                    let new_urls = disco_rx.borrow_and_update().excluding(&our_url);
                    if !new_urls.0.is_empty() {
                        info!(peers=?new_urls, "rate limit collector using new set of peers");
                        urls = new_urls;
                    }
                }

                let mut peer_results: FuturesUnordered<_> = urls
                    .0
                    .iter()
                    .map(|url| {
                        rpc::send_with_options(
                            &agent.peer_client,
                            url,
                            RateLimitStateRequest {},
                            SendOptions::default().with_timeout(Duration::from_millis(500)),
                        )
                        .map(move |r| (PeerId(url.to_string()), r))
                    })
                    .collect();

                while let Some((peer, result)) = peer_results.next().await {
                    if let Ok(RateLimitStateResponse::Ok(updates)) = result {
                        let now = Time::now();
                        for update in updates {
                            match marshalling::from_slice(&update.state) {
                                Err(err) => {
                                    warn!(
                                        ?peer,
                                        ?err,
                                        "failed to deserialize rate limiter state from peer"
                                    );
                                }
                                Ok(state) => {
                                    tenant_states.entry(update.tenant).or_default().update(
                                        now,
                                        peer.clone(),
                                        state,
                                    );
                                }
                            }
                        }
                    }
                }

                let now = Time::now();
                let merged_states: Vec<_> = tenant_states
                    .iter_mut()
                    .map(|(tenant, states)| (tenant.clone(), states.merged(now)))
                    .collect();

                with_lock!(&agent.tenant_limiters.0.tenants, |locked| {
                    for (tenant, state) in merged_states {
                        locked
                            .entry(tenant)
                            .or_insert_with(|| RateLimiter::new(agent.default_rate_limiter_rate))
                            .update_from_peers(state);
                    }
                });
                sleep(Duration::from_millis(10)).await;
            }
        });
    }

    async fn start_tenant_config_fetcher(&self) {
        let mut last = match self.reload_tenant_config(&[]).await {
            Ok(ReloadTenantConfigResult::Updated(config)) => config,
            Ok(ReloadTenantConfigResult::NotChanged) => Vec::new(),
            Err(_) => Vec::new(),
        };
        let agent = self.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(60)).await;
                match agent.reload_tenant_config(&last).await {
                    Ok(ReloadTenantConfigResult::NotChanged) => {}
                    Ok(ReloadTenantConfigResult::Updated(new_config)) => {
                        last = new_config;
                    }
                    Err(_) => {
                        // already logged
                    }
                }
            }
        });
    }

    async fn reload_tenant_config(
        &self,
        last: &[(String, TenantConfiguration)],
    ) -> Result<ReloadTenantConfigResult, RetryError<tonic::Status>> {
        match self.0.store.get_tenants().await {
            Err(err) => {
                warn!(?err, "failed to get tenant info from bigtable");
                Err(err)
            }
            Ok(tenants) => {
                debug!(?tenants, "got tenant info from bigtable");
                if tenants == last {
                    return Ok(ReloadTenantConfigResult::NotChanged);
                }
                with_lock!(&self.0.tenant_limiters.0.tenants, |locked| {
                    for (tenant, config) in &tenants {
                        locked
                            .entry(tenant.clone())
                            .and_modify(|rl| rl.update_limit(config.capacity_reqs_per_sec()))
                            .or_insert_with(|| RateLimiter::new(config.capacity_reqs_per_sec()));
                    }
                });
                info!(num_tenants=?tenants.len(), "updated tenant rate limiting configuration");
                Ok(ReloadTenantConfigResult::Updated(tenants))
            }
        }
    }

    async fn handle_reload_tenant_config(
        &self,
        _: ReloadTenantConfigurationRequest,
    ) -> Result<ReloadTenantConfigurationResponse, HandlerError> {
        match self.reload_tenant_config(&[]).await {
            Err(_) => Ok(ReloadTenantConfigurationResponse::NoStore),
            Ok(ReloadTenantConfigResult::NotChanged) => {
                Ok(ReloadTenantConfigurationResponse::Ok { num_tenants: 0 })
            }
            Ok(ReloadTenantConfigResult::Updated(config)) => {
                Ok(ReloadTenantConfigurationResponse::Ok {
                    num_tenants: config.len(),
                })
            }
        }
    }
}

enum ReloadTenantConfigResult {
    NotChanged,
    Updated(Vec<(String, TenantConfiguration)>),
}

impl<T: Transport + 'static> Service<Request<IncomingBody>> for Agent<T> {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<IncomingBody>) -> Self::Future {
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
                        .status(hyper::StatusCode::NOT_FOUND)
                        .body(Full::from(Bytes::new()))
                        .unwrap());
                };
                match path {
                    AppRequest::PATH => handle_rpc(&agent, request, Self::handle_app).await,
                    StatusRequest::PATH => handle_rpc(&agent, request, Self::handle_status).await,
                    RateLimitStateRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_ratelimit_state).await
                    }
                    ReadCapturedRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_read_captured).await
                    }
                    "livez" => Ok(agent.handle_livez(request).await),
                    BecomeLeaderRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_become_leader).await
                    }
                    StepDownRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_stepdown_as_leader).await
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
                    ReloadTenantConfigurationRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_reload_tenant_config).await
                    }
                    PrepareTransferRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_prepare_transfer).await
                    }
                    CancelPreparedTransferRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_cancel_prepared_transfer).await
                    }
                    TransferOutRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_transfer_out).await
                    }
                    TransferInRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_transfer_in).await
                    }
                    CompleteTransferRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_complete_transfer).await
                    }
                    GroupOwnsRangeRequest::PATH => {
                        handle_rpc(&agent, request, Self::handle_group_owns_range).await
                    }
                    _ => Ok(Response::builder()
                        .status(hyper::StatusCode::NOT_FOUND)
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
                            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
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
        let groups = with_lock!(&self.0.state, |locked| {
            if let Ok(hsm_status) = &hsm_status {
                // The ID is cached before service discovery registration, but we
                // set it here too in case others call this before that happens.
                locked.hsm_id = Some(hsm_status.id);
            }
            locked
                .groups
                .iter()
                .map(|((realm, group), gs)| AgentGroupStatus {
                    realm: *realm,
                    group: *group,
                    role: gs.role.clone(),
                    leader: gs.leader.as_ref().map(|ls| AgentGroupLeaderStatus {
                        num_waiting_clients: ls.response_channels.len(),
                        last_appended: ls
                            .last_appended
                            .as_ref()
                            .map(|e| (e.index, e.entry_mac.clone())),
                        append_queue_len: ls.append_queue.len(),
                    }),
                })
                .collect()
        });

        Ok(StatusResponse {
            hsm: hsm_status.ok(),
            uptime: self.0.boot_time.elapsed(),
            agent: AgentStatus {
                name: self.0.name.clone(),
                build_hash: self.0.build_info.git_hash.unwrap_or("").to_owned(),
                groups,
            },
        })
    }

    async fn handle_ratelimit_state(
        &self,
        _request: RateLimitStateRequest,
    ) -> Result<RateLimitStateResponse, HandlerError> {
        let states = with_lock!(&self.0.tenant_limiters.0.last_state, |locked| {
            locked.clone()
        });
        Ok(RateLimitStateResponse::Ok(states))
    }

    async fn handle_livez(&self, _request: Request<IncomingBody>) -> Response<Full<Bytes>> {
        let unavailable_response = |message: Arguments| -> Response<Full<Bytes>> {
            Response::builder()
                .status(hyper::StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::from(Bytes::from(format!(
                    "{}\n{}",
                    message,
                    self.0.build_info.livez()
                ))))
                .unwrap()
        };

        let not_registered = with_lock!(&self.0.state, |locked| {
            !locked.registered || locked.hsm_id.is_none()
        });
        if not_registered {
            // The HSM ID is cached before registration, so the message
            // only mentions service discovery.
            return unavailable_response(format_args!("not yet registered with service discovery"));
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
                .status(hyper::StatusCode::OK)
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
        let (realm, group, entry, delta, role) =
            match self.0.hsm.send(hsm_api::NewRealmRequest {}).await {
                Err(_) => return Ok(Response::NoHsm),
                Ok(hsm_api::NewRealmResponse::HaveRealm) => return Ok(Response::HaveRealm),
                Ok(hsm_api::NewRealmResponse::Ok {
                    realm,
                    group,
                    entry,
                    delta,
                    role,
                }) => (realm, group, entry, delta, role),
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
                self.finish_new_group(realm, group, vec![hsm_id], role);
                Ok(Response::Ok { realm, group })
            }
            Err(store::AppendError::LogPrecondition) => Ok(Response::StorePreconditionFailed),
            Err(err) if err.is_no_store() => Ok(Response::NoStore),
            Err(err) => todo!("{err:?}"),
        }
    }

    fn finish_new_group(
        &self,
        realm: RealmId,
        group: GroupId,
        config: Vec<HsmId>,
        role: RoleStatus,
    ) {
        let s = GroupState {
            configuration: config.clone(),
            role: RoleStatus {
                role: GroupMemberRole::Witness,
                at: RoleLogicalClock(0),
            },
            leader: None,
        };
        {
            let existing = self
                .0
                .state
                .lock()
                .unwrap()
                .groups
                .insert((realm, group), s);
            assert!(existing.is_none());
        }
        self.start_watching(realm, group, LogIndex::FIRST);
        self.maybe_role_changed(realm, group, role);
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

        let (group, statement, entry, role) = match self
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
                role,
            }) => (group, statement, entry, role),
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
                self.finish_new_group(realm, group, configuration, role);
                Ok(Response::Ok { group, statement })
            }
            Err(store::AppendError::LogPrecondition) => Ok(Response::StorePreconditionFailed),
            Err(err) if err.is_no_store() => Ok(Response::NoStore),
            Err(err) => todo!("{err:?}"),
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
            Ok(HsmResponse::Ok(role)) => {
                let mut start = false;
                self.0
                    .state
                    .lock()
                    .unwrap()
                    .groups
                    .entry((request.realm, request.group))
                    .or_insert_with(|| {
                        start = true;
                        GroupState {
                            configuration: request.configuration,
                            role,
                            leader: None,
                        }
                    });
                if start {
                    self.start_watching(request.realm, request.group, LogIndex::FIRST);
                }
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
        let deadline = Instant::now() + Duration::from_secs(5);
        Ok(self.handle_become_leader_inner(&request, deadline).await)
    }

    async fn handle_become_leader_inner(
        &self,
        request: &BecomeLeaderRequest,
        deadline: Instant,
    ) -> BecomeLeaderResponse {
        type Response = BecomeLeaderResponse;
        type HsmResponse = hsm_api::BecomeLeaderResponse;

        let hsm = &self.0.hsm;
        let store = &self.0.store;
        let tags = [tag!("realm": ?request.realm), tag!("group": ?request.group)];

        if with_lock!(&self.0.state, |locked| locked.hsm_id.is_none()) {
            // The HSM should be up by now, and we don't want to start
            // leadership without knowing its ID.
            return Response::NoHsm;
        }

        let read_log_entry = |_| async {
            let entry = store
                .read_last_log_entry(&request.realm, &request.group)
                .await
                .map_err(|_| {
                    // read_last_log_entry already logged a warning
                    AttemptError::Fatal {
                        error: Response::NoStore,
                        tags: vec![tag!("kind": "no_store")],
                    }
                })?;

            let Some(expected) = request.last else {
                return Ok(entry);
            };

            // If the cluster manager is doing a coordinated leadership
            // handoff, it knows what the last log index of the stepping
            // down leader owned.
            match entry.index.cmp(&expected) {
                Ordering::Less => {
                    // The last leader probably hasn't quite written the
                    // entry to the store yet. Wait for it.
                    Err(AttemptError::Retryable {
                        error: Response::FutureIndex,
                        tags: vec![tag!("kind": "future_index")],
                    })
                }
                Ordering::Equal => Ok(entry),
                Ordering::Greater => {
                    // The log is beyond this point, so a new leader
                    // starting here would be unable to append anything.
                    warn!(
                        found = %entry.index,
                        %expected,
                        "found log entry beyond BecomeLeaderRequest index",
                    );
                    Err(AttemptError::Fatal {
                        error: Response::StaleIndex,
                        tags: vec![tag!("kind": "stale_index")],
                    })
                }
            }
        };

        let last_entry: LogEntry = match Retry::new("reading log entry to become leader")
            .with(store_retries)
            .with_deadline(Some(deadline))
            .with_metrics(
                &self.0.metrics,
                "agent.handle_become_leader.read_log_entry",
                &tags,
            )
            .retry(read_log_entry, retry_logging_debug!())
            .await
        {
            Ok(entry) => entry,
            Err(RetryError::Exhausted {
                last: Some(response),
            }) => return response,
            Err(RetryError::Exhausted { last: None }) => return Response::Timeout,
            Err(RetryError::Fatal { error: response }) => return response,
        };

        info!(
            index=?last_entry.index,
            "read log entry, asking HSM to become leader"
        );

        let hsm_become_leader = |_| async {
            match hsm
                .send(hsm_api::BecomeLeaderRequest {
                    realm: request.realm,
                    group: request.group,
                    last_entry: last_entry.clone(),
                })
                .await
            {
                Err(_) => Err(AttemptError::Fatal {
                    error: Response::NoHsm,
                    tags: vec![tag!("kind": "no_hsm")],
                }),
                Ok(HsmResponse::Ok { role }) => {
                    self.maybe_role_changed(request.realm, request.group, role);
                    Ok(Response::Ok)
                }
                Ok(HsmResponse::InvalidRealm) => Err(AttemptError::Fatal {
                    error: Response::InvalidRealm,
                    tags: vec![tag!("kind": "invalid_realm")],
                }),
                Ok(HsmResponse::InvalidGroup) => Err(AttemptError::Fatal {
                    error: Response::InvalidGroup,
                    tags: vec![tag!("kind": "invalid_group")],
                }),
                Ok(HsmResponse::StepdownInProgress) => {
                    info!(
                        realm=?request.realm,
                        group=?request.group,
                        state=?self.0.state.lock().unwrap(),
                        "didn't become leader because still stepping down",
                    );
                    Err(AttemptError::Fatal {
                        error: Response::StepdownInProgress,
                        tags: vec![tag!("kind": "stepdown_in_progress")],
                    })
                }
                Ok(HsmResponse::InvalidMac) => panic!("invalid MAC found in log"),
                Ok(HsmResponse::NotCaptured { have }) => {
                    // On an active group it's possible that the index that the
                    // HSM has captured up to is behind the log entry we just
                    // read. Wait around a little to let it catch up.
                    // Particularly for cluster rebalance operations, it's
                    // better to wait slightly here so that the selected agent
                    // becomes leader, rather then ending up trying to undo the
                    // leadership move.
                    let error = Response::NotCaptured { have };
                    let tags = vec![tag!("kind": "not_captured")];
                    let is_close = have.is_some_and(|have| {
                        LogIndex(have.0.saturating_add(1000)) >= last_entry.index
                    });
                    if is_close {
                        Err(AttemptError::Retryable { error, tags })
                    } else {
                        Err(AttemptError::Fatal { error, tags })
                    }
                }
            }
        };

        match Retry::new("requesting HSM to become leader")
            .with(hsm_retries)
            .with_deadline(Some(deadline))
            .with_metrics(
                &self.0.metrics,
                "agent.handle_become_leader.hsm_request",
                &tags,
            )
            .retry(hsm_become_leader, retry_logging_debug!())
            .await
        {
            Ok(response) => response,
            Err(RetryError::Exhausted {
                last: Some(response),
            }) => response,
            Err(RetryError::Exhausted { last: None }) => Response::Timeout,
            Err(RetryError::Fatal { error: response }) => response,
        }
    }

    async fn handle_stepdown_as_leader(
        &self,
        request: StepDownRequest,
    ) -> Result<StepDownResponse, HandlerError> {
        type Response = StepDownResponse;
        type HsmResponse = hsm_api::StepDownResponse;

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
            Ok(HsmResponse::Ok { role, last }) => {
                match role.role {
                    GroupMemberRole::Witness => {
                        info!(group=?request.group,
                            realm=?request.realm,
                            index=?last,
                            "HSM stepped down as leader")
                    }
                    GroupMemberRole::SteppingDown { .. } => {
                        info!(group=?request.group,
                            realm=?request.realm,
                            index=?last,
                            "HSM will step down as leader")
                    }
                    _ => {}
                }
                self.maybe_role_changed(request.realm, request.group, role);
                Ok(Response::Ok { last })
            }
            Ok(HsmResponse::InvalidGroup) => Ok(Response::InvalidGroup),
            Ok(HsmResponse::InvalidRealm) => Ok(Response::InvalidRealm),
            Ok(HsmResponse::NotLeader(role)) => {
                self.maybe_role_changed(request.realm, request.group, role);
                Ok(Response::NotLeader)
            }
        }
    }

    #[instrument(level = "trace", skip(self))]
    async fn handle_read_captured(
        &self,
        request: ReadCapturedRequest,
    ) -> Result<ReadCapturedResponse, HandlerError> {
        type Response = ReadCapturedResponse;

        let c = with_lock!(&self.0.state, |state| state
            .captures
            .iter()
            .find(|c| c.group == request.group && c.realm == request.realm)
            .cloned());
        Ok(Response::Ok(c))
    }

    /// Called by `handle_app` to process [`AppRequest`]s of type Handshake
    /// that don't have a payload. Unlike other [`AppRequest`]s, these don't
    /// require dealing with the log or Merkle tree.
    #[instrument(level = "trace", skip(self, request))]
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

        match self.start_app_request(request, &tags).await {
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
                    // create a reservation for the follow on request if there's going to be one.
                    if matches!(
                        request_type,
                        AppResultType::Recover1
                            | AppResultType::Recover2 { .. }
                            | AppResultType::Register1
                    ) {
                        let record_id = record_id.clone();
                        with_lock!(&self.0.tenant_limiters.0.tenants, |locked| {
                            locked
                            .get_mut(&tenant)
                            .expect(
                                "start_app_request created the bucket if it didn't already exist",
                            )
                            .add_reservation(record_id);
                        });
                    }
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

        let is_leader = with_lock!(&self.0.state, |locked| {
            let group_state = group_state_mut(&mut locked.groups, realm, group);
            match &mut group_state.leader {
                Some(leader) => {
                    leader
                        .response_channels
                        .insert(append_request.entry.entry_mac.clone().into(), sender);
                    true
                }
                None => {
                    // Its possible for start_app_request to succeed, but to
                    // have subsequently lost leadership due to a background
                    // capture_next or commit operation.
                    false
                }
            }
        });
        if !is_leader {
            return Ok((Response::NotLeader, None));
        }

        self.append(realm, group, append_request);
        match receiver.await {
            Ok((response, res_type)) => Ok((Response::Ok(response), Some(res_type))),
            Err(oneshot::Canceled) => Ok((Response::NotLeader, None)),
        }
    }

    #[instrument(level = "trace", skip(self, request))]
    async fn start_app_request(
        &self,
        request: AppRequest,
        tags: &[metrics::Tag],
    ) -> Result<Append, AppResponse> {
        type HsmResponse = hsm_api::AppResponse;
        type Response = AppResponse;

        let rate_limit_result = {
            let tenant = request.tenant.clone();
            let rec_id = request.record_id.clone();
            with_lock!(&self.0.tenant_limiters.0.tenants, move |locked| {
                let bucket = locked
                    .entry(tenant)
                    .or_insert_with(|| RateLimiter::new(self.0.default_rate_limiter_rate));
                bucket.allow(rec_id)
            })
        };
        if !rate_limit_result.allowed {
            warn!(tenant=?request.tenant, bucket=?rate_limit_result, "rate limit exceeded");
            return Err(Response::RateLimitExceeded);
        } else {
            debug!(tenant=?request.tenant, bucket=?rate_limit_result, "rate limit allowed");
        }

        #[derive(Debug, thiserror::Error)]
        enum FatalError<T: Transport> {
            // These ultimately map to NO_HSM, but it's useful to separate them
            // out so that more detailed warnings are logged.
            #[error("HSM transport error: {0:?}")]
            HsmTransport(T::FatalError),
            #[error("{0:?}")]
            Other(AppResponse),
        }

        #[derive(Debug, thiserror::Error)]
        enum RetryableError<T: Transport> {
            #[error("Merkle node was missing (likely deleted before we read it)")]
            MissingNode,
            #[error("HSM transport error: {0:?}")]
            HsmTransport(T::RetryableError),
            #[error("HSM rejected stale proof. This agent will get a fresh one. Tree root hash was from log index {}", .index.0)]
            StaleProof { index: LogIndex },
            #[error("The store is too busy to handle a merkle path read request")]
            StoreBusy,
        }

        impl<T: Transport> From<FatalError<T>> for AttemptError<FatalError<T>, RetryableError<T>> {
            fn from(error: FatalError<T>) -> Self {
                let kind = match &error {
                    FatalError::HsmTransport(_) => "hsm_transport",
                    FatalError::Other(response) => match response {
                        AppResponse::Ok(_) => "ok_error", // shouldn't happen
                        AppResponse::NoHsm => "no_hsm",
                        AppResponse::NoStore => "no_store",
                        AppResponse::NoPubSub => "no_pub_sub",
                        AppResponse::InvalidRealm => "invalid_realm",
                        AppResponse::InvalidGroup => "invalid_group",
                        AppResponse::NotLeader => "not_leader",
                        AppResponse::InvalidProof => "invalid_proof",
                        AppResponse::MissingSession => "missing_session",
                        AppResponse::SessionError => "session_error",
                        AppResponse::DecodingError => "decoding_error",
                        AppResponse::RateLimitExceeded => "rate_limit_exceeded",
                    },
                };
                AttemptError::Fatal {
                    error,
                    tags: vec![tag!(kind)],
                }
            }
        }
        impl<T: Transport> From<RetryableError<T>> for AttemptError<FatalError<T>, RetryableError<T>> {
            fn from(error: RetryableError<T>) -> Self {
                let kind = match &error {
                    RetryableError::HsmTransport(_) => "hsm_transport",
                    RetryableError::MissingNode => "missing_node",
                    RetryableError::StaleProof { .. } => "stale_proof",
                    RetryableError::StoreBusy => "store_busy",
                };
                AttemptError::Retryable {
                    error,
                    tags: vec![tag!(kind)],
                }
            }
        }

        let run = |_| async {
            let cached_entry: Option<LogEntry> = with_lock!(&self.0.state, |locked| {
                match group_state(&locked.groups, request.realm, request.group)
                    .leader
                    .as_ref()
                {
                    Some(leader) => Ok(leader.last_appended.clone()),
                    None => Err(AttemptError::from(FatalError::<T>::Other(
                        Response::NotLeader,
                    ))),
                }
            })?;

            let entry: LogEntry = match cached_entry {
                Some(entry) => entry,
                None => match self
                    .0
                    .store
                    .read_last_log_entry(&request.realm, &request.group)
                    .await
                {
                    Ok(entry) => entry,
                    Err(RetryError::Fatal {
                        error: ReadLastLogEntryFatal::EmptyLog,
                    }) => return Err(FatalError::Other(Response::InvalidGroup).into()),
                    Err(_) => return Err(FatalError::Other(Response::NoStore).into()),
                },
            };

            let Some(partition) = entry.partition else {
                return Err(FatalError::Other(Response::NotLeader).into());
            };

            let proof = merkle::read(
                &request.realm,
                &self.0.store,
                &partition.range,
                &partition.root_hash,
                &request.record_id,
                &self.0.metrics,
                tags,
            )
            .await
            .map_err(|error| -> AttemptError<_, _> {
                match error {
                    TreeStoreError::MissingNode => RetryableError::MissingNode.into(),
                    TreeStoreError::Network(_) => {
                        warn!(?error, "start_app_request: error reading proof");
                        FatalError::Other(Response::NoStore).into()
                    }
                    TreeStoreError::Busy => RetryableError::StoreBusy.into(),
                }
            })?;

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
                Err(error) => Err(error
                    .map_fatal_err(FatalError::HsmTransport)
                    .map_retryable_err(RetryableError::HsmTransport)),
                Ok(HsmResponse::InvalidRealm) => {
                    Err(FatalError::Other(Response::InvalidRealm).into())
                }
                Ok(HsmResponse::InvalidGroup) => {
                    Err(FatalError::Other(Response::InvalidGroup).into())
                }
                Ok(HsmResponse::StaleProof) => {
                    Err(RetryableError::StaleProof { index: entry.index }.into())
                }
                Ok(HsmResponse::NotLeader(role)) => {
                    self.maybe_role_changed(request.realm, request.group, role);
                    Err(FatalError::Other(Response::NotLeader).into())
                }
                Ok(HsmResponse::NotOwner) => Err(FatalError::Other(Response::NotLeader).into()),
                Ok(HsmResponse::InvalidProof) => {
                    Err(FatalError::Other(Response::InvalidProof).into())
                }
                // TODO, is this right? if we can't decrypt the leaf, then the proof is likely bogus.
                Ok(HsmResponse::InvalidRecordData) => {
                    Err(FatalError::Other(Response::InvalidProof).into())
                }
                Ok(HsmResponse::MissingSession) => {
                    Err(FatalError::Other(Response::MissingSession).into())
                }
                Ok(HsmResponse::SessionError) => {
                    Err(FatalError::Other(Response::SessionError).into())
                }
                Ok(HsmResponse::DecodingError) => {
                    Err(FatalError::Other(Response::DecodingError).into())
                }

                Ok(HsmResponse::Ok { entry, delta }) => {
                    trace!(
                        agent = self.0.name,
                        ?entry,
                        ?delta,
                        "got new log entry and data updates from HSM"
                    );
                    Ok(Append { entry, delta })
                }
            }
        };
        match Retry::new("handling app request")
            .with(store_retries)
            .with_metrics(&self.0.metrics, "agent.start_app_request", tags)
            .retry(run, retry_logging!())
            .await
        {
            Ok(append) => Ok(append),
            Err(RetryError::Fatal {
                error: FatalError::HsmTransport(_),
            }) => return Err(Response::NoHsm),
            Err(RetryError::Fatal {
                error: FatalError::Other(response),
            }) => return Err(response),
            Err(err @ RetryError::Exhausted { .. }) => panic!("failed to start app request: {err}"),
        }
    }

    fn maybe_role_changed(&self, realm: RealmId, group: GroupId, role_now: RoleStatus) {
        let starting_info = with_lock!(&self.0.state, |locked| {
            let group_state = group_state_mut(&mut locked.groups, realm, group);

            if role_now.at < group_state.role.at {
                warn!(%role_now, %group_state.role, "skipping stale state update");
                return None;
            }
            if role_now.at == group_state.role.at {
                assert_eq!(role_now.role, group_state.role.role);
                return None;
            }

            info!(?group, from=%group_state.role, to=%role_now, "HSM role transitioned");
            group_state.role = role_now.clone();

            match role_now.role {
                GroupMemberRole::Witness => {
                    // If we've transitioned to witness from leader/stepdown we
                    // need to cleanup our leader state.
                    group_state.leader = None;
                    None
                }
                GroupMemberRole::SteppingDown {
                    leader_starting: starting_index,
                }
                | GroupMemberRole::Leader {
                    starting: starting_index,
                } => {
                    // Start the leader tasks if needed.
                    if group_state.leader.is_none() {
                        group_state.leader = Some(LeaderState {
                            append_queue: HashMap::new(),
                            appending: AppendingState::NotAppending {
                                next: starting_index,
                            },
                            committed: None,
                            last_appended: None,
                            uncompacted_rows: VecDeque::new(),
                            response_channels: HashMap::new(),
                        });
                        Some((group_state.configuration.clone(), starting_index))
                    } else {
                        // Leader tasks already running. (e.g. become_leader
                        // called while already leader, or transitioning from
                        // leader to stepping down)
                        None
                    }
                }
            }
        });

        if let Some((config, starting_index)) = starting_info {
            info!(name=?self.0.name, ?realm, ?group, "Starting group committer");
            tokio::spawn(
                self.clone()
                    .group_committer(realm, group, config, starting_index),
            );
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
