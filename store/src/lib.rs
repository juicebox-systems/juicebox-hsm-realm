use futures::FutureExt;
use google::auth::AuthMiddleware;
use google::bigtable::v2::bigtable_client::BigtableClient as BtClient;
use google::bigtable::v2::{read_rows_request, PingAndWarmRequest, ReadRowsRequest};
use google::GrpcConnectionOptions;
use http::Uri;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{oneshot, Semaphore};
use tokio::time::sleep;
use tracing::{debug, info, instrument, trace, warn};

use bigtable::mutate::MutateRowsError;
use bigtable::read::{Reader, RowKey};
use bigtable::{
    new_admin_client, new_data_client, AuthManager, BigtableClient, BigtableTableAdminClient,
    ConnWarmer, Instance,
};
use hsm_api::merkle::StoreDelta;
use hsm_api::{DataHash, EntryMac, GroupId, LogEntry, LogIndex};
use jburl::Url;
use juicebox_realm_api::types::RealmId;
use observability::{metrics, metrics_tag as tag};
use retry_loop::{Retry, RetryError};
use service_core::clap_parsers::parse_duration;

mod base128;
pub mod discovery;
mod lease;
pub mod log;
mod merkle;
pub mod tenant_config;
pub mod tenants;

pub use bigtable::bigtable_retries as store_retries;
use log::{LogRow, ReadLastLogEntryError, ReadLastLogEntryFatal};
pub use merkle::merkle_table;
use merkle::{DeleteKeySet, InstanceIds, MerkleDeleteQueue};

#[derive(clap::Args, Clone, Debug)]
pub struct BigtableArgs {
    /// The name of the GCP project that contains the bigtable instance.
    #[arg(
        long = "bigtable-project",
        default_value = "prj",
        env = "JB_GCP_PROJECT"
    )]
    pub project: String,

    /// The name of the bigtable instance to connect to.
    #[arg(
        long = "bigtable-instance",
        default_value = "instance",
        env = "JB_BIGTABLE"
    )]
    pub instance: String,

    /// The url to the bigtable emulator [default uses GCP endpoints].
    #[arg(long = "bigtable-url")]
    pub url: Option<Uri>,

    /// The bigtable gRPC request timeout setting.
    #[arg(long = "bigtable-timeout",
            value_parser=parse_duration,
            default_value=format!("{:?}", GrpcConnectionOptions::default().timeout))]
    pub timeout: Duration,

    /// The bigtable gRPC connection timeout setting.
    #[arg(long ="bigtable-connect-timeout",
            value_parser=parse_duration,
            default_value=format!("{:?}", GrpcConnectionOptions::default().connect_timeout))]
    pub connect_timeout: Duration,

    /// The bigtable gRPC http2 Keep-alive interval setting.
    ///
    /// Interval between sending http2 keep-alive ping messages.
    #[arg(long = "bigtable-http-keepalive-interval",
            value_parser=parse_duration,
            default_value=format!("{:?}", GrpcConnectionOptions::default().http2_keepalive_interval))]
    pub http2_keepalive_interval: Duration,

    /// The bigtable gRPC http2 Keep-alive timeout setting.
    ///
    /// The timeout duration waiting for a http2 keep-alive ping response.
    #[arg(long = "bigtable-http-keepalive-timeout",
        value_parser=parse_duration,
        default_value=format!("{:?}", GrpcConnectionOptions::default().http2_keepalive_timeout))]
    pub http2_keepalive_timeout: Duration,

    /// The bigtable gRPC http2 Keep-alive while idle setting.
    ///
    /// If true http2 keep alive messages will continue to be sent when the connection would otherwise be idle
    #[arg(long = "bigtable-http-keepalive-while-idle",
        default_value_t=GrpcConnectionOptions::default().http2_keepalive_while_idle)]
    pub http2_keepalive_while_idle: bool,
}

impl BigtableArgs {
    pub fn needs_auth(&self) -> bool {
        match &self.url {
            Some(url) => {
                let host = url.host().expect("url should specify host");
                host == "googleapis.com" || host.ends_with(".googleapis.com")
            }
            None => true,
        }
    }

    pub async fn connect_data(
        &self,
        auth_manager: AuthManager,
        options: Options,
    ) -> Result<StoreClient, tonic::transport::Error> {
        let data_url = match &self.url {
            Some(u) => u.clone(),
            None => Uri::from_static("https://bigtable.googleapis.com"),
        };
        info!(
            instance = self.instance,
            project = self.project,
            %data_url,
            "Connecting to Bigtable Data"
        );
        let instance = Instance {
            project: self.project.clone(),
            instance: self.instance.clone(),
        };
        let conn_options = GrpcConnectionOptions {
            timeout: self.timeout,
            connect_timeout: self.connect_timeout,
            http2_keepalive_interval: self.http2_keepalive_interval,
            http2_keepalive_timeout: self.http2_keepalive_timeout,
            http2_keepalive_while_idle: self.http2_keepalive_while_idle,
        };
        StoreClient::new(
            data_url.clone(),
            instance,
            auth_manager.clone(),
            options,
            conn_options,
        )
        .await
    }

    pub async fn connect_admin(
        &self,
        auth_manager: AuthManager,
        metrics: metrics::Client,
    ) -> Result<StoreAdminClient, tonic::transport::Error> {
        let admin_url = match &self.url {
            Some(u) => u.clone(),
            None => Uri::from_static("https://bigtableadmin.googleapis.com"),
        };
        info!(
            inst = self.instance,
            project = self.project,
             %admin_url,
            "Connecting to Bigtable Admin"
        );
        let instance = Instance {
            project: self.project.clone(),
            instance: self.instance.clone(),
        };
        let options = GrpcConnectionOptions {
            timeout: self.timeout,
            connect_timeout: self.connect_timeout,
            http2_keepalive_interval: self.http2_keepalive_interval,
            http2_keepalive_timeout: self.http2_keepalive_timeout,
            http2_keepalive_while_idle: self.http2_keepalive_while_idle,
        };
        StoreAdminClient::new(admin_url.clone(), instance, auth_manager, options, metrics).await
    }

    pub fn add_to_cmd(&self, cmd: &mut Command) {
        cmd.arg("--bigtable-instance")
            .arg(&self.instance)
            .arg("--bigtable-project")
            .arg(&self.project);
        if let Some(u) = &self.url {
            cmd.arg("--bigtable-url").arg(u.to_string());
        }
    }
}

#[derive(Clone)]
pub struct StoreAdminClient {
    bigtable: BigtableTableAdminClient,
    instance: Instance,
}

impl fmt::Debug for StoreAdminClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreAdminClient")
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

impl StoreAdminClient {
    pub async fn new(
        url: Uri,
        instance: Instance,
        auth_manager: AuthManager,
        options: GrpcConnectionOptions,
        metrics: metrics::Client,
    ) -> Result<Self, tonic::transport::Error> {
        let bigtable = new_admin_client(url, auth_manager, options, metrics).await?;
        Ok(Self { bigtable, instance })
    }

    pub async fn initialize_shared_tables(&self) -> Result<(), tonic::Status> {
        let mut bigtable = self.bigtable.clone();
        discovery::initialize(&mut bigtable, &self.instance).await?;
        lease::initialize(&mut bigtable, &self.instance).await?;
        tenant_config::initialize(&mut bigtable, &self.instance).await
    }

    pub async fn initialize_realm(&self, realm: &RealmId) -> Result<(), tonic::Status> {
        let mut bigtable = self.bigtable.clone();
        merkle::initialize(&mut bigtable, &self.instance, realm).await?;
        log::initialize(&mut bigtable, &self.instance, realm).await?;
        tenants::initialize(&mut bigtable, &self.instance, realm).await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct StoreClient(Arc<StoreClientInner>);

struct StoreClientInner {
    // https://cloud.google.com/bigtable/docs/reference/data/rpc/google.bigtable.v2
    bigtable: BigtableClient,
    instance: Instance,
    last_write: Mutex<LastWriteCache>,
    metrics: metrics::Client,
    merkle_cache: merkle::Cache,
    merkle_ids: InstanceIds,
    merkle_delete_queue: MerkleDeleteQueue,
    merkle_large_read_permits: Semaphore,
    merkle_large_read_limit: usize,
    warmer: TablesReadWarmer,
}

#[derive(Clone)]
struct StoreClientMerkleDeleter {
    bigtable: BigtableClient,
    instance: Instance,
    metrics: metrics::Client,
    merkle_cache: merkle::Cache,
}

// Invariant: the log entry has been written at the end of a log row.
type LastWriteCache = HashMap<(RealmId, GroupId), (LogIndex, EntryMac)>;

impl fmt::Debug for StoreClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreClient")
            .field("instance", &self.0.instance)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppendError {
    #[error("error writing Merkle nodes: {0}")]
    MerkleWrites(RetryError<MutateRowsError>),
    #[error("error writing log entry: {0}")]
    LogWrite(RetryError<tonic::Status>),
    #[error("error checking log state: {0}")]
    UnknownLogState(ReadLastLogEntryError),
    #[error("log precondition not met")]
    LogPrecondition,
}

impl AppendError {
    pub fn is_no_store(&self) -> bool {
        matches!(
            self,
            Self::MerkleWrites(RetryError::Exhausted { .. })
                | Self::LogWrite(RetryError::Exhausted { .. })
                | Self::UnknownLogState(RetryError::Exhausted { .. })
        )
    }
}

pub struct Options {
    pub metrics: metrics::Client,

    /// The maximum size of the agent's LRU Merkle tree cache, in number of
    /// nodes. This is unused for non-agents, since only agents access Merkle
    /// trees.
    ///
    /// Set this to at least the expected number of concurrent requests times
    /// the depth of the Merkle tree(s). For example, if you have a Merkle tree
    /// with 1 million records, its depth (base-2 logarithm) is about 20. If
    /// you expect 1000 concurrent requests, you should set this limit to be
    /// greater than 20,000.
    ///
    /// If unset, this will basically disable the cache (but the cache
    /// implementation insists on a limit of at least 1 entry).
    pub merkle_cache_nodes_limit: Option<usize>,

    /// The maximum number of concurrent reads of "large" merkle paths. This
    /// stops the store from overwhelming bigtable with read requests while our
    /// merkle cache is cold. Once the top of the tree is cached most reads will
    /// only read a few nodes from the bottom of the tree which is cheap.
    ///
    /// This may need to be tuned based on the number of HSMs in the cluster and
    /// the number of bigtable nodes.
    pub merkle_large_read_permits: usize,

    /// The number of key prefixes in a merkle path read for it to be considered
    /// a large read. Because the bottom of the tree is sparsely populated this
    /// value will be relatively high.
    ///
    /// This may need tuning if the size of the tree changes dramatically.
    pub merkle_large_read_limit: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            metrics: metrics::Client::NONE,
            merkle_cache_nodes_limit: None,
            merkle_large_read_limit: 246,
            merkle_large_read_permits: 10,
        }
    }
}

impl StoreClient {
    pub async fn new(
        url: Uri,
        instance: Instance,
        auth_manager: AuthManager,
        options: Options,
        conn_options: GrpcConnectionOptions,
    ) -> Result<Self, tonic::transport::Error> {
        let warmer = TablesReadWarmer::new();
        let bigtable = new_data_client(
            instance.clone(),
            url,
            auth_manager,
            conn_options,
            options.metrics.clone(),
            warmer.clone(),
        )
        .await?;

        let cache = merkle::Cache::new(options.merkle_cache_nodes_limit.unwrap_or(1));
        let deleter = StoreClientMerkleDeleter {
            bigtable: bigtable.clone(),
            instance: instance.clone(),
            metrics: options.metrics.clone(),
            merkle_cache: cache.clone(),
        };
        let res = Self(Arc::new(StoreClientInner {
            bigtable,
            instance,
            last_write: Mutex::new(HashMap::new()),
            metrics: options.metrics.clone(),
            merkle_cache: cache,
            merkle_ids: InstanceIds::new(),
            merkle_delete_queue: MerkleDeleteQueue::new(options.metrics, move |dks| {
                let deleter = deleter.clone();
                async move {
                    let _ = deleter.remove_merkle_nodes(dks).await;
                }
            }),
            merkle_large_read_permits: Semaphore::new(options.merkle_large_read_permits),
            merkle_large_read_limit: options.merkle_large_read_limit,
            warmer,
        }));
        Ok(res)
    }

    #[instrument(
        level = "trace",
        name = "append_log_entries_and_update_merkle_tree",
        skip(self, entries, delta)
    )]
    pub async fn append(
        &self,
        realm: &RealmId,
        group: &GroupId,
        entries: &[LogEntry],
        delta: StoreDelta<DataHash>,
    ) -> Result<LogRow, AppendError> {
        let (row, _handle) = self
            .append_inner(realm, group, entries, delta, sleep(Duration::from_secs(5)))
            .await?;
        Ok(row)
    }

    // Helper for `append` that's broken out for testing. Returns the join
    // handle of the delete task if one was started.
    pub async fn append_inner<F: Future + Send + 'static>(
        &self,
        realm: &RealmId,
        group: &GroupId,
        entries: &[LogEntry],
        delta: StoreDelta<DataHash>,
        delete_waiter: F,
    ) -> Result<(LogRow, Option<oneshot::Receiver<()>>), AppendError> {
        assert!(
            !entries.is_empty(),
            "append passed empty list of things to append."
        );
        trace!(
            realm = ?realm,
            group = ?group,
            first_index = ?entries[0].index,
            entries = entries.len(),
            merkle_nodes_new = delta.adds().len(),
            merkle_nodes_remove = delta.removes().len(),
            "append starting",
        );
        let start = Instant::now();

        // The first entry in the log (index 1) must have a previous MAC of
        // zero. For subsequent entries, make sure the previous log entry
        // exists at the end of a log row and matches the expected value.
        match entries[0].index.prev() {
            None => {
                assert_eq!(
                    entries[0].prev_mac,
                    EntryMac::zero(),
                    "previous entry MAC for the first log entry must be zero"
                );
            }
            Some(prev_index) => {
                self.check_previous_entry(realm, group, prev_index, &entries[0].prev_mac)
                    .await?;
            }
        }

        // Make sure the batch of entries internally have the expected indexes
        // and MACs.
        let mut prev = &entries[0];
        for e in &entries[1..] {
            assert_eq!(e.index, prev.index.next());
            assert_eq!(e.prev_mac, prev.entry_mac);
            prev = e;
        }

        // Write new Merkle nodes.
        self.write_merkle_nodes(realm, group, delta.adds())
            .await
            .map_err(AppendError::MerkleWrites)?;

        // Append the new entries but only if no other writer has appended.
        let append_start = Instant::now();
        let mut bigtable = self.0.bigtable.clone();
        let appended_row = self
            .log_append(&mut bigtable, realm, group, entries)
            .await?;
        self.0.metrics.timing(
            "store_client.append_log.time",
            append_start.elapsed(),
            [tag!(?realm), tag!(?group)],
        );

        // append is supposed to be called sequentially, so this isn't racy.
        // Even if it's not called sequentially, last_write is purely a
        // performance improvement (it can save a log read); it's not a
        // correctness thing. The code above that uses last_write to check the
        // MAC chain will fall back to reading the log entry from the store if
        // the last_write info doesn't apply to that append.
        {
            let last = entries.last().unwrap();
            let mut locked = self.0.last_write.lock().unwrap();
            locked.insert((*realm, *group), (last.index, last.entry_mac.clone()));
        }

        // Delete obsolete Merkle nodes. These deletes are deferred a bit so
        // that slow concurrent readers can still access them.
        let delete_handle = if !delta.removes().is_empty() {
            let deletes = DeleteKeySet {
                realm: *realm,
                keys: delta.into_inner().1,
            };
            let handle = self
                .0
                .merkle_delete_queue
                .queue(
                    async {
                        delete_waiter.await;
                        deletes
                    }
                    .boxed(),
                )
                .await
                .expect("delete queue unexpectedly shutdown");
            Some(handle)
        } else {
            None
        };

        let dur = start.elapsed();
        self.0.metrics.timing(
            "store_client.append_inner.time",
            dur,
            [tag!(?realm), tag!(?group)],
        );
        trace!(
            realm = ?realm,
            group = ?group,
            ?dur,
            entries = entries.len(),
            "append succeeded"
        );
        Ok((appended_row, delete_handle))
    }

    /// Used in [`append_inner`]. Makes sure the previous log entry exists at
    /// the end of a log row and matches the expected value.
    async fn check_previous_entry(
        &self,
        realm: &RealmId,
        group: &GroupId,
        prev_index: LogIndex,
        prev_mac: &EntryMac,
    ) -> Result<(), AppendError> {
        assert!(prev_index >= LogIndex::FIRST);

        // Check `last_write` cache.
        {
            let locked = self.0.last_write.lock().unwrap();
            if let Some((last_index, last_mac)) = locked.get(&(*realm, *group)) {
                if *last_index == prev_index {
                    // Cache hit.
                    if last_mac == prev_mac {
                        return Ok(());
                    } else {
                        return Err(AppendError::LogPrecondition);
                    }
                }
            }
        }

        // Cache miss, so fetch the last log entry from Bigtable. Later, when
        // this log append succeeds, it'll update the `last_write` cache for
        // next time.
        match self.read_last_log_entry(realm, group).await {
            Ok(prev) => {
                if prev.index == prev_index && prev.entry_mac == *prev_mac {
                    Ok(())
                } else {
                    Err(AppendError::LogPrecondition)
                }
            }
            Err(RetryError::Fatal {
                error: ReadLastLogEntryFatal::EmptyLog,
            }) => {
                // prev_index >= 1, so the log shouldn't be empty.
                Err(AppendError::LogPrecondition)
            }
            Err(err) => Err(AppendError::UnknownLogState(err)),
        }
    }

    pub async fn shutdown_delete_queue(&self) {
        match self.0.merkle_delete_queue.shutdown().await {
            Ok(handle) => {
                info!("starting graceful shutdown of the merkle delete queue");
                if let Err(e) = handle.await {
                    warn!(err=?e, "error waiting for merkle delete queue shutdown");
                }
            }
            Err(_) => {
                warn!("shutdown_delete_queue called, but already shutdown");
            }
        }
    }
}

#[derive(Clone)]
struct TablesReadWarmer(Arc<Mutex<HashSet<RealmId>>>);

impl TablesReadWarmer {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(HashSet::new())))
    }

    fn add(&self, realm: RealmId) {
        self.0.lock().unwrap().insert(realm);
    }
}

impl ConnWarmer for TablesReadWarmer {
    async fn warm(&self, inst: Instance, mut conn: BtClient<AuthMiddleware>) {
        let r = conn
            .ping_and_warm(PingAndWarmRequest {
                name: inst.path(),
                app_profile_id: String::from(""),
            })
            .await;
        debug!(?r, "ping_and_warm result");

        let mut tables: Vec<String> = {
            let locked = self.0.lock().unwrap();
            locked
                .iter()
                .flat_map(|realm| {
                    [
                        log::log_table(&inst, realm),
                        merkle::merkle_table(&inst, realm),
                        tenants::tenant_user_table(&inst, realm),
                    ]
                })
                .collect()
        };
        tables.push(discovery::discovery_table(&inst));
        tables.push(lease::lease_table(&inst));
        for table in tables {
            if let Err(err) = Reader::read_rows(
                &mut conn,
                Retry::new("warmup read request")
                    .with_max_attempts(1)
                    .with_timeout(Duration::from_secs(5)),
                ReadRowsRequest {
                    table_name: table.clone(),
                    app_profile_id: String::from(""),
                    rows: None,
                    filter: None,
                    rows_limit: 1,
                    request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone
                        .into(),
                    reversed: false,
                },
            )
            .await
            {
                warn!(?err, ?table, "warmup read request failed for table");
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ServiceKind {
    Agent,
    LoadBalancer,
    ClusterManager,
}

impl StoreClient {
    #[instrument(level = "trace", skip(self))]
    pub async fn get_addresses(
        &self,
        kind: Option<ServiceKind>,
    ) -> Result<Vec<(Url, ServiceKind)>, RetryError<tonic::Status>> {
        discovery::get_addresses(
            self.0.bigtable.clone(),
            &self.0.instance,
            kind,
            self.0.metrics.clone(),
        )
        .await
    }

    #[instrument(level = "trace", skip(self, address), fields(address = %address))]
    pub async fn set_address(
        &self,
        address: &Url,
        kind: ServiceKind,
        // timestamp of the registration, typically SystemTime::now()
        timestamp: SystemTime,
    ) -> Result<(), RetryError<tonic::Status>> {
        discovery::set_address(
            &self.0.bigtable,
            &self.0.instance,
            address,
            kind,
            timestamp,
            self.0.metrics.clone(),
        )
        .await
    }

    // Obtain a lease for the specified duration. Only one lease is available at
    // any one time for a given key. Owner is recorded in the lease table only
    // for diagnostic purposes.
    pub async fn obtain_lease(
        &self,
        key: impl Into<LeaseKey>,
        owner: String,
        dur: Duration,
        timestamp: SystemTime,
    ) -> Result<Option<Lease>, RetryError<tonic::Status>> {
        lease::obtain(
            &self.0.bigtable,
            &self.0.instance,
            key.into(),
            owner,
            dur,
            timestamp,
            &self.0.metrics,
        )
        .await
    }

    pub async fn extend_lease(
        &self,
        lease: Lease,
        dur: Duration,
        timestamp: SystemTime,
    ) -> Result<Lease, RetryError<ExtendLeaseError, tonic::Status>> {
        lease::extend(
            &self.0.bigtable,
            &self.0.instance,
            lease,
            dur,
            timestamp,
            &self.0.metrics,
        )
        .await
    }

    pub async fn terminate_lease(&self, lease: Lease) -> Result<(), RetryError<tonic::Status>> {
        lease::terminate(&self.0.bigtable, &self.0.instance, lease, &self.0.metrics).await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExtendLeaseError {
    #[error("Tonic/gRPC error: {0}")]
    Rpc(tonic::Status),
    #[error("not lease owner")]
    NotOwner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseType {
    ClusterManagement,
}

pub struct LeaseKey(pub LeaseType, pub String);

impl LeaseKey {
    fn into_bigtable_key(self) -> Vec<u8> {
        let t = match self.0 {
            LeaseType::ClusterManagement => b"-cm",
        };
        let mut k = self.1.into_bytes();
        k.extend(t);
        k
    }
}

#[derive(Clone)]
pub struct Lease {
    key: Vec<u8>,
    id: Vec<u8>,
    owner: String,
    expires: u64, //Microseconds since EPOCH.
}

impl Lease {
    // The lease is held until this time.
    pub fn until(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_micros(self.expires)
    }
}

// Timestamps are in microseconds, but need to be rounded to milliseconds
// (or coarser depending on table schema).
pub(crate) fn to_micros(d: Duration) -> i64 {
    (d.as_millis() * 1000).try_into().unwrap()
}

/// This module should be used in unit/integration tests and non-critical
/// tooling only.
#[allow(dead_code)]
pub mod testing {
    use super::*;

    pub fn get_connection(client: &StoreClient) -> BigtableClient {
        client.0.bigtable.clone()
    }

    pub fn get_instance(client: &StoreClient) -> Instance {
        client.0.instance.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_key_into_bigtable_key() {
        let k = LeaseKey(LeaseType::ClusterManagement, "abc".to_string());
        assert_eq!(b"abc-cm".to_vec(), k.into_bigtable_key());
    }
}
