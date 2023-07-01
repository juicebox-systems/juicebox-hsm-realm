use crate::autogen::google;

use futures::Future;
use google::bigtable::admin::v2::table::TimestampGranularity;
use google::bigtable::admin::v2::{ColumnFamily, CreateTableRequest, GcRule, Table};
use google::bigtable::v2::column_range::{EndQualifier, StartQualifier};
use google::bigtable::v2::row_range::{EndKey::EndKeyClosed, StartKey::StartKeyClosed};
use google::bigtable::v2::{
    mutation, read_rows_request, row_filter::Filter, CheckAndMutateRowRequest, ColumnRange,
    Mutation, ReadRowsRequest, RowFilter, RowRange, RowSet,
};
use http::Uri;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Write;
use std::ops::Deref;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tonic::transport::Endpoint;
use tonic::Code;
use tracing::{info, instrument, trace, warn, Span};
use url::Url;

use crate::google_auth::AuthMiddleware;
use crate::metrics;
use crate::metrics_tag as tag;
use hsmcore::hsm::types::{DataHash, EntryMac, GroupId, HsmId, LogEntry, LogIndex};
use hsmcore::merkle::agent::StoreDelta;
use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_marshalling as marshalling;

pub mod discovery;
mod merkle;
mod mutate;
mod read;

use merkle::merkle_table_brief;
use mutate::{mutate_rows, MutateRowsError};
use read::{read_rows, Cell, RowKey};

type AuthManager = Option<Arc<gcp_auth::AuthenticationManager>>;
type BigtableTableAdminClient =
    google::bigtable::admin::v2::bigtable_table_admin_client::BigtableTableAdminClient<
        AuthMiddleware,
    >;
type BigtableClient = google::bigtable::v2::bigtable_client::BigtableClient<AuthMiddleware>;

#[derive(clap::Args, Clone, Debug)]
#[group(id = "BigtableArgs")]
pub struct Args {
    /// The name of the GCP project that contains the bigtable instance.
    #[arg(long = "bigtable-project", default_value = "prj")]
    pub project: String,

    /// The name of the bigtable instance to connect to.
    #[arg(long = "bigtable-instance", default_value = "instance")]
    pub instance: String,

    /// The url to the big table emulator [default uses GCP endpoints].
    #[arg(long = "bigtable-url")]
    pub url: Option<Uri>,
}

#[derive(clap::Args, Clone, Debug)]
#[group(id = "BigtableAgentArgs")]
pub struct AgentArgs {
    /// The maximum size of the agent's LRU Merkle tree cache, in number of
    /// nodes.
    #[arg(
        long = "merkle-cache-size",
        value_name = "NODES",
        default_value_t = 25_000
    )]
    pub merkle_cache_nodes_limit: usize,
}

impl AgentArgs {
    pub fn to_options(&self) -> Options {
        Options {
            merkle_cache_nodes_limit: Some(self.merkle_cache_nodes_limit),
            ..Options::default()
        }
    }
}

impl Args {
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
        StoreClient::new(data_url.clone(), instance, auth_manager, options).await
    }

    pub async fn connect_admin(
        &self,
        auth_manager: AuthManager,
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
        StoreAdminClient::new(admin_url.clone(), instance, auth_manager).await
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

#[derive(Clone, Debug)]
pub struct Instance {
    pub project: String,
    pub instance: String,
}

impl Instance {
    fn path(&self) -> String {
        format!(
            "projects/{project}/instances/{instance}",
            project = self.project,
            instance = self.instance,
        )
    }
}

fn log_table(instance: &Instance, realm: &RealmId) -> String {
    let mut buf = String::new();
    write!(
        buf,
        "projects/{project}/instances/{instance}/tables/",
        project = instance.project,
        instance = instance.instance
    )
    .unwrap();
    for byte in realm.0 {
        write!(buf, "{byte:02x}").unwrap();
    }
    write!(buf, "-log").unwrap();
    buf
}

fn log_table_brief(realm: &RealmId) -> String {
    let mut buf = String::new();
    for byte in realm.0 {
        write!(buf, "{byte:02x}").unwrap();
    }
    write!(buf, "-log").unwrap();
    buf
}

struct DownwardLogIndex(LogIndex);

impl DownwardLogIndex {
    fn bytes(&self) -> [u8; 8] {
        let index: LogIndex = self.0;
        let index: u64 = index.0;
        (u64::MAX - index).to_be_bytes()
    }
}

fn log_key(group: &GroupId, index: LogIndex) -> Vec<u8> {
    (group.0.iter())
        .chain(DownwardLogIndex(index).bytes().iter())
        .cloned()
        .collect()
}

#[derive(Clone)]
pub struct StoreAdminClient {
    // https://cloud.google.com/bigtable/docs/reference/admin/rpc/google.bigtable.admin.v2
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
    ) -> Result<Self, tonic::transport::Error> {
        let channel = Endpoint::from(url).connect().await?;
        let channel = AuthMiddleware::new(
            channel,
            auth_manager,
            &["https://www.googleapis.com/auth/bigtable.admin.table"],
        );
        let bigtable = BigtableTableAdminClient::new(channel);
        Ok(Self { bigtable, instance })
    }

    /// Creates a little Bigtable table for service discovery.
    pub async fn initialize_discovery(&self) -> Result<(), tonic::Status> {
        discovery::initialize(self.bigtable.clone(), &self.instance).await
    }

    pub async fn initialize_realm(&self, realm: &RealmId) -> Result<(), tonic::Status> {
        let mut bigtable = self.bigtable.clone();

        self.initialize_discovery().await?;

        // Create table for Merkle trees.
        bigtable
            .create_table(CreateTableRequest {
                parent: self.instance.path(),
                table_id: merkle_table_brief(realm),
                table: Some(Table {
                    name: String::from(""),
                    cluster_states: HashMap::new(),
                    column_families: HashMap::from([(
                        String::from("f"),
                        ColumnFamily {
                            gc_rule: Some(GcRule { rule: None }),
                        },
                    )]),
                    granularity: TimestampGranularity::Unspecified as i32,
                    restore_info: None,
                    deletion_protection: false,
                }),
                initial_splits: Vec::new(),
            })
            .await?;

        // Create table for logs.
        bigtable
            .create_table(CreateTableRequest {
                parent: self.instance.path(),
                table_id: log_table_brief(realm),
                table: Some(Table {
                    name: String::from(""),
                    cluster_states: HashMap::new(),
                    column_families: HashMap::from([(
                        String::from("f"),
                        ColumnFamily {
                            gc_rule: Some(GcRule { rule: None }),
                        },
                    )]),
                    granularity: TimestampGranularity::Unspecified as i32,
                    restore_info: None,
                    deletion_protection: false,
                }),
                initial_splits: Vec::new(),
            })
            .await?;

        Ok(())
    }
}

pub struct StoreClient {
    // https://cloud.google.com/bigtable/docs/reference/data/rpc/google.bigtable.v2
    bigtable: BigtableClient,
    instance: Instance,
    last_write: Mutex<Option<(RealmId, GroupId, LogIndex, EntryMac)>>,
    metrics: metrics::Client,
    merkle_cache: merkle::Cache,
}

impl Clone for StoreClient {
    fn clone(&self) -> Self {
        // StoreClient is cloned during append to handle the delayed merkle node delete.
        Self {
            bigtable: self.bigtable.clone(),
            instance: self.instance.clone(),
            last_write: Mutex::new(None),
            metrics: self.metrics.clone(),
            merkle_cache: self.merkle_cache.clone(),
        }
    }
}

impl fmt::Debug for StoreClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreClient")
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum AppendError {
    Grpc(tonic::Status),
    MerkleWrites(google::rpc::Status),
    LogPrecondition,
    MerkleDeletes(google::rpc::Status),
}

impl From<tonic::Status> for AppendError {
    fn from(value: tonic::Status) -> Self {
        AppendError::Grpc(value)
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
}

impl Default for Options {
    fn default() -> Self {
        Self {
            metrics: metrics::Client::NONE,
            merkle_cache_nodes_limit: None,
        }
    }
}

impl StoreClient {
    pub async fn new(
        url: Uri,
        instance: Instance,
        auth_manager: AuthManager,
        options: Options,
    ) -> Result<Self, tonic::transport::Error> {
        let channel = Endpoint::from(url).connect().await?;
        let channel = AuthMiddleware::new(
            channel,
            auth_manager,
            &["https://www.googleapis.com/auth/bigtable.data"],
        );
        let bigtable = BigtableClient::new(channel);
        Ok(Self {
            bigtable,
            instance,
            last_write: Mutex::new(None),
            metrics: options.metrics,
            merkle_cache: merkle::Cache::new(options.merkle_cache_nodes_limit.unwrap_or(1)),
        })
    }

    #[instrument(
        level = "trace",
        name = "append_log_entries_and_update_merkle_tree",
        skip(self)
    )]
    pub async fn append(
        &self,
        realm: &RealmId,
        group: &GroupId,
        entries: &[LogEntry],
        delta: StoreDelta<DataHash>,
    ) -> Result<(), AppendError> {
        self.append_inner(realm, group, entries, delta, sleep(Duration::from_secs(5)))
            .await?;
        Ok(())
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
    ) -> Result<Option<JoinHandle<()>>, AppendError> {
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

        // Make sure the previous log entry exists and matches the expected value.
        if entries[0].index != LogIndex::FIRST {
            let prev_index = entries[0].index.prev().unwrap();
            let read_log_entry = {
                let last_write = self.last_write.lock().unwrap();
                match last_write.deref() {
                    Some((last_realm, last_group, last_index, last_mac))
                        if last_realm == realm
                            && last_group == group
                            && *last_index == prev_index =>
                    {
                        if *last_mac != entries[0].prev_mac {
                            return Err(AppendError::LogPrecondition);
                        }
                        false
                    }
                    _ => true,
                }
            };
            if read_log_entry {
                if let Some(prev) = self
                    .read_log_entry(realm, group, prev_index)
                    .await
                    .expect("TODO")
                {
                    if prev.entry_mac != entries[0].prev_mac {
                        return Err(AppendError::LogPrecondition);
                    }
                } else {
                    return Err(AppendError::LogPrecondition);
                };
            }
        }

        // Make sure the batch of entries have the expected indexes & macs
        let mut prev = &entries[0];
        for e in &entries[1..] {
            assert_eq!(e.index, prev.index.next());
            assert_eq!(e.prev_mac, prev.entry_mac);
            prev = e;
        }

        // Write new Merkle nodes.
        self.write_merkle_nodes(realm, group, delta.adds())
            .await
            .map_err(|e| match e {
                MutateRowsError::Tonic(e) => AppendError::Grpc(e),
                MutateRowsError::Mutation(e) => AppendError::MerkleWrites(e),
            })?;

        // Append the new entries but only if no other writer has appended.
        let append_start = Instant::now();
        let mut bigtable = self.bigtable.clone();
        self.log_append(&mut bigtable, realm, group, entries)
            .await?;
        self.metrics.timing(
            "store_client.append_log.time",
            append_start.elapsed(),
            [tag!(?realm), tag!(?group)],
        );

        // append is supposed to be called sequentially, so this isn't racy.
        // Even if its not called sequentially last_write is purely a
        // performance improvement (it can save a log read), its not a
        // correctness thing. The code above that uses last_write to check the
        // mac chain will fallback to reading the log entry from the store if
        // the last_write info doesn't apply to that append.
        let last = entries.last().unwrap();
        *self.last_write.lock().unwrap() =
            Some((*realm, *group, last.index, last.entry_mac.clone()));

        // Delete obsolete Merkle nodes. These deletes are deferred a bit so
        // that slow concurrent readers can still access them.
        let delete_handle = if !delta.removes().is_empty() {
            let store = self.clone();
            let realm = *realm;
            let group = *group;
            Some(tokio::spawn(async move {
                delete_waiter.await;
                store
                    .remove_merkle_nodes(&realm, &group, delta.removes())
                    .await
                    .expect("TODO");
            }))
        } else {
            None
        };

        let dur = start.elapsed();
        self.metrics.timing(
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
        Ok(delete_handle)
    }

    /// Append a new batch of log entries, but only if the row doesn't yet
    /// exist.
    #[instrument(level = "trace", skip(self, bigtable, entries), fields(retries,num_entries = entries.len()))]
    async fn log_append(
        &self,
        bigtable: &mut BigtableClient,
        realm: &RealmId,
        group: &GroupId,
        entries: &[LogEntry],
    ) -> Result<(), AppendError> {
        const MAX_RETRIES: usize = 3;
        for retries in 0.. {
            Span::current().record("retries", retries);

            match bigtable
                .check_and_mutate_row(CheckAndMutateRowRequest {
                    table_name: log_table(&self.instance, realm),
                    app_profile_id: String::new(),
                    row_key: log_key(group, entries[0].index),
                    predicate_filter: None, // checks for any value
                    true_mutations: Vec::new(),
                    false_mutations: entries
                        .iter()
                        .map(|entry| Mutation {
                            mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                                family_name: String::from("f"),
                                column_qualifier: DownwardLogIndex(entry.index).bytes().to_vec(),
                                timestamp_micros: -1,
                                value: marshalling::to_vec(entry).expect("TODO"),
                            })),
                        })
                        .collect(),
                })
                .await
            {
                Err(status) if status.code() == Code::Unknown => {
                    // Disconnect errors get bundled under Unknown. We need to
                    // determine the current state of the row in bigtable before
                    // attempting a retry, otherwise we can trip the log
                    // precondition check unintentionally.
                    warn!(?realm, ?group, ?status, "error while appending log entry");
                    self.metrics.incr(
                        "store_client.log_append.unknown_error",
                        [tag!(?realm), tag!(?group)],
                    );

                    match self.read_last_log_entry(realm, group).await? {
                        Some(entry) if entry.index < entries[0].index => {
                            // Latest log entry is before the first one we're trying to write.
                            // The row wasn't written and we can retry that.
                            info!(
                                ?realm,
                                ?group,
                                "GRPC Unknown error and it appears the log entry wasn't written"
                            );
                        }
                        Some(entry) if &entry == entries.last().unwrap() => {
                            // Latest log entry matches the last log entry we were writing.
                            // The write succeeded.
                            info!(
                                ?realm,
                                ?group,
                                "GRPC Unknown error and it appears the log entry was written"
                            );
                            return Ok(());
                        }
                        Some(_) => {
                            // Latest log entry does not match anything we're expecting. It must have
                            // been written by another leader.
                            info!(
                                ?realm,
                                ?group,
                                "GRPC Unknown error and it appears the log entry was written by someone else"
                            );
                            return Err(AppendError::LogPrecondition);
                        }
                        None => {
                            // No long entry at all, safe to retry.
                            info!(
                                ?realm,
                                ?group,
                                "GRPC Unknown error and the log appears empty"
                            );
                        }
                    }
                    if retries >= MAX_RETRIES {
                        return Err(AppendError::Grpc(status));
                    }
                }
                Err(status) => return Err(AppendError::Grpc(status)),
                Ok(append_response) => {
                    if append_response.into_inner().predicate_matched {
                        return Err(AppendError::LogPrecondition);
                    }
                    return Ok(());
                }
            }
        }
        unreachable!()
    }

    #[instrument(level = "trace", skip(self))]
    pub async fn read_log_entry(
        &self,
        realm: &RealmId,
        group: &GroupId,
        index: LogIndex,
    ) -> Result<Option<LogEntry>, tonic::Status> {
        let rows = read_rows(
            &mut self.bigtable.clone(),
            ReadRowsRequest {
                table_name: log_table(&self.instance, realm),
                app_profile_id: String::new(),
                rows: Some(RowSet {
                    row_keys: Vec::new(),
                    row_ranges: vec![RowRange {
                        start_key: Some(StartKeyClosed(log_key(group, index))),
                        end_key: Some(EndKeyClosed(log_key(group, LogIndex::FIRST))),
                    }],
                }),
                filter: Some(RowFilter {
                    filter: Some(Filter::ColumnRangeFilter(ColumnRange {
                        family_name: String::from("f"),
                        start_qualifier: Some(StartQualifier::StartQualifierClosed(
                            DownwardLogIndex(index).bytes().to_vec(),
                        )),
                        end_qualifier: Some(EndQualifier::EndQualifierClosed(
                            DownwardLogIndex(index).bytes().to_vec(),
                        )),
                    })),
                }),
                rows_limit: 1,
                request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            },
        )
        .await?;

        let entry: Option<LogEntry> = rows.into_iter().next().and_then(|(_key, cells)| {
            cells
                .into_iter()
                .find(|cell| cell.family == "f")
                .map(|cell| marshalling::from_slice(&cell.value).expect("TODO"))
        });
        if let Some(e) = &entry {
            assert_eq!(e.index, index);
        }
        trace!(
            realm = ?realm,
            group = ?group,
            index = ?index,
            entry = ?entry,
            "read_log_entry completed",
        );
        Ok(entry)
    }

    #[instrument(level = "trace", skip(self))]
    pub async fn read_last_log_entry(
        &self,
        realm: &RealmId,
        group: &GroupId,
    ) -> Result<Option<LogEntry>, tonic::Status> {
        trace!(?realm, ?group, "read_last_log_entry starting");
        let start = Instant::now();

        let rows = read_rows(
            &mut self.bigtable.clone(),
            ReadRowsRequest {
                table_name: log_table(&self.instance, realm),
                app_profile_id: String::new(),
                rows: Some(RowSet {
                    row_keys: Vec::new(),
                    row_ranges: vec![RowRange {
                        start_key: Some(StartKeyClosed(log_key(group, LogIndex(u64::MAX)))),
                        end_key: Some(EndKeyClosed(log_key(group, LogIndex::FIRST))),
                    }],
                }),
                filter: Some(RowFilter {
                    filter: Some(Filter::CellsPerRowLimitFilter(1)),
                }),
                rows_limit: 1,
                request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            },
        )
        .await?;

        let entry = rows.into_iter().next().and_then(|(_key, cells)| {
            cells
                .into_iter()
                .find(|cell| cell.family == "f")
                .map(|cell| marshalling::from_slice(&cell.value).expect("TODO"))
        });

        self.metrics.timing(
            "store_client.read_last_log_entry.time",
            start.elapsed(),
            [tag!(?realm), tag!(?group)],
        );
        trace!(?realm, ?group, ?entry, "read_last_log_entry completed");
        Ok(entry)
    }

    /// Returns an Iterator style object that can read the log starting from the supplied
    /// log index. max_entries indicates how large of a chunk to return. However due to the
    /// variable batch size when appending you may get up to MAX_BATCH_SIZE-1
    /// entries more returned than max_entries.
    pub fn read_log_entries_iter(
        &self,
        realm: RealmId,
        group: GroupId,
        starting_at: LogIndex,
        max_entries: u16,
    ) -> LogEntriesIter {
        assert!(max_entries > 0);
        let table_name = log_table(&self.instance, &realm);
        LogEntriesIter {
            realm,
            group,
            next: Position::LogIndex(starting_at),
            max_entries: max_entries as u64,
            client: self.clone(),
            table_name,
        }
    }
}

enum Position {
    // A log index, that may or may not be the first log index in a row.
    LogIndex(LogIndex),
    // A log index that is known to be the first log index in a row.
    RowBoundary(LogIndex),
}

pub struct LogEntriesIter {
    realm: RealmId,
    group: GroupId,
    next: Position,
    max_entries: u64,
    client: StoreClient,
    table_name: String,
}

impl LogEntriesIter {
    /// Read the next chunk of log entries from the log. The returned Log
    /// Entries are in increasing log index order. returns an empty Vec if
    /// there's nothing new in the log since the last call to next.
    #[instrument(level = "trace", name = "LogEntriesIter::next", skip(self))]
    pub async fn next(&mut self) -> Result<Vec<LogEntry>, tonic::Status> {
        let rows = match self.next {
            Position::LogIndex(i) => self.read_for_log_index(i).await?,
            Position::RowBoundary(i) => self.read_for_row_boundary(i).await?,
        };

        let entries: Vec<LogEntry> = rows
            .into_iter()
            .rev()
            .flat_map(|(_rowkey, cells)| {
                cells
                    .into_iter()
                    .rev()
                    .filter(|c| c.family == "f")
                    .map(|c| marshalling::from_slice(&c.value).expect("TODO"))
            })
            .collect();

        let index = match self.next {
            Position::LogIndex(i) => i,
            Position::RowBoundary(i) => i,
        };
        if !entries.is_empty() {
            assert_eq!(entries[0].index, index);
            assert!(entries
                .as_slice()
                .windows(2)
                .all(|w| w[1].index == w[0].index.next()));
            self.next = Position::RowBoundary(entries.last().unwrap().index.next());
        }

        trace!(
            realm = ?self.realm,
            group = ?self.group,
            index = ?index,
            entries = ?entries.len(),
            "read_log_entries::next completed",
        );
        Ok(entries)
    }

    async fn read_for_log_index(
        &self,
        index: LogIndex,
    ) -> Result<Vec<(RowKey, Vec<Cell>)>, tonic::Status> {
        read_rows(
            &mut self.client.bigtable.clone(),
            ReadRowsRequest {
                table_name: self.table_name.clone(),
                app_profile_id: String::new(),
                rows: Some(RowSet {
                    row_keys: Vec::new(),
                    row_ranges: vec![RowRange {
                        start_key: Some(StartKeyClosed(log_key(&self.group, index))),
                        end_key: Some(EndKeyClosed(log_key(&self.group, LogIndex::FIRST))),
                    }],
                }),
                filter: Some(RowFilter {
                    filter: Some(Filter::ColumnRangeFilter(ColumnRange {
                        family_name: String::from("f"),
                        start_qualifier: None,
                        end_qualifier: Some(EndQualifier::EndQualifierClosed(
                            DownwardLogIndex(index).bytes().to_vec(),
                        )),
                    })),
                }),
                rows_limit: 1,
                request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            },
        )
        .await
    }

    async fn read_for_row_boundary(
        &self,
        index: LogIndex,
    ) -> Result<Vec<(RowKey, Vec<Cell>)>, tonic::Status> {
        read_rows(
            &mut self.client.bigtable.clone(),
            ReadRowsRequest {
                table_name: self.table_name.clone(),
                app_profile_id: String::new(),
                rows: Some(RowSet {
                    row_keys: Vec::new(),
                    row_ranges: vec![RowRange {
                        start_key: Some(StartKeyClosed(log_key(
                            &self.group,
                            LogIndex(index.0.saturating_add(self.max_entries - 1)),
                        ))),
                        end_key: Some(EndKeyClosed(log_key(&self.group, index))),
                    }],
                }),
                filter: Some(RowFilter {
                    filter: Some(Filter::ColumnRangeFilter(ColumnRange {
                        family_name: String::from("f"),
                        start_qualifier: None,
                        end_qualifier: Some(EndQualifier::EndQualifierClosed(
                            DownwardLogIndex(index).bytes().to_vec(),
                        )),
                    })),
                }),
                rows_limit: 0,
                request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            },
        )
        .await
    }
}

impl StoreClient {
    #[instrument(level = "trace", skip(self))]
    pub async fn get_addresses(&self) -> Result<Vec<(HsmId, Url)>, tonic::Status> {
        discovery::get_addresses(self.bigtable.clone(), &self.instance).await
    }

    #[instrument(level = "trace", skip(self, address), fields(address = %address))]
    pub async fn set_address(
        &self,
        hsm: &HsmId,
        address: &Url,
        // timestamp of the registration, typically SystemTime::now()
        timestamp: SystemTime,
    ) -> Result<(), tonic::Status> {
        discovery::set_address(
            self.bigtable.clone(),
            &self.instance,
            hsm,
            address,
            timestamp,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM1: RealmId = RealmId([
        0x66, 0x80, 0x13, 0x4b, 0xf4, 0x5d, 0xc9, 0x3f, 0xce, 0xee, 0xcd, 0x03, 0xe5, 0x38, 0xc8,
        0x9f,
    ]);

    const GROUP1: GroupId = GroupId([
        0x0d, 0xbb, 0x03, 0x61, 0xb0, 0xc3, 0x23, 0xdd, 0xeb, 0xa3, 0x4f, 0x4d, 0x02, 0x3a, 0xbb,
        0x53,
    ]);

    #[test]
    fn test_log_table() {
        let instance = Instance {
            project: String::from("prj1"),
            instance: String::from("inst2"),
        };
        let expected = "projects/prj1/instances/inst2/tables/6680134bf45dc93fceeecd03e538c89f-log";
        assert_eq!(log_table(&instance, &REALM1), expected);
        assert_eq!(
            format!("{}/tables/{}", instance.path(), log_table_brief(&REALM1)),
            expected
        );
    }

    #[test]
    fn test_downward_logindex() {
        assert_eq!(
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe],
            DownwardLogIndex(LogIndex(1)).bytes()
        );
        assert_eq!(
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd],
            DownwardLogIndex(LogIndex(2)).bytes()
        );
    }

    #[test]
    fn test_log_key() {
        assert_eq!(
            log_key(&GROUP1, LogIndex(12943236441930260757)),
            vec![
                0x0d, 0xbb, 0x03, 0x61, 0xb0, 0xc3, 0x23, 0xdd, 0xeb, 0xa3, 0x4f, 0x4d, 0x02, 0x3a,
                0xbb, 0x53, 0x4c, 0x60, 0x63, 0x08, 0x42, 0xdb, 0x1e, 0xea
            ]
        );
    }
}
