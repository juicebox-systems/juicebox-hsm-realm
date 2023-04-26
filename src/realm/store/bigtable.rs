use async_trait::async_trait;
use futures::Future;
use google::bigtable::admin::v2::table::TimestampGranularity;
use google::bigtable::admin::v2::{ColumnFamily, CreateTableRequest, GcRule, Table};
use google::bigtable::v2::column_range::{EndQualifier, StartQualifier};
use google::bigtable::v2::row_range::{
    EndKey::EndKeyClosed, EndKey::EndKeyOpen, StartKey::StartKeyClosed,
};
use google::bigtable::v2::{
    mutate_rows_request, mutation, read_rows_request, row_filter, row_filter::Filter,
    CheckAndMutateRowRequest, ColumnRange, MutateRowRequest, MutateRowResponse, MutateRowsRequest,
    Mutation, ReadRowsRequest, RowFilter, RowRange, RowSet,
};
use http::Uri;
use loam_sdk_core::marshalling;
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
use tracing::{debug, info, instrument, trace, warn};
use url::Url;

mod mutate;
mod read;

use super::super::merkle::agent::TreeStoreReader;
use crate::autogen::google;
use crate::google_auth::AuthMiddleware;
use hsmcore::hsm::types::{DataHash, EntryHmac, GroupId, HsmId, LogEntry, LogIndex, RecordId};
use hsmcore::merkle::agent::{all_store_key_starts, Node, StoreDelta, StoreKey, TreeStoreError};
use loam_sdk_core::types::RealmId;
use mutate::{mutate_rows, MutateRowsError};
use read::{read_rows, Cell, RowKey};

type AuthManager = Option<Arc<gcp_auth::AuthenticationManager>>;
type BigtableTableAdminClient =
    google::bigtable::admin::v2::bigtable_table_admin_client::BigtableTableAdminClient<
        AuthMiddleware,
    >;
type BigtableClient = google::bigtable::v2::bigtable_client::BigtableClient<AuthMiddleware>;

/// Agents should register themselves with service discovery this often.
pub const DISCOVERY_REGISTER_INTERVAL: Duration = Duration::from_secs(60 * 10);

/// Discovery records that haven't been updated in at least this log will be expired and deleted.
pub const DISCOVERY_EXPIRY_AGE: Duration = Duration::from_secs(60 * 21);

#[derive(clap::Args, Clone, Debug)]
pub struct BigTableArgs {
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

impl BigTableArgs {
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
        StoreClient::new(data_url.clone(), instance, auth_manager).await
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

fn merkle_table(instance: &Instance, realm: &RealmId) -> String {
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
    write!(buf, "-merkle").unwrap();
    buf
}

fn merkle_table_brief(realm: &RealmId) -> String {
    let mut buf = String::new();
    for byte in realm.0 {
        write!(buf, "{byte:02x}").unwrap();
    }
    write!(buf, "-merkle").unwrap();
    buf
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

fn discovery_table(instance: &Instance) -> String {
    format!(
        "projects/{project}/instances/{instance}/tables/discovery",
        project = instance.project,
        instance = instance.instance
    )
}

fn discovery_table_brief() -> String {
    String::from("discovery")
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
        // This is not realm-specific, so it might already exist.
        if let Err(e) = self
            .bigtable
            .clone()
            .create_table(CreateTableRequest {
                parent: self.instance.path(),
                table_id: discovery_table_brief(),
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
            .await
        {
            if e.code() != tonic::Code::AlreadyExists {
                return Err(e);
            }
        }
        Ok(())
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
    last_write: Mutex<Option<(RealmId, GroupId, LogIndex, EntryHmac)>>,
}

impl Clone for StoreClient {
    fn clone(&self) -> Self {
        // StoreClient is cloned during append to handle the delayed merkle node delete.
        Self {
            bigtable: self.bigtable.clone(),
            instance: self.instance.clone(),
            last_write: Mutex::new(None),
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

impl StoreClient {
    pub async fn new(
        url: Uri,
        instance: Instance,
        auth_manager: AuthManager,
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
        })
    }

    #[instrument(level = "trace", skip(self))]
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

    // broken out for testing. Returns the join handle of the delete task if one was started.
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
            merkle_nodes_new = delta.add.len(),
            merkle_nodes_remove = delta.remove.len(),
            "append starting",
        );
        let start = Instant::now();

        // Make sure the previous log entry exists and matches the expected value.
        if entries[0].index != LogIndex::FIRST {
            let prev_index = entries[0].index.prev().unwrap();
            let read_log_entry = {
                let last_write = self.last_write.lock().unwrap();
                match last_write.deref() {
                    Some((last_realm, last_group, last_index, last_hmac))
                        if last_realm == realm
                            && last_group == group
                            && *last_index == prev_index =>
                    {
                        if *last_hmac != entries[0].prev_hmac {
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
                    if prev.entry_hmac != entries[0].prev_hmac {
                        return Err(AppendError::LogPrecondition);
                    }
                } else {
                    return Err(AppendError::LogPrecondition);
                };
            }
        }

        // Make sure the batch of entries have the expected indexes & hmacs
        let mut prev = &entries[0];
        for e in &entries[1..] {
            assert_eq!(e.index, prev.index.next());
            assert_eq!(e.prev_hmac, prev.entry_hmac);
            prev = e;
        }

        let mut bigtable = self.bigtable.clone();

        // Write new Merkle nodes.
        let new_merkle_entries = delta
            .add
            .iter()
            .map(|(key, value)| mutate_rows_request::Entry {
                row_key: key.store_key().into_bytes(),
                mutations: vec![Mutation {
                    mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                        family_name: String::from("f"),
                        column_qualifier: b"n".to_vec(),
                        timestamp_micros: -1,
                        // TODO: unnecessarily wraps the leaf node values.
                        value: marshalling::to_vec(value).expect("TODO"),
                    })),
                }],
            })
            .collect::<Vec<_>>();

        if !new_merkle_entries.is_empty() {
            mutate_rows(
                &mut bigtable,
                MutateRowsRequest {
                    table_name: merkle_table(&self.instance, realm),
                    app_profile_id: String::new(),
                    entries: new_merkle_entries,
                },
            )
            .await
            .map_err(|e| match e {
                MutateRowsError::Tonic(e) => AppendError::Grpc(e),
                MutateRowsError::Mutation(e) => AppendError::MerkleWrites(e),
            })?;
        }

        // Append the new row but only if it doesn't yet exist.
        let append_response = bigtable
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
            .map_err(AppendError::Grpc)?
            .into_inner();
        if append_response.predicate_matched {
            return Err(AppendError::LogPrecondition);
        }

        // append is supposed to be called sequentially, so this isn't racy.
        // Even if its not called sequentially last_write is purely a
        // performance improvement (it can save a log read), its not a
        // correctness thing. The code above that uses last_write to check the
        // hmac chain will fallback to reading the log entry from the store if
        // the last_write info doesn't apply to that append.
        let last = entries.last().unwrap();
        *self.last_write.lock().unwrap() =
            Some((*realm, *group, last.index, last.entry_hmac.clone()));

        // Delete obsolete Merkle nodes. These deletes are deferred a bit so
        // that slow concurrent readers can still access them.
        let to_remove = delta
            .remove
            .iter()
            .map(|k| k.store_key())
            .collect::<Vec<_>>();

        let delete_handle = if !to_remove.is_empty() {
            let store = self.clone();
            let realm = *realm;
            Some(tokio::spawn(async move {
                delete_waiter.await;
                store.remove(&realm, to_remove).await.expect("TODO");
            }))
        } else {
            None
        };

        trace!(
            realm = ?realm,
            group = ?group,
            dur = ?start.elapsed(),
            entries = entries.len(),
            "append succeeded"
        );
        Ok(delete_handle)
    }

    #[instrument(level = "trace", skip(self))]
    async fn remove(
        &self,
        realm: &RealmId,
        to_remove: Vec<StoreKey>,
    ) -> Result<(), MutateRowsError> {
        let mut bigtable = self.bigtable.clone();
        mutate_rows(
            &mut bigtable,
            MutateRowsRequest {
                table_name: merkle_table(&self.instance, realm),
                app_profile_id: String::new(),
                entries: to_remove
                    .into_iter()
                    .map(|key| mutate_rows_request::Entry {
                        row_key: key.into_bytes(),
                        mutations: vec![Mutation {
                            mutation: Some(mutation::Mutation::DeleteFromRow(
                                mutation::DeleteFromRow {},
                            )),
                        }],
                    })
                    .collect(),
            },
        )
        .await
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
    #[instrument(level = "trace", skip(self))]
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
        let rows = read_rows(
            &mut self.bigtable.clone(),
            ReadRowsRequest {
                table_name: discovery_table(&self.instance),
                app_profile_id: String::new(),
                rows: None, // read all rows
                filter: Some(RowFilter {
                    filter: Some(row_filter::Filter::CellsPerColumnLimitFilter(1)),
                }),
                rows_limit: 0,
                request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            },
        )
        .await?;

        let mut addresses = Vec::with_capacity(rows.len());
        let mut expired = Vec::new();
        let expire_when_before = SystemTime::now() - DISCOVERY_EXPIRY_AGE;
        for (row_key, cells) in rows {
            for cell in cells {
                if cell.family == "f" && cell.qualifier == b"a" {
                    let written_at =
                        SystemTime::UNIX_EPOCH + Duration::from_micros(cell.timestamp as u64);
                    if written_at < expire_when_before {
                        expired.push(row_key.0.clone());
                    } else if let Some(url) = String::from_utf8(cell.value)
                        .ok()
                        .and_then(|url| Url::parse(&url).ok())
                    {
                        let mut hsm = HsmId([0u8; 16]);
                        hsm.0.copy_from_slice(&row_key.0);
                        addresses.push((hsm, url))
                    }
                }
            }
        }
        if !expired.is_empty() {
            let mut bigtable = self.bigtable.clone();
            let table = discovery_table(&self.instance);
            tokio::spawn(async move {
                let len = expired.len();
                let r = mutate_rows(
                    &mut bigtable,
                    MutateRowsRequest {
                        table_name: table,
                        app_profile_id: String::new(),
                        entries: expired
                            .into_iter()
                            .map(|key| mutate_rows_request::Entry {
                                row_key: key,
                                mutations: vec![Mutation {
                                    mutation: Some(mutation::Mutation::DeleteFromRow(
                                        mutation::DeleteFromRow {},
                                    )),
                                }],
                            })
                            .collect(),
                    },
                )
                .await;
                match r {
                    Err(e) => warn!(error = ?e, "failed to remove expired discovery entries"),
                    Ok(_) => debug!(num=?len, "removed expired discovery entries"),
                }
            });
        }

        trace!(
            num_addresses = addresses.len(),
            first_address = ?addresses
                .first()
                .map(|(hsm, url)| (hsm, url.as_str())),
            "get_addresses completed"
        );

        Ok(addresses)
    }

    #[instrument(level = "trace", skip(self, address), fields(address = %address))]
    pub async fn set_address(
        &self,
        hsm: &HsmId,
        address: &Url,
        // timestamp of the registration, typically SystemTime::now()
        timestamp: SystemTime,
    ) -> Result<(), tonic::Status> {
        trace!(?hsm, address = address.as_str(), "set_address starting");
        // Come back before April 11 2262 to fix this.
        let timestamp_micros = (timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            * 1000)
            .try_into()
            .unwrap(); // timestamps are in microseconds, but need to be rounded to milliseconds (or coarser depending on table schema).

        let MutateRowResponse { /* empty */ } = self
            .bigtable
            .clone()
            .mutate_row(MutateRowRequest {
                table_name: discovery_table(&self.instance),
                app_profile_id: String::new(),
                row_key: hsm.0.to_vec(),
                mutations: vec![Mutation {
                    mutation: Some(mutation::Mutation::DeleteFromColumn(mutation::DeleteFromColumn {
                        family_name: String::from("f"),
                        column_qualifier: b"a".to_vec(),
                        time_range:None,
                    })),
                },
                Mutation {
                    mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                        family_name: String::from("f"),
                        column_qualifier: b"a".to_vec(),
                        timestamp_micros,
                        value: address.as_str().as_bytes().to_vec(),
                    })),
                }],
            })
            .await?
            .into_inner();
        trace!(?hsm, address = address.as_str(), "set_address completed");
        Ok(())
    }
}

#[async_trait]
impl TreeStoreReader<DataHash> for StoreClient {
    #[instrument(level = "trace", skip(self))]
    async fn path_lookup(
        &self,
        realm: &RealmId,
        record_id: &RecordId,
    ) -> Result<HashMap<DataHash, Node<DataHash>>, TreeStoreError> {
        trace!(realm = ?realm, record = ?record_id, "path_lookup starting");

        let rows = read_rows(
            &mut self.bigtable.clone(),
            ReadRowsRequest {
                table_name: merkle_table(&self.instance, realm),
                app_profile_id: String::new(),
                rows: Some(RowSet {
                    row_keys: Vec::new(),
                    row_ranges: all_store_key_starts(record_id)
                        .into_iter()
                        .map(|prefix| RowRange {
                            end_key: Some(EndKeyOpen(prefix.next().into_bytes())),
                            start_key: Some(StartKeyClosed(prefix.into_bytes())),
                        })
                        .collect(),
                }),
                filter: Some(RowFilter {
                    filter: Some(row_filter::Filter::CellsPerColumnLimitFilter(1)),
                }),
                rows_limit: 0,
                request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            },
        )
        .await
        .map_err(|e| TreeStoreError::Network(e.to_string()))?;

        let nodes: HashMap<DataHash, Node<DataHash>> = rows
            .into_iter()
            .map(|(row_key, cells)| {
                let (_, hash) = StoreKey::parse(&row_key.0).unwrap();
                let node: Node<DataHash> = marshalling::from_slice(
                    &cells
                        .into_iter()
                        .find(|cell| cell.family == "f" && cell.qualifier == b"n")
                        .expect("every Merkle row should contain a node value")
                        .value,
                )
                .expect("TODO");
                (hash, node)
            })
            .collect();

        trace!(realm = ?realm, record = ?record_id, nodes = nodes.len(), "path_lookup completed");
        Ok(nodes)
    }

    #[instrument(level = "trace", skip(self))]
    async fn read_node(
        &self,
        realm: &RealmId,
        key: StoreKey,
    ) -> Result<Node<DataHash>, TreeStoreError> {
        trace!(realm = ?realm, key = ?key, "read_node starting");

        let rows = read_rows(
            &mut self.bigtable.clone(),
            ReadRowsRequest {
                table_name: merkle_table(&self.instance, realm),
                app_profile_id: String::new(),
                rows: Some(RowSet {
                    row_keys: vec![key.clone().into_bytes()],
                    row_ranges: Vec::new(),
                }),
                filter: Some(RowFilter {
                    filter: Some(row_filter::Filter::CellsPerColumnLimitFilter(1)),
                }),
                rows_limit: 0,
                request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            },
        )
        .await
        .map_err(|e| TreeStoreError::Network(e.to_string()))?;

        let node = match rows.into_iter().next().and_then(|(_key, cells)| {
            cells
                .into_iter()
                .find(|cell| cell.family == "f" && cell.qualifier == b"n")
                .map(|cell| marshalling::from_slice(&cell.value).expect("TODO"))
                .expect("every Merkle row should contain a node value")
        }) {
            Some(node) => Ok(node),
            None => Err(TreeStoreError::MissingNode),
        };

        trace!(realm = ?realm, key = ?key, ok = node.is_ok(), "read_node completed");
        node
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
    fn test_merkle_table() {
        let instance = Instance {
            project: String::from("prj1"),
            instance: String::from("inst2"),
        };
        let expected =
            "projects/prj1/instances/inst2/tables/6680134bf45dc93fceeecd03e538c89f-merkle";
        assert_eq!(merkle_table(&instance, &REALM1), expected);
        assert_eq!(
            format!("{}/tables/{}", instance.path(), merkle_table_brief(&REALM1)),
            expected
        );
    }

    #[test]
    fn test_log_table() {
        let instance = Instance {
            project: String::from("prj1"),
            instance: String::from("inst2"),
        };
        let realm = RealmId([0xca; 16]);
        let expected = "projects/prj1/instances/inst2/tables/cacacacacacacacacacacacacacacaca-log";
        assert_eq!(log_table(&instance, &realm), expected);
        assert_eq!(
            format!("{}/tables/{}", instance.path(), log_table_brief(&realm)),
            expected
        );
    }

    #[test]
    fn test_discovery_table() {
        let instance = Instance {
            project: String::from("prj1"),
            instance: String::from("inst2"),
        };
        let expected = "projects/prj1/instances/inst2/tables/discovery";
        assert_eq!(discovery_table(&instance), expected);
        assert_eq!(
            format!("{}/tables/{}", instance.path(), discovery_table_brief()),
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
