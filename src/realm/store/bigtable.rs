use crate::autogen::google;
use async_trait::async_trait;
use google::bigtable::admin::v2::table::TimestampGranularity;
use google::bigtable::admin::v2::{ColumnFamily, CreateTableRequest, Table};
use google::bigtable::v2::row_range::EndKey::EndKeyOpen;
use google::bigtable::v2::row_range::StartKey::StartKeyClosed;
use google::bigtable::v2::{
    mutate_rows_request, mutation, read_rows_request, row_filter, CheckAndMutateRowRequest,
    MutateRowRequest, MutateRowResponse, MutateRowsRequest, Mutation, ReadRowsRequest, RowFilter,
    RowRange, RowSet,
};
use std::collections::HashMap;
use std::fmt::Write;
use tonic::transport::{Channel, Endpoint};
use tracing::trace;
use url::Url;

mod mutate;
mod read;

use super::super::hsm::types::{DataHash, GroupId, HsmId, LogEntry, LogIndex, RealmId, RecordId};
use super::super::merkle;
use super::super::merkle::agent::{
    all_store_key_starts, Node, StoreDelta, StoreKey, TreeStoreError, TreeStoreReader,
};
use mutate::{mutate_rows, MutateRowsError};
use read::read_rows;

type BigtableTableAdminClient =
    google::bigtable::admin::v2::bigtable_table_admin_client::BigtableTableAdminClient<Channel>;
type BigtableClient =
    google::bigtable::v2::bigtable_client::BigtableClient<tonic::transport::Channel>;

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

#[derive(Clone, Debug)]
pub struct StoreAdminClient {
    // https://cloud.google.com/bigtable/docs/reference/admin/rpc/google.bigtable.admin.v2
    bigtable: BigtableTableAdminClient,
    instance: Instance,
}

impl StoreAdminClient {
    pub async fn new(url: String, instance: Instance) -> Result<Self, f64> {
        let endpoint = Endpoint::from_shared(url).expect("TODO");
        let bigtable = BigtableTableAdminClient::connect(endpoint)
            .await
            .expect("TODO");
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
                    name: discovery_table(&self.instance),
                    cluster_states: HashMap::new(),
                    column_families: HashMap::from([(
                        String::from("f"),
                        ColumnFamily { gc_rule: None },
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
                    name: merkle_table(&self.instance, realm),
                    cluster_states: HashMap::new(),
                    column_families: HashMap::from([(
                        String::from("f"),
                        ColumnFamily { gc_rule: None },
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
                    name: log_table(&self.instance, realm),
                    cluster_states: HashMap::new(),
                    column_families: HashMap::from([(
                        String::from("f"),
                        ColumnFamily { gc_rule: None },
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

#[derive(Clone, Debug)]
pub struct StoreClient {
    // https://cloud.google.com/bigtable/docs/reference/data/rpc/google.bigtable.v2
    bigtable: BigtableClient,
    instance: Instance,
}

#[derive(Debug)]
pub enum AppendError {
    Grpc(tonic::Status),
    MerkleWrites(google::rpc::Status),
    LogPrecondition,
    MerkleDeletes(google::rpc::Status),
}

impl StoreClient {
    pub async fn new(url: String, instance: Instance) -> Result<Self, f64> {
        let endpoint = Endpoint::from_shared(url).expect("TODO");
        let bigtable = BigtableClient::connect(endpoint).await.expect("TODO");
        Ok(Self { bigtable, instance })
    }

    pub async fn append(
        &self,
        realm: &RealmId,
        group: &GroupId,
        entry: &LogEntry,
        delta: &StoreDelta<DataHash>,
    ) -> Result<(), AppendError> {
        trace!(
            realm = ?realm,
            group = ?group,
            index = ?entry.index,
            delta_adds = delta.add.len(),
            delta_removes = delta.remove.len(),
            "append starting",
        );

        let mut bigtable = self.bigtable.clone();

        // Write new Merkle nodes.
        if !delta.add.is_empty() {
            mutate_rows(
                &mut bigtable,
                MutateRowsRequest {
                    table_name: merkle_table(&self.instance, realm),
                    app_profile_id: String::new(),
                    entries: delta
                        .add
                        .iter()
                        .map(|(key, value)| mutate_rows_request::Entry {
                            row_key: key.store_key().into_bytes(),
                            mutations: vec![Mutation {
                                mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                                    family_name: String::from("f"),
                                    column_qualifier: b"n".to_vec(),
                                    timestamp_micros: -1,
                                    // TODO: this unnecessarily includes the
                                    // node's hash and unnecessarily wraps the
                                    // leaf node values.
                                    value: rmp_serde::to_vec(value).expect("TODO"),
                                })),
                            }],
                        })
                        .collect(),
                },
            )
            .await
            .map_err(|e| match e {
                MutateRowsError::Tonic(e) => AppendError::Grpc(e),
                MutateRowsError::Mutation(e) => AppendError::MerkleWrites(e),
            })?;
        }

        // Make sure the previous log entry exists and matches the expected
        // value.
        // TODO: cache some info about the last entry to avoid this read.
        if entry.index != LogIndex::FIRST {
            let prev_index = entry.index.prev().unwrap();
            let Some(prev) = self.read_log_entry(realm, group, prev_index)
                .await
                .expect("TODO") else {
                return Err(AppendError::LogPrecondition);
            };
            if prev.entry_hmac != entry.prev_hmac {
                return Err(AppendError::LogPrecondition);
            }
        }

        // Append the new entry but only if it doesn't yet exist.
        let append_response = bigtable
            .check_and_mutate_row(CheckAndMutateRowRequest {
                table_name: log_table(&self.instance, realm),
                app_profile_id: String::new(),
                row_key: log_key(group, entry.index),
                predicate_filter: None, // checks for any value
                true_mutations: Vec::new(),
                false_mutations: vec![Mutation {
                    mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                        family_name: String::from("f"),
                        column_qualifier: b"e".to_vec(),
                        timestamp_micros: -1,
                        value: rmp_serde::to_vec(entry).expect("TODO"),
                    })),
                }],
            })
            .await
            .map_err(AppendError::Grpc)?
            .into_inner();
        if append_response.predicate_matched {
            return Err(AppendError::LogPrecondition);
        }

        // Delete obsolete Merkle nodes.
        // TODO: defer these deletes so slow concurrent readers can read this
        if !delta.remove.is_empty() {
            mutate_rows(
                &mut bigtable,
                MutateRowsRequest {
                    table_name: merkle_table(&self.instance, realm),
                    app_profile_id: String::new(),
                    entries: delta
                        .remove
                        .iter()
                        .map(|key| mutate_rows_request::Entry {
                            row_key: key.store_key().into_bytes(),
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
            .map_err(|e| match e {
                MutateRowsError::Tonic(e) => AppendError::Grpc(e),
                MutateRowsError::Mutation(e) => AppendError::MerkleDeletes(e),
            })?;
        }

        trace!("append succeeded");
        Ok(())
    }

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
                    row_keys: vec![log_key(group, index)],
                    row_ranges: Vec::new(),
                }),
                filter: None,
                rows_limit: 0,
                request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            },
        )
        .await?;

        let entry = rows.into_iter().next().and_then(|(_key, cells)| {
            cells
                .into_iter()
                .find(|cell| cell.family == "f" && cell.qualifier == b"e")
                .map(|cell| rmp_serde::from_slice(&cell.value).expect("TODO"))
        });

        trace!(
            realm = ?realm,
            group = ?group,
            index = ?index,
            entry = ?entry,
            "read_log_entry completed",
        );
        Ok(entry)
    }

    pub async fn read_last_log_entry(
        &self,
        realm: &RealmId,
        group: &GroupId,
    ) -> Result<Option<LogEntry>, tonic::Status> {
        trace!(?realm, ?group, "read_last_log_entry starting");

        // This is an inefficient placeholder to avoid copy-pasting the
        // `read_log_entry` code.
        //
        // TODO: do a single range read instead to find the last log entry.
        let mut index = LogIndex::FIRST;
        let mut last = None;
        while let Some(entry) = self.read_log_entry(realm, group, index).await? {
            last = Some(entry);
            index = index.next();
        }

        trace!(?realm, ?group, ?last, "read_last_log_entry completed");
        Ok(last)
    }

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
        .map_err(|e| TreeStoreError::Network(Box::new(e)))?;

        let nodes: HashMap<DataHash, Node<DataHash>> = rows
            .into_iter()
            .map(|(row_key, cells)| {
                // TODO: there should be an easier way to parse a StoreKey.
                let mut hash = DataHash(Default::default());
                let hash_len = hash.0.len();
                hash.0
                    .copy_from_slice(&row_key.0[(row_key.0.len() - hash_len)..]);
                let node: Node<DataHash> = rmp_serde::from_slice(
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

    async fn read_node(
        &self,
        realm: &RealmId,
        prefix: &merkle::KeyVec,
        hash: &DataHash,
    ) -> Result<Node<DataHash>, TreeStoreError> {
        trace!(realm = ?realm, prefix = ?prefix, hash = ?hash, "read_node starting");

        let rows = read_rows(
            &mut self.bigtable.clone(),
            ReadRowsRequest {
                table_name: merkle_table(&self.instance, realm),
                app_profile_id: String::new(),
                rows: Some(RowSet {
                    row_keys: vec![StoreKey::new(prefix.clone(), *hash).into_bytes()],
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
        .map_err(|e| TreeStoreError::Network(Box::new(e)))?;

        let node = match rows.into_iter().next().and_then(|(_key, cells)| {
            cells
                .into_iter()
                .find(|cell| cell.family == "f" && cell.qualifier == b"n")
                .map(|cell| rmp_serde::from_slice(&cell.value).expect("TODO"))
                .expect("every Merkle row should contain a node value")
        }) {
            Some(node) => Ok(node),
            None => Err(TreeStoreError::MissingNode),
        };

        trace!(realm = ?realm, prefix = ?prefix, hash = ?hash, ok = node.is_ok(), "read_node completed");
        node
    }

    pub fn realm_reader<'a>(&'a self, realm: &'a RealmId) -> impl TreeStoreReader<DataHash> + 'a {
        RealmReader { store: self, realm }
    }

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

        let addresses: Vec<(HsmId, Url)> = rows
            .into_iter()
            .filter_map(|(row_key, cells)| {
                cells
                    .into_iter()
                    .find(|cell| cell.family == "f" && cell.qualifier == b"a")
                    .and_then(|cell| String::from_utf8(cell.value).ok())
                    .and_then(|url| Url::parse(&url).ok())
                    .map(|url| {
                        let mut hsm = HsmId([0u8; 16]);
                        hsm.0.copy_from_slice(&row_key.0);
                        (hsm, url)
                    })
            })
            .collect();

        trace!(
            addresses = ?addresses
                .iter()
                .map(|(hsm, url)| (hsm, url.as_str()))
                .collect::<Vec<_>>(),
            "get_addresses completed"
        );

        Ok(addresses)
    }

    pub async fn set_address(&self, hsm: &HsmId, address: &Url) -> Result<(), tonic::Status> {
        trace!(?hsm, address = address.as_str(), "set_address starting");
        let MutateRowResponse { /* empty */ } = self
            .bigtable
            .clone()
            .mutate_row(MutateRowRequest {
                table_name: discovery_table(&self.instance),
                app_profile_id: String::new(),
                row_key: hsm.0.to_vec(),
                mutations: vec![Mutation {
                    mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                        family_name: String::from("f"),
                        column_qualifier: b"a".to_vec(),
                        timestamp_micros: -1,
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

struct RealmReader<'a> {
    store: &'a StoreClient,
    realm: &'a RealmId,
}

#[async_trait]
impl<'a> TreeStoreReader<DataHash> for RealmReader<'a> {
    async fn path_lookup(
        &self,
        record_id: RecordId,
    ) -> Result<HashMap<DataHash, Node<DataHash>>, TreeStoreError> {
        self.store.path_lookup(self.realm, &record_id).await
    }

    async fn fetch(
        &self,
        prefix: merkle::KeyVec,
        hash: DataHash,
    ) -> Result<Node<DataHash>, TreeStoreError> {
        self.store.read_node(self.realm, &prefix, &hash).await
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
