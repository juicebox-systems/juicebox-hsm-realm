use google::bigtable::admin::v2::table::TimestampGranularity;
use google::bigtable::admin::v2::{ColumnFamily, CreateTableRequest, GcRule, Table};
use google::bigtable::v2::column_range::{EndQualifier, StartQualifier};
use google::bigtable::v2::row_range::{EndKey::EndKeyClosed, StartKey::StartKeyClosed};
use google::bigtable::v2::{
    mutation, read_rows_request, row_filter::Filter, CheckAndMutateRowRequest, ColumnRange,
    Mutation, ReadRowsRequest, RowFilter, RowRange, RowSet,
};
use std::collections::HashMap;
use std::fmt::Write;
use std::time::Instant;
use tonic::Code;
use tracing::{info, instrument, trace, warn, Span};

use super::{AppendError, StoreClient};
use bigtable::read::{read_rows, Cell, RowKey};
use bigtable::{BigtableClient, BigtableTableAdminClient, Instance};
use hsm_api::{GroupId, LogEntry, LogIndex};
use juicebox_marshalling as marshalling;
use juicebox_realm_api::types::RealmId;
use observability::metrics_tag as tag;

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

/// Create table for logs.
pub(super) async fn initialize(
    bigtable: &mut BigtableTableAdminClient,
    instance: &Instance,
    realm: &RealmId,
) -> Result<(), tonic::Status> {
    bigtable
        .create_table(CreateTableRequest {
            parent: instance.path(),
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
                change_stream_config: None,
                deletion_protection: false,
            }),
            initial_splits: Vec::new(),
        })
        .await?;
    Ok(())
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

impl StoreClient {
    /// Append a new batch of log entries, but only if the row doesn't yet
    /// exist.
    #[instrument(level = "trace", skip(self, bigtable, entries), fields(retries,num_entries = entries.len()))]
    pub(super) async fn log_append(
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
                reversed: false,
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
                reversed: false,
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
                reversed: false,
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
                reversed: false,
            },
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
