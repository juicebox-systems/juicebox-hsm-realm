//! This module deals with operations on the HSM transaction log table.
//!
//! The log table is named `{realm}-log` and contains log entries for every
//! group in the realm. A row contains either a batch of consecutive log
//! entries written together or a tombstone marking where a batch of log
//! entries used to be.
//!
//! Log entries normally count up from 1, but the log table is encoded using
//! downward log indexes that get smaller as the log index gets larger. This
//! makes finding the last entry in the log efficient. (Bigtable now supports
//! experimental reversed range queries, but these are stated to be less
//! efficient than forwards range queries.)
//!
//! The row keys are binary `{group}{downward_log_index}`. Log entries are
//! written to rows in batch, so not every log index is represented as a row
//! key. The index in the row key is the lowest upward index (highest downward
//! index) from the entries in the row.
//!
//! Within a log entry row, all columns are under a column family named `f`
//! (which retroactively stands for the "first" family we created). The column
//! qualifiers are the downward log indexes. This makes finding the finding the
//! last log entry efficient within a row (since columns are sorted and the
//! query can limit to one column/cell).
//!
//! Rows containing log entries are quickly replaced with tombstones during log
//! compaction, and tombstones are eventually deleted. A tombstone retains the
//! same row key from the log entries that it replaces (so that it blocks a
//! stray leader from appending conflicting entries there). Within a tombstone
//! row, there is one cell under the column family named `t` and a column named
//! `t`, with an empty value. The advantage of using a separate column family
//! is that Bigtable's built-in garbage collection policies are used to delete
//! the tombstones (but must never delete real log entries).
//!
//! Each log has a few useful invariants related to tombstones. The last log
//! entry/row (highest upward index or lowest downward index) is never a
//! tombstone. From lowest to highest upward indexes (highest to lowest
//! downward indexes), the possibly-empty ranges of a log are:
//!  - gaps (deleted entries) intermixed with tombstones, then
//!  - a log entry row, then
//!  - gaps and tombstones intermixed with log entries for up to
//!    `TOMBSTONE_WINDOW_SIZE - 1` more rows, then
//!  - a sequence of log entry rows with no gaps nor tombstones.
//!
//! This implies that when reading from the end of the log towards the start,
//! after encountering `TOMBSTONE_WINDOW_SIZE` tombstones, there will be no
//! more log entry rows.

use google::bigtable::admin::v2::gc_rule::Rule::MaxAge;
use google::bigtable::admin::v2::table::TimestampGranularity;
use google::bigtable::admin::v2::{ColumnFamily, CreateTableRequest, GcRule, Table};
use google::bigtable::v2::column_range::StartQualifier;
use google::bigtable::v2::row_filter::{Chain, Interleave};
use google::bigtable::v2::row_range::{
    EndKey::EndKeyClosed, StartKey::StartKeyClosed, StartKey::StartKeyOpen,
};
use google::bigtable::v2::{
    mutate_rows_request, mutation, read_rows_request, row_filter::Filter, CheckAndMutateRowRequest,
    ColumnRange, MutateRowsRequest, Mutation, ReadRowsRequest, RowFilter, RowRange, RowSet,
};
use std::array::TryFromSliceError;
use std::collections::HashMap;
use std::fmt::Write;
use std::time::Instant;
use thiserror::Error;
use tonic::Code;
use tracing::{info, instrument, warn, Span};

use super::{AppendError, StoreClient};
use bigtable::mutate::{mutate_rows, MutateRowsError};
use bigtable::read::{Cell, Reader, RowKey};
use bigtable::{BigtableClient, BigtableTableAdminClient, Instance};
use hsm_api::{GroupId, LogEntry, LogIndex};
use juicebox_marshalling as marshalling;
use juicebox_realm_api::types::RealmId;
use observability::metrics;
use observability::metrics_tag as tag;

/// Defines how many tombstones can be intermingled with log entry rows.
///
/// Setting this to a larger value allows more tombstones to be written with a
/// single request to Bigtable whenever the compactor is behind. However, it
/// increases the cost of listing all the rows when a new leader begins
/// compaction. The compactor only needs to outpace the rate of log appends and
/// not add too much overhead, so a modest value should be sufficient.
///
/// # Warning
///
/// It would be hard to change this safely for an existing cluster.
const TOMBSTONE_WINDOW_SIZE: usize = 100;

pub(crate) fn log_table(instance: &Instance, realm: &RealmId) -> String {
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

/// A column family in a log table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogFamily {
    EntryBatch, // "f"
    Tombstone,  // "t"
}

impl LogFamily {
    fn name(&self) -> &'static str {
        match self {
            Self::EntryBatch => "f",
            Self::Tombstone => "t",
        }
    }

    fn name_string(&self) -> String {
        self.name().to_owned()
    }
}

#[derive(Debug, Error)]
#[error("unexpected column family {family:?} in log table")]
struct LogFamilyParseError<'a> {
    family: &'a str,
}

impl<'a> TryFrom<&'a str> for LogFamily {
    type Error = LogFamilyParseError<'a>;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        match value {
            "f" => Ok(Self::EntryBatch),
            "t" => Ok(Self::Tombstone),
            family => Err(LogFamilyParseError { family }),
        }
    }
}

impl<'a> TryFrom<&'a String> for LogFamily {
    type Error = LogFamilyParseError<'a>;

    fn try_from(value: &'a String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
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
                column_families: HashMap::from([
                    (
                        LogFamily::EntryBatch.name_string(),
                        ColumnFamily {
                            gc_rule: Some(GcRule { rule: None }),
                        },
                    ),
                    (
                        LogFamily::Tombstone.name_string(),
                        ColumnFamily {
                            // Bigtable will start to delete tombstones in any
                            // order after a week. This happens during their
                            // background compaction process, which can take an
                            // additional week.
                            gc_rule: Some(GcRule {
                                rule: Some(MaxAge(prost_types::Duration {
                                    seconds: 60 * 60 * 24 * 7,
                                    nanos: 0,
                                })),
                            }),
                        },
                    ),
                ]),
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

#[derive(Debug, Eq, PartialEq)]
struct DownwardLogIndex(LogIndex);

impl DownwardLogIndex {
    fn bytes(&self) -> [u8; 8] {
        let index: LogIndex = self.0;
        let index: u64 = index.0;
        (u64::MAX - index).to_be_bytes()
    }

    fn decode(bytes: [u8; 8]) -> LogIndex {
        LogIndex(u64::MAX - u64::from_be_bytes(bytes))
    }
}

impl From<[u8; 8]> for DownwardLogIndex {
    fn from(bytes: [u8; 8]) -> Self {
        DownwardLogIndex(Self::decode(bytes))
    }
}

impl TryFrom<&[u8]> for DownwardLogIndex {
    type Error = TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = <[u8; 8]>::try_from(bytes)?;
        Ok(Self::from(bytes))
    }
}

fn log_key(group: &GroupId, index: LogIndex) -> Vec<u8> {
    (group.0.iter())
        .chain(DownwardLogIndex(index).bytes().iter())
        .cloned()
        .collect()
}

fn parse_log_key(key: &RowKey) -> Result<(GroupId, LogIndex), &'static str> {
    let key = &key.0;
    if key.len() == GroupId([0; 16]).0.len() + DownwardLogIndex(LogIndex::FIRST).bytes().len() {
        let group_id = <[u8; 16]>::try_from(&key[..16]).unwrap();
        let downward_log_index = <[u8; 8]>::try_from(&key[16..24]).unwrap();
        Ok((
            GroupId(group_id),
            DownwardLogIndex::decode(downward_log_index),
        ))
    } else {
        Err("unexpected log row key format")
    }
}

/// Summarizes a row in the log table. Used for compaction.
///
/// This is marked as `non_exhaustive` so that only this module may create
/// `LogRow` instances. To create them for testing, see
/// [`testing::new_log_row`].
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub struct LogRow {
    /// The smallest index of the log entries written to the row.
    pub index: LogIndex,
    /// If true, the row was last known to contain a tombstone (but might be
    /// deleted by now). If false, it was last known to contain a batch of log
    /// entries (but might be a tombstone or deleted by now).
    pub is_tombstone: bool,
}

/// Returned from [`StoreClient::list_log_rows_page`] to indicate that the
/// caller should request the next page.
struct More(bool);

/// Error type for [`StoreClient::read_last_log_entry`].
#[derive(Debug, thiserror::Error)]
pub enum ReadLastLogEntryError {
    #[error("failed to read the last log entry: empty log")]
    EmptyLog,

    #[error(transparent)]
    Grpc(#[from] tonic::Status),
}

/// Error type for [`StoreClient::read_log_entries_iter`].
#[derive(Debug, thiserror::Error)]
pub enum LogEntriesIterError {
    #[error(
        "failed to iterate log entries: next entry needed at {0:?} was a \
        tombstone or a gap"
    )]
    Compacted(LogIndex),

    #[error(transparent)]
    Grpc(#[from] tonic::Status),
}

impl StoreClient {
    /// Appends a new batch of log entries, but only if the row doesn't yet
    /// exist.
    ///
    /// The caller must have checked that the entry before `entries[0]` was the
    /// last entry in a row and the `prev_mac` matches.
    #[instrument(
        level = "trace",
        skip(self, bigtable, entries),
        fields(
            retries,
            first_index = ?entries[0].index,
            num_entries = entries.len(),
        ),
    )]
    pub(super) async fn log_append(
        &self,
        bigtable: &mut BigtableClient,
        realm: &RealmId,
        group: &GroupId,
        entries: &[LogEntry],
    ) -> Result<LogRow, AppendError> {
        const MAX_RETRIES: usize = 3;
        for retries in 0.. {
            Span::current().record("retries", retries);

            match bigtable
                .check_and_mutate_row(CheckAndMutateRowRequest {
                    table_name: log_table(&self.instance, realm),
                    app_profile_id: String::new(),
                    row_key: log_key(group, entries[0].index),
                    predicate_filter: None, // check for any value, including tombstones
                    true_mutations: Vec::new(),
                    false_mutations: entries
                        .iter()
                        .map(|entry| Mutation {
                            mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                                family_name: LogFamily::EntryBatch.name_string(),
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

                    match self.read_last_log_entry_with_row(realm, group).await {
                        Ok((_, entry)) if entry.index.next() == entries[0].index => {
                            // Latest log entry is before the first one we're
                            // trying to write. The row wasn't written and we
                            // can retry that.
                            info!(
                                ?realm,
                                ?group,
                                "GRPC Unknown error and it appears the log entries weren't written"
                            );
                        }
                        Ok((row, entry))
                            if row.index == entries[0].index
                                && entry == *entries.last().unwrap() =>
                        {
                            // Latest log row matches the entries we were
                            // writing. The write succeeded.
                            info!(
                                ?realm,
                                ?group,
                                "GRPC Unknown error and it appears the log entries were written"
                            );
                            return Ok(row);
                        }
                        Ok(_) => {
                            // Latest log entry does not match anything we're
                            // expecting. It must have been written by another
                            // leader.
                            info!(
                                ?realm,
                                ?group,
                                "GRPC Unknown error and it appears a log entry was written by someone else"
                            );
                            return Err(AppendError::LogPrecondition);
                        }
                        Err(ReadLastLogEntryError::EmptyLog) => {
                            // No log entry at all, safe to retry.
                            info!(
                                ?realm,
                                ?group,
                                "GRPC Unknown error and the log appears empty"
                            );
                            // For anything but the first entry, the caller
                            // should have already checked that the log isn't
                            // empty.
                            assert_eq!(entries[0].index, LogIndex::FIRST);
                        }
                        Err(ReadLastLogEntryError::Grpc(e)) => return Err(e.into()),
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
                    return Ok(LogRow {
                        index: entries[0].index,
                        is_tombstone: false,
                    });
                }
            }
        }
        unreachable!()
    }

    /// Reads and returns the newest entry at the end of the log.
    ///
    /// The returned entry will be the last entry in a row, and this will never
    /// return a tombstone (since the last row must not be compacted).
    pub async fn read_last_log_entry(
        &self,
        realm: &RealmId,
        group: &GroupId,
    ) -> Result<LogEntry, ReadLastLogEntryError> {
        self.read_last_log_entry_with_row(realm, group)
            .await
            .map(|(_row, entry)| entry)
    }

    #[instrument(level = "trace", skip(self))]
    async fn read_last_log_entry_with_row(
        &self,
        realm: &RealmId,
        group: &GroupId,
    ) -> Result<(LogRow, LogEntry), ReadLastLogEntryError> {
        let start = Instant::now();

        // Retry when the last entry appears to be a tombstone. The last log
        // entry should never be a tombstone, but it might appear so with
        // concurrent operations:
        //
        //     Task 1                          Task 2
        //     ---------------------------     --------------------------
        //     scan for last log key -> 12
        //                                     append entry 13
        //                                     commit entry 13
        //                                     replace 12 with tombstone
        //     read entry 12 -> tombstone
        let mut attempt: u64 = 0;
        loop {
            attempt += 1;

            let request = ReadRowsRequest {
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
            };

            let (row_index, cell) =
                match Reader::read_cell(&mut self.bigtable.clone(), request).await? {
                    Some((key, cell)) => {
                        let (_, row_index) = parse_log_key(&key).unwrap();
                        (row_index, cell)
                    }
                    None => return Err(ReadLastLogEntryError::EmptyLog),
                };

            return match LogFamily::try_from(&cell.family).unwrap() {
                LogFamily::EntryBatch => {
                    let entry: LogEntry = marshalling::from_slice(&cell.value).expect("TODO");
                    self.metrics.timing(
                        "store_client.read_last_log_entry.time",
                        start.elapsed(),
                        [tag!(?realm), tag!(?group)],
                    );
                    Ok((
                        LogRow {
                            index: row_index,
                            is_tombstone: false,
                        },
                        entry,
                    ))
                }

                LogFamily::Tombstone => {
                    if attempt > 100 {
                        panic!("giving up after too many attempts");
                    }
                    warn!(
                        ?realm, ?group, index = %row_index, attempt,
                        "last log entry is a tombstone: retrying",
                    );
                    continue;
                }
            };
        }
    }

    /// Returns an iterator-style object that can read the log starting from
    /// the supplied log index.
    ///
    /// max_entries indicates how large of a chunk to return. However, due to
    /// the variable batch size when appending, you may get up to
    /// MAX_BATCH_SIZE-1 more entries returned than max_entries.
    pub fn read_log_entries_iter(
        &self,
        realm: RealmId,
        group: GroupId,
        starting_at: LogIndex,
        max_entries: u16,
    ) -> LogEntriesIter {
        assert!(max_entries > 0);
        self.warmer.add(realm);
        let table_name = log_table(&self.instance, &realm);
        LogEntriesIter {
            realm,
            group,
            next: Position::LogIndex(starting_at),
            max_entries: u64::from(max_entries),
            client: self.clone(),
            table_name,
            metrics: self.metrics.clone(),
        }
    }

    /// Lists every row in the log, from the first row containing log entries
    /// up to the given index.
    ///
    /// This is used for log compaction. When a new leader starts up, it needs
    /// to find existing entries to compact.
    ///
    /// If `up_to` refers to a log index within a row (not the start of the
    /// row), then this returns the row that includes `up_to`. If `up_to` is
    /// the start of a row (or a gap), this does not return that row.
    ///
    /// The rows are returned in forwards log order.
    #[instrument(level = "trace", skip(self), fields(pages, rows, lowest, highest))]
    pub async fn list_log_rows(
        &self,
        realm: &RealmId,
        group: &GroupId,
        mut up_to: LogIndex,
    ) -> Result<Vec<LogRow>, tonic::Status> {
        let start = Instant::now();
        let mut rows: Vec<LogRow> = Vec::new();
        let mut pages = 0;
        while up_to > LogIndex::FIRST {
            let (page, More(more)) = self.list_log_rows_page(realm, group, up_to).await?;
            pages += 1;
            rows.extend_from_slice(&page);
            if let Some(row) = rows.last() {
                up_to = row.index;
            }
            if !more {
                break;
            }
        }

        // Remove trailing tombstones (towards the start of the log), as
        // they're not needed.
        while rows.last().is_some_and(|row| row.is_tombstone) {
            rows.pop();
        }

        // Flip to forwards log order.
        rows.reverse();

        Span::current().record("pages", pages);
        Span::current().record("rows", rows.len());
        if let Some(lowest) = rows.first() {
            Span::current().record("lowest", lowest.index.0);
            Span::current().record("highest", rows.last().unwrap().index.0);
        }

        let tags = [tag!(?realm), tag!(?group)];
        self.metrics
            .timing("store_client.list_log_rows.time", start.elapsed(), &tags);
        self.metrics
            .distribution("store_client.list_log_rows.count", rows.len(), &tags);

        Ok(rows)
    }

    /// Helper to [`list_log_rows`]. Retrieves a limited number of row
    /// summaries for a slice of the log and returns them in reverse log order.
    ///
    /// If `up_to` refers to a log index within a row (not the start of the
    /// row), then this returns the row that includes `up_to`. If `up_to` is
    /// the start of a row (or a gap), this does not return the row.
    #[instrument(level = "trace", skip(self), fields(rows, lowest, highest, more))]
    async fn list_log_rows_page(
        &self,
        realm: &RealmId,
        group: &GroupId,
        up_to: LogIndex,
    ) -> Result<(Vec<LogRow>, More), tonic::Status> {
        assert!(up_to > LogIndex::FIRST);

        let request = ReadRowsRequest {
            table_name: log_table(&self.instance, realm),
            app_profile_id: String::new(),
            rows: Some(RowSet {
                row_keys: Vec::new(),
                row_ranges: vec![RowRange {
                    start_key: Some(StartKeyOpen(log_key(group, up_to))),
                    end_key: Some(EndKeyClosed(log_key(group, LogIndex::FIRST))),
                }],
            }),
            filter: Some(RowFilter {
                filter: Some(Filter::Interleave(Interleave {
                    filters: vec![
                        // Return log entry rows without the actual entries.
                        RowFilter {
                            filter: Some(Filter::Chain(Chain {
                                filters: vec![
                                    RowFilter {
                                        filter: Some(Filter::ColumnRangeFilter(ColumnRange {
                                            family_name: LogFamily::EntryBatch.name_string(),
                                            start_qualifier: None,
                                            end_qualifier: None,
                                        })),
                                    },
                                    RowFilter {
                                        filter: Some(Filter::CellsPerRowLimitFilter(1)),
                                    },
                                    RowFilter {
                                        filter: Some(Filter::StripValueTransformer(true)),
                                    },
                                ],
                            })),
                        },
                        // Also return tombstones.
                        RowFilter {
                            filter: Some(Filter::ColumnRangeFilter(ColumnRange {
                                family_name: LogFamily::Tombstone.name_string(),
                                start_qualifier: None,
                                end_qualifier: None,
                            })),
                        },
                    ],
                })),
            }),
            rows_limit: i64::try_from(TOMBSTONE_WINDOW_SIZE).unwrap(),
            request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            reversed: false,
        };

        let rows: Vec<LogRow> = Reader::read_column(&mut self.bigtable.clone(), request)
            .await?
            .into_iter()
            .map(|(key, cell)| LogRow {
                index: parse_log_key(&key).unwrap().1,
                is_tombstone: match LogFamily::try_from(&cell.family).unwrap() {
                    LogFamily::Tombstone => true,
                    LogFamily::EntryBatch => false,
                },
            })
            .collect();

        // Technically, we could stop after cumulatively finding
        // `TOMBSTONE_WINDOW_SIZE` tombstones, but it's easier to stop after
        // finding that many in the same page.
        let more =
            More(rows.len() == TOMBSTONE_WINDOW_SIZE && !rows.iter().all(|row| row.is_tombstone));

        Span::current().record("rows", rows.len());
        if let Some(lowest) = rows.first() {
            Span::current().record("lowest", lowest.index.0);
            Span::current().record("highest", rows.last().unwrap().index.0);
        }
        Span::current().record("more", more.0);

        Ok((rows, more))
    }

    /// Overwrite the start of the log with tombstones.
    ///
    /// `rows` must represent a consecutive sequence of rows in the log,
    /// including tombstone rows. The caller must guarantee that there are no
    /// rows containing log entries with an upward index below `rows[0].index`.
    #[instrument(
        level = "trace",
        skip(self, rows),
        fields(rows = rows.len(), lowest, highest, chunks),
    )]
    pub async fn replace_oldest_rows_with_tombstones(
        &self,
        realm: &RealmId,
        group: &GroupId,
        rows: &[LogRow],
    ) -> Result<(), MutateRowsError> {
        let start = Instant::now();
        if let Some(lowest) = rows.first() {
            Span::current().record("lowest", lowest.index.0);
            Span::current().record("highest", rows.last().unwrap().index.0);
        }

        assert!(
            rows.windows(2).all(|w| w[0].index < w[1].index),
            "rows must be sorted and unique by log index"
        );

        // It's critical for this to be chunked including tombstone rows. For a
        // counter-argument, suppose `rows` skipped tombstones. Agent 1 calls
        // this function, so its first chunk is `TOMBSTONE_WINDOW_SIZE` log
        // entry rows (spanning more than `TOMBSTONE_WINDOW_SIZE` rows).
        // Bigtable writes the last tombstones in the chunk, then crashes.
        // Agent 2 reads the log and does the same. Now the log contains more
        // than `TOMBSTONE_WINDOW_SIZE` log entries interspersed with
        // tombstones, which is a problem. Instead, by chunking inclusive of
        // the tombstones, agent 1's write can only modify the first
        // `TOMBSTONE_WINDOW_SIZE` rows from the first log entry row
        // (inclusive), and agent-2's write will do the same.
        let mut num_chunks = 0;
        for chunk in rows.chunks(TOMBSTONE_WINDOW_SIZE) {
            num_chunks += 1;
            self.replace_chunk_with_tombstones(realm, group, chunk)
                .await?;
        }

        Span::current().record("chunks", num_chunks);
        let tags = [tag!(?realm), tag!(?group)];
        self.metrics.timing(
            "store_client.replace_oldest_rows_with_tombstones.time",
            start.elapsed(),
            &tags,
        );
        self.metrics.distribution(
            "store_client.replace_oldest_rows_with_tombstones.rows",
            rows.len(),
            &tags,
        );
        Ok(())
    }

    /// Helper to [`Self::replace_oldest_rows_with_tombstones`]. Split out for
    /// tracing.
    #[instrument(
        level = "trace",
        skip(self, rows),
        fields(rows = rows.len(), lowest, highest, chunks),
    )]
    async fn replace_chunk_with_tombstones(
        &self,
        realm: &RealmId,
        group: &GroupId,
        rows: &[LogRow],
    ) -> Result<(), MutateRowsError> {
        assert!(rows.len() <= TOMBSTONE_WINDOW_SIZE);
        if let Some(lowest) = rows.first() {
            Span::current().record("lowest", lowest.index.0);
            Span::current().record("highest", rows.last().unwrap().index.0);
        }
        let mut bigtable = self.bigtable.clone();

        // Retry on grpc stream unknown errors.
        loop {
            let request = MutateRowsRequest {
                table_name: log_table(&self.instance, realm),
                app_profile_id: String::new(),
                entries: rows
                    .iter()
                    // Don't overwrite existing tombstones, since that'd reset
                    // their timestamps and needlessly expand their lifetimes.
                    .filter(|row| !row.is_tombstone)
                    .map(|row| mutate_rows_request::Entry {
                        row_key: log_key(group, row.index),
                        mutations: vec![
                            Mutation {
                                mutation: Some(mutation::Mutation::DeleteFromRow(
                                    mutation::DeleteFromRow {},
                                )),
                            },
                            Mutation {
                                mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                                    family_name: LogFamily::Tombstone.name_string(),
                                    column_qualifier: b"t".to_vec(),
                                    timestamp_micros: -1, // server-assigned
                                    value: Vec::new(),
                                })),
                            },
                        ],
                    })
                    .collect(),
            };
            match mutate_rows(&mut bigtable, request).await {
                Ok(()) => return Ok(()),
                Err(MutateRowsError::Tonic(status)) if status.code() == Code::Unknown => {
                    warn!(?realm, ?group, ?status, "error while writing tombstones");
                    continue;
                }
                Err(status) => return Err(status),
            }
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
    metrics: metrics::Client,
    realm: RealmId,
    group: GroupId,
    next: Position,
    max_entries: u64,
    client: StoreClient,
    table_name: String,
}

impl LogEntriesIter {
    /// Reads the next chunk of log entries from the log.
    ///
    /// The returned Log Entries are in increasing upward log index order.
    /// Returns an empty Vec if there's nothing new in the log since the last
    /// call to next. It's safe to call `next()` again after a Grpc error.
    #[instrument(
        level = "trace",
        name = "LogEntriesIter::next",
        skip(self),
        fields(
            realm = ?self.realm,
            group = ?self.group,
            index,
            entries,
        )
    )]
    pub async fn next(&mut self) -> Result<Vec<LogEntry>, LogEntriesIterError> {
        let start = Instant::now();
        let rows = match self.next {
            Position::LogIndex(i) => match self.read_for_log_index(i).await? {
                Some(row) => vec![row],
                None => Vec::new(),
            },
            Position::RowBoundary(i) => self.read_for_row_boundary(i).await?,
        };

        let index = match self.next {
            Position::LogIndex(i) => i,
            Position::RowBoundary(i) => i,
        };
        Span::current().record("index", index.0);

        let entries: Vec<LogEntry> = rows
            .into_iter()
            .rev()
            .flat_map(|(row_key, cells)| {
                cells.into_iter().rev().map(move |cell| {
                    match LogFamily::try_from(&cell.family).unwrap() {
                        LogFamily::EntryBatch => {
                            let entry: LogEntry =
                                marshalling::from_slice(&cell.value).expect("TODO");
                            Ok(entry)
                        }
                        LogFamily::Tombstone => Err(LogEntriesIterError::Compacted(
                            index.max(parse_log_key(&row_key).unwrap().1),
                        )),
                    }
                })
            })
            .collect::<Result<_, _>>()?;

        if !entries.is_empty() {
            if entries[0].index != index {
                return Err(LogEntriesIterError::Compacted(index));
            }
            for w in entries.as_slice().windows(2) {
                if w[0].index.next() != w[1].index {
                    return Err(LogEntriesIterError::Compacted(w[0].index.next()));
                }
            }
            self.next = Position::RowBoundary(entries.last().unwrap().index.next());
        }

        Span::current().record("entries", entries.len());
        self.metrics.timing(
            "store_client.log_entries_iter_next.time",
            start.elapsed(),
            [tag!("realm": ?self.realm), tag!("group": ?self.group)],
        );
        Ok(entries)
    }

    /// Reads the row containing `index` (which may be in the middle of the
    /// row).
    ///
    /// The returned value is `Ok(None)` only if the index is past the end of
    /// the log, while gaps and tombstones result in
    /// `Err(LogEntriesIterError::Compacted(_))`.
    async fn read_for_log_index(
        &self,
        index: LogIndex,
    ) -> Result<Option<(RowKey, Vec<Cell>)>, LogEntriesIterError> {
        if let Some(row) = self.try_read_for_log_index(index).await? {
            return Ok(Some(row));
        }

        // `index` wasn't found. Determine whether it's past the end of the log
        // or has already been deleted.
        match self
            .client
            .read_last_log_entry(&self.realm, &self.group)
            .await
        {
            Ok(last_entry) if last_entry.index < index => Ok(None),

            Ok(_) => {
                // Because the last entry is >= `index`, we now know that
                // either `index` is a gap or actually exists. It could have
                // been created after the first attempt, so retry once to
                // disambiguate.
                match self.try_read_for_log_index(index).await? {
                    Some(row) => Ok(Some(row)),
                    None => Err(LogEntriesIterError::Compacted(index)),
                }
            }

            Err(ReadLastLogEntryError::EmptyLog) => Ok(None),

            Err(ReadLastLogEntryError::Grpc(err)) => Err(err.into()),
        }
    }

    async fn try_read_for_log_index(
        &self,
        index: LogIndex,
    ) -> Result<Option<(RowKey, Vec<Cell>)>, tonic::Status> {
        let request = ReadRowsRequest {
            table_name: self.table_name.clone(),
            app_profile_id: String::new(),
            rows: Some(RowSet {
                row_keys: Vec::new(),
                row_ranges: vec![RowRange {
                    start_key: Some(StartKeyClosed(log_key(&self.group, index))),
                    end_key: Some(EndKeyClosed(log_key(&self.group, LogIndex::FIRST))),
                }],
            }),
            // We want to get both log entries and tombstones. For regular log
            // entries, don't filter on log index here because if the entry for
            // the index doesn't yet exist, we need the row_limits:1 to kick in
            // and prevent the query from scanning the entire log. We don't
            // bother filtering on the column families since we don't expect to
            // encounter any other column families.
            filter: None,
            rows_limit: 1,
            request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            reversed: false,
        };

        match Reader::read_row(&mut self.client.bigtable.clone(), request).await? {
            None => Ok(None),
            Some((key, mut cells)) => {
                cells.retain(|cell| match LogFamily::try_from(&cell.family).unwrap() {
                    LogFamily::EntryBatch => {
                        DownwardLogIndex::try_from(cell.qualifier.as_slice())
                            .expect("log entry cell qualifier should be downward log index")
                            .0
                            >= index
                    }
                    LogFamily::Tombstone => true,
                });
                if cells.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some((key, cells)))
                }
            }
        }
    }

    /// Reads multiple rows down to and including the row with the key exactly
    /// determined by the index.
    ///
    /// The caller must ensure that `index` is at a row boundary. If it's not,
    /// this won't return the row that includes `index`.
    async fn read_for_row_boundary(
        &self,
        index: LogIndex,
    ) -> Result<Vec<(RowKey, Vec<Cell>)>, tonic::Status> {
        let request = ReadRowsRequest {
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
            filter: None, // get both log entries and tombstones
            rows_limit: 0,
            request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            reversed: false,
        };
        Reader::read_rows(&mut self.client.bigtable.clone(), request).await
    }
}

/// This module should be used in unit/integration tests and non-critical
/// tooling only.
#[allow(dead_code)]
pub mod testing {
    use super::*;

    pub fn log_table(instance: &Instance, realm: &RealmId) -> String {
        super::log_table(instance, realm)
    }

    pub fn parse_log_key(key: &RowKey) -> Result<(GroupId, LogIndex), &'static str> {
        super::parse_log_key(key)
    }

    pub fn new_log_row(index: LogIndex, is_tombstone: bool) -> LogRow {
        LogRow {
            index,
            is_tombstone,
        }
    }

    /// Error type for [`read_log_entry`].
    #[derive(Debug, thiserror::Error)]
    pub enum ReadLogEntryError {
        #[error("failed to read specific log entry: found a tombstone")]
        Tombstone,

        #[error(
            "failed to read specific log entry: it does not exist (it was never \
        created or its tombstone was deleted)"
        )]
        NotFound,

        #[error(transparent)]
        Grpc(#[from] tonic::Status),
    }

    /// Reads a particular entry from the log.
    ///
    /// This used to be production code, but it's typically safer with respect
    /// to gaps and compaction to use [`StoreClient::read_last_log_entry`].
    /// Now, this only exists to be tested, which is silly.
    #[instrument(level = "trace", skip(store))]
    pub async fn read_log_entry(
        store: &StoreClient,
        realm: &RealmId,
        group: &GroupId,
        index: LogIndex,
    ) -> Result<LogEntry, ReadLogEntryError> {
        let filters = vec![
            RowFilter {
                filter: Some(Filter::Interleave(Interleave {
                    filters: vec![
                        // Read the requested log entry, or if that doesn't
                        // exist, the highest log entry with an index <
                        // requested index. This ensures the rows_limit:1 kicks
                        // in and stops the query. rows_limit is a results rows
                        // limit, not a scan limit.
                        RowFilter {
                            filter: Some(Filter::ColumnRangeFilter(ColumnRange {
                                family_name: LogFamily::EntryBatch.name_string(),
                                start_qualifier: Some(StartQualifier::StartQualifierClosed(
                                    DownwardLogIndex(index).bytes().to_vec(),
                                )),
                                end_qualifier: None,
                            })),
                        },
                        // Also return tombstones.
                        RowFilter {
                            filter: Some(Filter::ColumnRangeFilter(ColumnRange {
                                family_name: LogFamily::Tombstone.name_string(),
                                start_qualifier: None,
                                end_qualifier: None,
                            })),
                        },
                    ],
                })),
            },
            RowFilter {
                filter: Some(Filter::CellsPerRowLimitFilter(1)),
            },
        ];

        let request = ReadRowsRequest {
            table_name: log_table(&store.instance, realm),
            app_profile_id: String::new(),
            rows: Some(RowSet {
                row_keys: Vec::new(),
                row_ranges: vec![RowRange {
                    start_key: Some(StartKeyClosed(log_key(group, index))),
                    end_key: Some(EndKeyClosed(log_key(group, LogIndex::FIRST))),
                }],
            }),
            filter: Some(RowFilter {
                filter: Some(Filter::Chain(Chain { filters })),
            }),
            rows_limit: 1,
            request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            reversed: false,
        };

        let Some((key, cell)) = Reader::read_cell(&mut store.bigtable.clone(), request).await?
        else {
            return Err(ReadLogEntryError::NotFound);
        };

        match LogFamily::try_from(&cell.family).unwrap() {
            LogFamily::EntryBatch => {
                if DownwardLogIndex::try_from(cell.qualifier.as_slice())
                    .expect("log entry cell qualifier should be downward log index")
                    == DownwardLogIndex(index)
                {
                    let entry: LogEntry = marshalling::from_slice(&cell.value).expect("TODO");
                    assert_eq!(entry.index, index);
                    Ok(entry)
                } else {
                    Err(ReadLogEntryError::NotFound)
                }
            }
            LogFamily::Tombstone => {
                if parse_log_key(&key).unwrap().1 == index {
                    Err(ReadLogEntryError::Tombstone)
                } else {
                    Err(ReadLogEntryError::NotFound)
                }
            }
        }
    }

    pub async fn delete_row(
        store: &StoreClient,
        realm: &RealmId,
        group: &GroupId,
        row: LogIndex,
    ) -> Result<(), MutateRowsError> {
        mutate_rows(
            &mut store.bigtable.clone(),
            MutateRowsRequest {
                table_name: log_table(&store.instance, realm),
                app_profile_id: String::new(),
                entries: vec![mutate_rows_request::Entry {
                    row_key: log_key(group, row),
                    mutations: vec![Mutation {
                        mutation: Some(mutation::Mutation::DeleteFromRow(
                            mutation::DeleteFromRow {},
                        )),
                    }],
                }],
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

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
    fn test_log_family() {
        use LogFamily::*;
        let _exhaustive = |family: &LogFamily| match family {
            // When the compiler forces you to add an arm here, also add it to
            // the list below.
            EntryBatch | Tombstone => {}
        };
        let all_families = [EntryBatch, Tombstone];

        for family in all_families {
            assert_eq!(
                family,
                LogFamily::try_from(family.name()).unwrap(),
                "{family:?}",
            );
        }
        assert_eq!(
            HashSet::from(all_families.map(|family| family.name())).len(),
            all_families.len(),
            "LogFamily names must be unique",
        );
        assert_eq!(
            "unexpected column family \"asdf\" in log table",
            LogFamily::try_from("asdf").unwrap_err().to_string()
        );
    }

    #[test]
    fn test_downward_logindex() {
        assert_eq!(
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            DownwardLogIndex(LogIndex(0)).bytes()
        );
        assert_eq!(
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe],
            DownwardLogIndex(LogIndex(1)).bytes()
        );
        assert_eq!(
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd],
            DownwardLogIndex(LogIndex(2)).bytes()
        );
        assert_eq!(
            [0, 0, 0, 0, 0, 0, 0, 0],
            DownwardLogIndex(LogIndex(u64::MAX)).bytes()
        );
        assert_eq!(
            DownwardLogIndex(LogIndex(2)),
            DownwardLogIndex::from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd])
        );
        for i in [0, 1, 2, 100, 42200032, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            let up = LogIndex(i);
            let down = DownwardLogIndex(up);
            assert_eq!(up, DownwardLogIndex::decode(down.bytes()));
            assert_eq!(down, DownwardLogIndex::from(down.bytes()));
            assert_eq!(
                down,
                DownwardLogIndex::try_from(down.bytes().as_slice()).unwrap()
            );
        }
        assert!(DownwardLogIndex::try_from([1, 2, 3].as_slice()).is_err());
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

    #[test]
    fn test_parse_log_key() {
        assert_eq!(
            Ok((GROUP1, LogIndex(12943236441930260757))),
            parse_log_key(&RowKey(log_key(&GROUP1, LogIndex(12943236441930260757))))
        );
    }
}
