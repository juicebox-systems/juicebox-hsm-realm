use google::bigtable::v2::bigtable_client::BigtableClient;
use google::bigtable::v2::read_rows_response::cell_chunk::RowStatus;
use google::bigtable::v2::read_rows_response::CellChunk;
use google::bigtable::v2::row_range::EndKey::{EndKeyClosed, EndKeyOpen};
use google::bigtable::v2::row_range::StartKey::{StartKeyClosed, StartKeyOpen};
use google::bigtable::v2::ReadRowsRequest;
use std::fmt;
use std::marker::PhantomData;
use tokio::sync::Mutex;
use tonic::codegen::{Body, Bytes, StdError};
use tracing::{instrument, Span};

use super::inspect_grpc_error;
use observability::retry_logging;
use observability::retry_loop::{Retry, RetryError};

#[derive(Clone, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct RowKey(pub Vec<u8>);

impl fmt::Debug for RowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&Hex(&self.0), f)
    }
}

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct Cell {
    pub family: String,
    pub qualifier: Vec<u8>,
    pub timestamp: i64,
    pub value: Vec<u8>,
}

impl fmt::Debug for Cell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cell")
            .field("family", &self.family)
            .field("qualifier", &String::from_utf8_lossy(&self.qualifier))
            .field("timestamp", &self.timestamp)
            .field("value", &Hex(&self.value))
            .finish()
    }
}

struct Hex<'a>(&'a [u8]);

impl<'a> fmt::Debug for Hex<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

pub struct Reader<T>(PhantomData<T>);

impl<T> Reader<T>
where
    T: tonic::client::GrpcService<tonic::body::BoxBody> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    /// Runs a query and returns the resulting rows.
    ///
    /// See [`Self::read_column`] to return only the first cell for each row,
    /// [`Self::read_row`] to return only the first row, and
    /// [`Self::read_cell`] to return only the first cell of the first row.
    pub async fn read_rows(
        bigtable: &mut BigtableClient<T>,
        retry: Retry<'_>,
        request: ReadRowsRequest,
    ) -> Result<Vec<(RowKey, Vec<Cell>)>, RetryError<tonic::Status>> {
        let mut rows = Vec::new();
        Self::read_rows_stream(bigtable, retry, request, |key, cells| {
            rows.push((key, cells))
        })
        .await?;
        Ok(rows)
    }

    /// Runs a query and returns the first cell of each of the resulting rows.
    ///
    /// To prevent wasted work, the caller should restrict the query to return
    /// only one cell per row.
    pub async fn read_column(
        bigtable: &mut BigtableClient<T>,
        retry: Retry<'_>,
        request: ReadRowsRequest,
    ) -> Result<Vec<(RowKey, Cell)>, RetryError<tonic::Status>> {
        let mut rows = Vec::new();
        Self::read_rows_stream(bigtable, retry, request, |key, cells| {
            let cell = cells.into_iter().next().unwrap();
            rows.push((key, cell))
        })
        .await?;
        Ok(rows)
    }

    /// Runs a query and returns the first resulting row.
    ///
    /// To prevent wasted work, the caller should restrict the query to return
    /// only one row.
    pub async fn read_row(
        bigtable: &mut BigtableClient<T>,
        retry: Retry<'_>,
        request: ReadRowsRequest,
    ) -> Result<Option<(RowKey, Vec<Cell>)>, RetryError<tonic::Status>> {
        let mut row = None;
        Self::read_rows_stream(bigtable, retry, request, |key, cells| {
            row.get_or_insert((key, cells));
        })
        .await?;
        Ok(row)
    }

    /// Runs a query and returns the first cell of the first resulting row.
    ///
    /// To prevent wasted work, the caller should restrict the query to return
    /// only one row and one cell.
    pub async fn read_cell(
        bigtable: &mut BigtableClient<T>,
        retry: Retry<'_>,
        request: ReadRowsRequest,
    ) -> Result<Option<(RowKey, Cell)>, RetryError<tonic::Status>> {
        let mut row = None;
        Self::read_rows_stream(bigtable, retry, request, |key, cells| {
            let cell = cells.into_iter().next().unwrap();
            row.get_or_insert((key, cell));
        })
        .await?;
        Ok(row)
    }

    #[instrument(
        level = "trace",
        skip(bigtable, request, row_fn),
        fields(
            num_request_items,
            num_response_chunks,
            num_response_messages,
            num_response_rows,
            retry_count,
        )
    )]
    pub async fn read_rows_stream<F>(
        bigtable: &mut BigtableClient<T>,
        mut retry: Retry<'_>,
        request: ReadRowsRequest,
        row_fn: F,
    ) -> Result<(), RetryError<tonic::Status>>
    where
        F: FnMut(RowKey, Vec<Cell>),
    {
        validate_request_rows(&request);
        Span::current().record(
            "num_request_items",
            match &request.rows {
                Some(rows) => rows.row_keys.len() + rows.row_ranges.len(),
                None => 0,
            },
        );

        // The future below needs access to some mutable state. The future
        // won't outlive the retry loop, but Rust doesn't know that. See
        // <https://rust-lang.github.io/async-fundamentals-initiative/roadmap/async_closures.html>
        // and
        // <https://smallcultfollowing.com/babysteps/blog/2023/03/29/thoughts-on-async-closures/>.
        // A Mutex works around the problem.
        struct State<F> {
            row_fn: F,
            last_completed_row: Option<RowKey>,
            num_rows: usize,
            num_response_chunks: usize,
            num_response_messages: usize,
        }
        let state = Mutex::new(State {
            row_fn,
            last_completed_row: None,
            num_rows: 0,
            num_response_chunks: 0,
            num_response_messages: 0,
        });

        let run = |_| async {
            let mut state = state.lock().await;
            let mut stream = bigtable
                .clone()
                .read_rows(request.clone())
                .await
                .map_err(inspect_grpc_error)?
                .into_inner();

            let mut active_row: Option<RowBuffer> = None;
            while let Some(message) = stream.message().await.map_err(inspect_grpc_error)? {
                state.num_response_messages += 1;
                state.num_response_chunks += message.chunks.len();
                for chunk in message.chunks {
                    let complete_row;
                    (active_row, complete_row) = process_read_chunk(chunk, active_row);
                    if let Some((key, row)) = complete_row {
                        // On a retry, we ask for the same row ranges and get
                        // back duplicate results (or even rows that weren't
                        // there the first time or changed since then). We skip
                        // those result rows here. (We could be smarter about
                        // filtering down the requested row ranges instead, but
                        // that would add some complexity.)
                        let is_duplicate =
                            state.last_completed_row.as_ref().is_some_and(|completed| {
                                if request.reversed {
                                    key >= *completed
                                } else {
                                    key <= *completed
                                }
                            });
                        if !is_duplicate {
                            state.num_rows += 1;
                            (state.row_fn)(key.clone(), row);
                            state.last_completed_row = Some(key);
                        }
                    }
                }
            }
            assert!(
                active_row.is_none(),
                "ReadRowsResponse missing chunks: last row didn't complete",
            );
            Ok(())
        };

        let result = retry.retry(run, retry_logging!()).await;

        let state = state.into_inner();
        let span = Span::current();
        span.record("num_response_chunks", state.num_response_chunks);
        span.record("num_response_messages", state.num_response_messages);
        span.record("num_response_rows", state.num_rows);

        result
    }
}

fn validate_request_rows(request: &ReadRowsRequest) {
    let Some(rows) = &request.rows else {
        // `None` indicates to return all rows, which is valid.
        return;
    };

    assert!(
        !rows.row_keys.is_empty() || !rows.row_ranges.is_empty(),
        "Bigtable read request missing row keys or ranges: {request:#?}"
    );

    // Cloud Bigtable can return errors like this when the range given is
    // trivially empty:
    //
    // ```
    // Status { code: InvalidArgument, message: "Error in field
    // 'row_ranges' : Error in element #0 : start_key must be less than
    // end_key", ...
    // ```
    //
    // The exact conditions that Cloud Bigtable checks are not documented. As
    // of 2024-01-02, Cloud Bigtable will reject this range:
    //
    // ```
    // RowRange {
    //     start_key: Some(StartKeyOpen(log_key(group, LogIndex::FIRST))),
    //     end_key: Some(EndKeyClosed(log_key(group, LogIndex::FIRST))),
    // }
    // ```
    //
    // The emulator has less restrictive checks. It validates only that `start
    // <= end`, ignoring the closed vs open distinctions for the bounds.
    // Therefore, the emulator permits the range above that Cloud Bigtable
    // rejects. See
    // <https://github.com/googleapis/google-cloud-go/blob/d101980/bigtable/bttest/validation.go#L27>.
    //
    // The assertion here is stricter than the emulator's in an attempt to
    // approximate Cloud Bigtable's logic.
    assert!(
        rows.row_ranges
            .iter()
            .filter_map(|range| range.start_key.as_ref().zip(range.end_key.as_ref()))
            .all(|(start, end)| match (start, end) {
                (StartKeyClosed(start), EndKeyClosed(end)) => start <= end,
                (StartKeyClosed(start), EndKeyOpen(end)) => start < end,
                (StartKeyOpen(start), EndKeyClosed(end)) => start < end,
                (StartKeyOpen(start), EndKeyOpen(end)) => start < end,
            }),
        "Bigtable read row range cannot be trivially empty: {request:#?}"
    );
}

// In between processing chunks, there's either an active row with an active
// cell or there's no active row. This struct represents an active row.
#[derive(Debug, Eq, PartialEq)]
struct RowBuffer {
    row_key: RowKey,
    completed: Vec<Cell>, // done unless the row is reset
    cell: Cell,           // active
}

/// Processes a single chunk for a `ReadRowsResponse`.
///
/// The first item returned, if any, has information about the active row being
/// processed, which will be continued in the next chunk. The second item
/// returned, if any, is a completed row.
///
/// # Implementation notes
///
/// The response comes back in cell chunks, as described in the documentation
/// for `ReadRowsResponse` in `googleapis/google/bigtable/v2/bigtable.proto`.
///
/// There's plenty of similar code out there to parse read results which may be
/// worth comparing to:
///  - Rust, MIT,
///    <https://github.com/liufuyang/bigtable_rs/blob/main/bigtable_rs/src/bigtable/read_rows.rs>
///  - Rust, Apache-2.0, decode_read_rows_response in
///    <https://github.com/solana-labs/solana/blob/master/storage-bigtable/src/bigtable.rs#L320>
///  - C++, Apache-2.0,
///    <https://github.com/googleapis/google-cloud-cpp/tree/main/google/cloud/bigtable>
///  - Go, Apache-2.0,
///    <https://github.com/googleapis/google-cloud-go/blob/main/bigtable/reader.go>
fn process_read_chunk(
    chunk: CellChunk,
    active_row: Option<RowBuffer>,
) -> (Option<RowBuffer>, Option<(RowKey, Vec<Cell>)>) {
    let (row_key, mut completed, old_cell) = match active_row {
        // The chunk continues an existing row.
        Some(RowBuffer {
            row_key,
            completed,
            cell,
        }) if chunk.row_status != Some(RowStatus::ResetRow(true)) => {
            assert!(chunk.row_key.is_empty() || chunk.row_key == row_key.0);
            (row_key, completed, Some(cell))
        }

        // The chunk starts a new row or resets the current row.
        _ => {
            assert!(!chunk.row_key.is_empty());
            (RowKey(chunk.row_key), Vec::new(), None)
        }
    };

    // At this point, we have an active row and may or may not have an
    // active cell.

    let new_cell = match chunk.qualifier {
        // The chunk starts a new cell.
        Some(qualifier) => {
            let family = match chunk.family_name {
                Some(family) => family,
                None => match &old_cell {
                    Some(old_cell) => old_cell.family.clone(),
                    None => panic!("CellChunk missing column family name (no previous cell)"),
                },
            };

            if let Some(old_cell) = old_cell {
                completed.push(old_cell);
            }

            let mut value = chunk.value;
            if chunk.value_size != 0 {
                assert!(chunk.value_size > 0);
                value.reserve_exact(
                    usize::try_from(chunk.value_size)
                        .unwrap_or(0)
                        .saturating_sub(value.len()),
                );
            }
            Cell {
                family,
                qualifier,
                timestamp: chunk.timestamp_micros,
                value,
            }
        }

        // The chunk continues an existing cell.
        None => match old_cell {
            Some(mut cell) => {
                cell.value.extend(chunk.value);
                cell
            }
            None => panic!("got CellChunk with no qualifier but have no active cell"),
        },
    };

    // At this point, we have an active row and an active cell.
    match chunk.row_status {
        Some(RowStatus::CommitRow(true)) => {
            completed.push(new_cell);
            (None, Some((row_key, completed)))
        }

        _ => (
            Some(RowBuffer {
                row_key,
                completed,
                cell: new_cell,
            }),
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process_read_chunks(
        chunks: Vec<CellChunk>,
    ) -> (Vec<(RowKey, Vec<Cell>)>, Option<RowBuffer>) {
        let mut completed = Vec::new();
        let mut active_row = None;
        for chunk in chunks {
            let complete_row;
            (active_row, complete_row) = process_read_chunk(chunk, active_row);
            if let Some((key, row)) = complete_row {
                completed.push((key, row));
            }
        }
        (completed, active_row)
    }

    #[test]
    fn test_process_read_chunk() {
        let (completed, active_row) = process_read_chunks(vec![
            // Tests chunk starting new row.
            CellChunk {
                row_key: b"key1".to_vec(),
                family_name: Some(String::from("f1")),
                qualifier: Some(b"q1".to_vec()),
                timestamp_micros: 12,
                labels: Vec::new(),
                value: b"val1".to_vec(),
                value_size: 0,
                row_status: None,
            },
            // Tests chunk continuing existing row with key and family carried
            // over.
            CellChunk {
                row_key: Vec::new(),
                family_name: None,
                qualifier: Some(b"q2".to_vec()),
                timestamp_micros: 11,
                labels: Vec::new(),
                value: b"val2".to_vec(),
                value_size: 0,
                row_status: None,
            },
            // Tests chunk containing the first part of a continued cell.
            CellChunk {
                row_key: b"key1".to_vec(),
                family_name: Some(String::from("f1")),
                qualifier: Some(b"q3".to_vec()),
                timestamp_micros: 14,
                labels: Vec::new(),
                value: b"val4".to_vec(),
                value_size: 12,
                row_status: None,
            },
            // Tests chunk containing the middle part of a continued cell.
            CellChunk {
                row_key: Vec::new(),
                family_name: None,
                qualifier: None,
                timestamp_micros: 0,
                labels: Vec::new(),
                value: b"5678".to_vec(),
                value_size: 0,
                row_status: None,
            },
            // Tests chunk containing the final part of a continued cell.
            CellChunk {
                row_key: Vec::new(),
                family_name: None,
                qualifier: None,
                timestamp_micros: 0,
                labels: Vec::new(),
                value: b"9012".to_vec(),
                value_size: 0,
                row_status: None,
            },
            // Tests chunk continuing and committing existing row with explicit
            // key and family.
            CellChunk {
                row_key: b"key1".to_vec(),
                family_name: Some(String::from("f2")),
                qualifier: Some(b"q3".to_vec()),
                timestamp_micros: 13,
                labels: Vec::new(),
                value: b"val3".to_vec(),
                value_size: 0,
                row_status: Some(RowStatus::CommitRow(true)),
            },
            // Tests chunk that will be forgotten in a row reset.
            CellChunk {
                row_key: b"key2".to_vec(),
                family_name: Some(String::from("f1")),
                qualifier: Some(b"q1".to_vec()),
                timestamp_micros: 16,
                labels: Vec::new(),
                value: b"val4".to_vec(),
                value_size: 0,
                row_status: None,
            },
            // Tests chunk that resets row.
            CellChunk {
                row_key: b"key2".to_vec(),
                family_name: Some(String::from("f1")),
                qualifier: Some(b"q2".to_vec()),
                timestamp_micros: 16,
                labels: Vec::new(),
                value: b"val5".to_vec(),
                value_size: 0,
                row_status: Some(RowStatus::ResetRow(true)),
            },
            // Tests chunk after a reset.
            CellChunk {
                row_key: b"key2".to_vec(),
                family_name: Some(String::from("f3")),
                qualifier: Some(b"q6".to_vec()),
                timestamp_micros: 18,
                labels: Vec::new(),
                value: b"val6".to_vec(),
                value_size: 0,
                row_status: Some(RowStatus::CommitRow(true)),
            },
        ]);

        assert_eq!(active_row, None);
        assert_eq!(
            completed,
            vec![
                (
                    RowKey(b"key1".to_vec()),
                    vec![
                        Cell {
                            family: String::from("f1"),
                            qualifier: b"q1".to_vec(),
                            timestamp: 12,
                            value: b"val1".to_vec(),
                        },
                        Cell {
                            family: String::from("f1"),
                            qualifier: b"q2".to_vec(),
                            timestamp: 11,
                            value: b"val2".to_vec(),
                        },
                        Cell {
                            family: String::from("f1"),
                            qualifier: b"q3".to_vec(),
                            timestamp: 14,
                            value: b"val456789012".to_vec(),
                        },
                        Cell {
                            family: String::from("f2"),
                            qualifier: b"q3".to_vec(),
                            timestamp: 13,
                            value: b"val3".to_vec(),
                        }
                    ]
                ),
                (
                    RowKey(b"key2".to_vec()),
                    vec![
                        Cell {
                            family: String::from("f1"),
                            qualifier: b"q2".to_vec(),
                            timestamp: 16,
                            value: b"val5".to_vec(),
                        },
                        Cell {
                            family: String::from("f3"),
                            qualifier: b"q6".to_vec(),
                            timestamp: 18,
                            value: b"val6".to_vec(),
                        }
                    ]
                )
            ]
        );
    }
}
