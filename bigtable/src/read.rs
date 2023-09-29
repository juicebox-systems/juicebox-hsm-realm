use google::bigtable::v2::read_rows_response::cell_chunk::RowStatus;
use google::bigtable::v2::read_rows_response::CellChunk;
use google::bigtable::v2::ReadRowsRequest;
use std::fmt;
use std::time::Duration;
use tonic::Code;
use tracing::{instrument, trace, warn, Span};

use super::BigtableClient;

#[derive(Clone, Hash, Eq, PartialEq)]
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

pub async fn read_rows(
    bigtable: &mut BigtableClient,
    request: ReadRowsRequest,
) -> Result<Vec<(RowKey, Vec<Cell>)>, tonic::Status> {
    let mut rows = Vec::new();
    read_rows_stream(bigtable, request, |key, cells| rows.push((key, cells)))
        .await
        .map(|_| rows)
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
    bigtable: &mut BigtableClient,
    request: ReadRowsRequest,
    mut row_fn: F,
) -> Result<(), tonic::Status>
where
    F: FnMut(RowKey, Vec<Cell>),
{
    Span::current().record(
        "num_request_items",
        match &request.rows {
            Some(rows) => rows.row_keys.len() + rows.row_ranges.len(),
            None => 0,
        },
    );

    let mut retry_count = 0;
    'outer: loop {
        let mut stream = bigtable.read_rows(request.clone()).await?.into_inner();
        let mut active_row: Option<RowBuffer> = None;
        let mut num_rows: usize = 0;
        let mut num_response_chunks: usize = 0;
        let mut num_response_messages: usize = 0;
        loop {
            match stream.message().await {
                Err(e) => {
                    // TODO, this seems to be a bug in hyper, in that it doesn't handle RST properly
                    // https://github.com/hyperium/hyper/issues/2872
                    warn!(?e, code=?e.code(), "stream.message error during read_rows");
                    if e.code() == Code::Internal {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                        trace!("retrying read_rows");
                        retry_count += 1;
                        continue 'outer;
                    } else {
                        return Err(e);
                    }
                }
                Ok(None) => break,
                Ok(Some(message)) => {
                    num_response_messages += 1;
                    num_response_chunks += message.chunks.len();
                    for chunk in message.chunks {
                        let complete_row;
                        (active_row, complete_row) = process_read_chunk(chunk, active_row);
                        if let Some((key, row)) = complete_row {
                            num_rows += 1;
                            row_fn(key, row);
                        }
                    }
                }
            };
        }
        assert!(
            active_row.is_none(),
            "ReadRowsResponse missing chunks: last row didn't complete",
        );
        Span::current().record("num_response_chunks", num_response_chunks);
        Span::current().record("num_response_messages", num_response_messages);
        Span::current().record("num_response_rows", num_rows);
        Span::current().record("retry_count", retry_count);
        return Ok(());
    }
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
