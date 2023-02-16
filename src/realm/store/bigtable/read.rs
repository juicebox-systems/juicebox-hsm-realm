use crate::autogen::google;
use google::bigtable::v2::read_rows_response::cell_chunk::RowStatus;
use google::bigtable::v2::read_rows_response::CellChunk;
use google::bigtable::v2::ReadRowsRequest;
use std::collections::HashMap;
use std::fmt;

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
        f.debug_struct("Column")
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
) -> Result<HashMap<RowKey, Vec<Cell>>, tonic::Status> {
    let mut stream = bigtable.read_rows(request).await?.into_inner();
    let mut rows = HashMap::new();
    let mut active_row: Option<RowBuffer> = None;
    while let Some(message) = stream.message().await? {
        for chunk in message.chunks {
            let complete_row;
            (active_row, complete_row) = process_read_chunk(chunk, active_row);
            if let Some((key, row)) = complete_row {
                rows.insert(key, row);
            }
        }
    }
    assert!(
        active_row.is_none(),
        "ReadRowsResponse missing chunks: last row didn't complete",
    );
    Ok(rows)
}

// In between processing chunks, there's either an active row with an active
// cell or there's no active row. This struct represents an active row.
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
    let (row_key, mut completed, cell) = match active_row {
        // The chunk starts a new row.
        None => {
            assert!(!chunk.row_key.is_empty());
            (RowKey(chunk.row_key), Vec::new(), None)
        }

        // The chunk continues an existing row.
        Some(RowBuffer {
            row_key,
            completed,
            cell,
        }) => {
            assert!(chunk.row_key.is_empty() || chunk.row_key == row_key.0);
            (row_key, completed, Some(cell))
        }
    };

    // At this point, we have an active row and may or may not have an
    // active cell.

    let cell = match chunk.qualifier {
        // The chunk starts a new cell.
        Some(qualifier) => {
            if let Some(cell) = cell {
                completed.push(cell);
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
                family: chunk
                    .family_name
                    .expect("CellChunk missing column family name"),
                qualifier,
                timestamp: chunk.timestamp_micros,
                value,
            }
        }

        // The chunk continues an existing cell.
        None => match cell {
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
            completed.push(cell);
            (None, Some((row_key, completed)))
        }

        Some(RowStatus::ResetRow(true)) => (None, None),

        _ => (
            Some(RowBuffer {
                row_key,
                completed,
                cell,
            }),
            None,
        ),
    }
}
