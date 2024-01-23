use google::bigtable::v2::{read_rows_request, ReadRowsRequest};
use std::io;
use std::time::{Duration, SystemTime};
use tracing::warn;

use bigtable::read::Reader;
use hsm_api::{GroupId, LogIndex};
use juicebox_sdk::RealmId;
use retry_loop::Retry;
use store::log::testing::{log_table, parse_log_key};
use store::StoreClient;

struct LogAccumulator {
    group: GroupId,
    start_row: LogIndex,
    end_row: LogIndex,
    entries: u64,
    entry_rows: u64,
    tombstones: u64,
    expired_tombstones: u64,
    bytes: u64,
}

fn flush<W: io::Write>(mut w: W, stats: Option<LogAccumulator>) -> Result<(), io::Error> {
    if let Some(LogAccumulator {
        group: _,
        start_row,
        end_row,
        entries,
        entry_rows,
        tombstones,
        expired_tombstones,
        bytes,
    }) = stats
    {
        // The header with the group ID is printed when the group is
        // discovered (to show that something is in progress).
        writeln!(
            w,
            "  row index {} through {}",
            commas(start_row.0),
            commas(end_row.0)
        )?;
        writeln!(
            w,
            "  {} entry rows containing {} entries",
            commas(entry_rows),
            commas(entries)
        )?;
        writeln!(
            w,
            "  {} tombstones ({:.02}% expired)",
            commas(tombstones),
            if tombstones == 0 {
                0.0
            } else {
                (expired_tombstones as f64) / (tombstones as f64) * 100.0
            }
        )?;
        writeln!(w, "  approx. {} bytes", commas(bytes))?;
    }
    Ok(())
}

pub(crate) async fn print_log_stats(realm: RealmId, store: &StoreClient) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let now = SystemTime::now();

    let instance = store::testing::get_instance(store);
    let mut bigtable = store::testing::get_connection(store);
    let request = ReadRowsRequest {
        table_name: log_table(&instance, &realm),
        app_profile_id: String::new(),
        rows: None,
        filter: None,
        rows_limit: 0,
        request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
        reversed: false,
    };

    let mut last: Option<LogAccumulator> = None;

    Reader::read_rows_stream(&mut bigtable, Retry::disabled(), request, |key, cells| {
        match parse_log_key(&key) {
            Err(_generic) => {
                warn!("failed to parse log row key: {key:?}");
            }

            Ok((group, index)) => {
                if last.as_ref().is_some_and(|last| last.group != group) {
                    flush(&stdout, last.take()).unwrap();
                }

                let last = last.get_or_insert_with(|| {
                    println!("log for group {group:?}:");
                    LogAccumulator {
                        group,
                        start_row: index,
                        end_row: index,
                        entries: 0,
                        entry_rows: 0,
                        tombstones: 0,
                        expired_tombstones: 0,
                        bytes: 0,
                    }
                });

                last.start_row = index;
                let first_cell = &cells[0];
                if first_cell.family == "f" {
                    last.entry_rows += 1;
                    last.entries += u64::try_from(cells.len()).unwrap();
                } else if first_cell.family == "t" {
                    last.tombstones += 1;
                    let expires_at = SystemTime::UNIX_EPOCH
                        + Duration::from_micros(u64::try_from(first_cell.timestamp).unwrap())
                        + Duration::from_secs(60 * 60 * 24 * 7);
                    if expires_at < now {
                        last.expired_tombstones += 1;
                    }
                } else {
                    warn!("unrecognized log column family: {:?}", first_cell.family);
                }
                last.bytes += u64::try_from(
                    key.0.len()
                        + cells
                            .iter()
                            .map(|cell| {
                                cell.family.len() + cell.qualifier.len() +
                                /* timestamp: */ 8 + cell.value.len()
                            })
                            .sum::<usize>(),
                )
                .unwrap();
            }
        }
    })
    .await
    .map_err(|err| err.last().unwrap())?;
    flush(&stdout, last).unwrap();

    Ok(())
}

/// Stringify an integer with thousands separators.
fn commas(input: u64) -> String {
    let input = input.to_string().into_bytes();
    let out_len = input.len() + (input.len() - 1) / 3;
    let mut output = String::with_capacity(out_len);
    let mut first = true;
    for group in input.rchunks(3).rev() {
        if first {
            first = false;
        } else {
            output.push(',');
        }
        for char in group {
            output.push(char::from(*char));
        }
    }
    assert_eq!(out_len, output.len());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flush() {
        let mut buf: Vec<u8> = Vec::new();
        flush(&mut buf, None).unwrap();
        assert!(buf.is_empty());

        flush(
            &mut buf,
            Some(LogAccumulator {
                group: GroupId([0xde; 16]),
                start_row: LogIndex(2_096_206),
                end_row: LogIndex(2_491_820),
                entries: 952,
                entry_rows: 23,
                tombstones: 391873,
                expired_tombstones: 92350,
                bytes: 13_324_001,
            }),
        )
        .unwrap();
        assert_eq!(
            "  row index 2,096,206 through 2,491,820
  23 entry rows containing 952 entries
  391,873 tombstones (23.57% expired)
  approx. 13,324,001 bytes
",
            String::from_utf8(buf).unwrap()
        );
    }

    #[test]
    fn test_commas() {
        assert_eq!("0", commas(0));
        assert_eq!("1", commas(1));
        assert_eq!("12", commas(12));
        assert_eq!("123", commas(123));
        assert_eq!("1,234", commas(1234));
        assert_eq!("12,345", commas(12345));
        assert_eq!("123,456", commas(123456));
        assert_eq!("1,234,567", commas(1234567));
        assert_eq!("12,345,678", commas(12345678));
        assert_eq!("123,456,789", commas(123456789));
        assert_eq!("1,234,567,890", commas(1234567890));
    }
}
