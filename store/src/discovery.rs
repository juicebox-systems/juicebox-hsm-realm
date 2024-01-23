use google::bigtable::admin::v2::table::TimestampGranularity;
use google::bigtable::admin::v2::{ColumnFamily, CreateTableRequest, GcRule, Table};
use google::bigtable::v2::row_range::{EndKey, StartKey};
use google::bigtable::v2::{
    mutate_rows_request, mutation, read_rows_request, MutateRowRequest, MutateRowsRequest,
    Mutation, ReadRowsRequest, RowRange, RowSet,
};
use std::collections::HashMap;
use std::str;
use std::time::{Duration, SystemTime};
use tracing::{debug, warn};
use url::Url;

use super::{to_micros, BigtableClient, BigtableTableAdminClient, Instance, RowKey, ServiceKind};
use bigtable::mutate::mutate_rows;
use bigtable::read::Reader;
use bigtable::{bigtable_retries, inspect_grpc_error};
use observability::metrics;
use retry_loop::{retry_logging, Retry, RetryError};

/// Agents should register themselves with service discovery this often.
pub const REGISTER_INTERVAL: Duration = Duration::from_secs(60 * 10);

/// After a failure registering with service discovery, agents should wait this
/// long before retrying.
pub const REGISTER_FAILURE_DELAY: Duration = Duration::from_secs(10);

/// Discovery records that haven't been updated in at least this log will be expired and deleted.
pub const EXPIRY_AGE: Duration = Duration::from_secs(60 * 21);

pub(crate) fn discovery_table(instance: &Instance) -> String {
    format!(
        "projects/{project}/instances/{instance}/tables/discovery",
        project = instance.project,
        instance = instance.instance
    )
}

fn discovery_table_brief() -> String {
    String::from("discovery")
}

/// Creates a little Bigtable table for service discovery.
pub(super) async fn initialize(
    mut bigtable: BigtableTableAdminClient,
    instance: &Instance,
) -> Result<(), tonic::Status> {
    // This is not realm-specific, so it might already exist.
    if let Err(e) = bigtable
        .create_table(CreateTableRequest {
            parent: instance.path(),
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
                change_stream_config: None,
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

pub(super) async fn get_addresses(
    mut bigtable: BigtableClient,
    instance: &Instance,
    kind: Option<ServiceKind>,
    metrics: metrics::Client,
) -> Result<Vec<(Url, ServiceKind)>, RetryError<tonic::Status>> {
    let row_set = kind.map(|s| RowSet {
        row_keys: Vec::new(),
        row_ranges: vec![RowRange {
            start_key: Some(StartKey::StartKeyClosed(vec![service_kind_key(s)])),
            end_key: Some(EndKey::EndKeyOpen(vec![service_kind_key(s)
                .checked_add(1)
                .unwrap()])),
        }],
    });
    let rows = match Reader::read_rows(
        &mut bigtable,
        Retry::new("read Bigtable service discovery table")
            .with(bigtable_retries)
            .with_metrics(&metrics, "store_client.discovery.get_addresses", &[]),
        ReadRowsRequest {
            table_name: discovery_table(instance),
            app_profile_id: String::new(),
            rows: row_set,
            filter: None,
            rows_limit: 0,
            request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            reversed: false,
        },
    )
    .await
    {
        Ok(rows) => rows,
        Err(RetryError::Fatal { error }) if error.code() == tonic::Code::NotFound => {
            warn!(
                error = error.message(),
                "couldn't read from Bigtable service discovery table \
                (the cluster manager should create it)"
            );
            return Ok(Vec::new());
        }
        Err(e) => return Err(e),
    };

    let mut addresses: Vec<(Url, ServiceKind)> = Vec::with_capacity(rows.len());
    let mut expired: Vec<RowKey> = Vec::new();
    let expire_when_before = SystemTime::now() - EXPIRY_AGE;
    'outer: for (row_key, cells) in rows {
        for cell in &cells {
            if cell.family == "f" {
                let written_at =
                    SystemTime::UNIX_EPOCH + Duration::from_micros(cell.timestamp as u64);
                if written_at < expire_when_before {
                    expired.push(row_key);
                    continue 'outer;
                }
                break;
            }
        }
        if let Some((address, svc_kind)) = parse_row_key(&row_key.0) {
            addresses.push((address, svc_kind))
        }
    }

    if !expired.is_empty() {
        let table_name = discovery_table(instance);
        tokio::spawn(delete_expired(bigtable, table_name, expired, metrics));
    }

    Ok(addresses)
}

async fn delete_expired(
    bigtable: BigtableClient,
    table_name: String,
    expired: Vec<RowKey>,
    metrics: metrics::Client,
) {
    let run = |_| async {
        let request = MutateRowsRequest {
            table_name: table_name.clone(),
            app_profile_id: String::new(),
            entries: expired
                .iter()
                .map(|key| mutate_rows_request::Entry {
                    row_key: key.0.clone(),
                    mutations: vec![Mutation {
                        mutation: Some(mutation::Mutation::DeleteFromRow(
                            mutation::DeleteFromRow {},
                        )),
                    }],
                })
                .collect(),
        };
        mutate_rows(&mut bigtable.clone(), request).await?;
        Ok(())
    };

    match Retry::new("deleting expired service discovery entries")
        .with(bigtable_retries)
        .with_metrics(&metrics, "store_client.discovery.delete_expired", &[])
        .retry(run, retry_logging!())
        .await
    {
        Ok(()) => {
            debug!(num = expired.len(), "removed expired discovery entries");
        }
        Err(_) => {
            // The Retry loop already logged a warning.
        }
    }
}

pub(super) async fn set_address(
    bigtable: &BigtableClient,
    instance: &Instance,
    address: &Url,
    kind: ServiceKind,
    // timestamp of the registration, typically SystemTime::now()
    timestamp: SystemTime,
    metrics: metrics::Client,
) -> Result<(), RetryError<tonic::Status>> {
    // Timestamps are in microseconds, but need to be rounded to milliseconds
    // (or coarser depending on table schema). Come back before April 11, 2262
    // to fix this.
    let timestamp_micros = to_micros(timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap());

    let run = |_| async {
        // Row keys are service_kind_key || url. There's one empty cell that has the timestamp.
        let mut row_key = Vec::with_capacity(1 + address.as_str().as_bytes().len());
        row_key.push(service_kind_key(kind));
        row_key.extend_from_slice(address.as_ref().as_bytes());

        let request = MutateRowRequest {
            table_name: discovery_table(instance),
            app_profile_id: String::new(),
            row_key,
            mutations: vec![
                Mutation {
                    mutation: Some(mutation::Mutation::DeleteFromFamily(
                        mutation::DeleteFromFamily {
                            family_name: String::from("f"),
                        },
                    )),
                },
                Mutation {
                    mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                        family_name: String::from("f"),
                        column_qualifier: b"t".to_vec(),
                        timestamp_micros,
                        value: Vec::new(),
                    })),
                },
            ],
        };
        bigtable
            .clone()
            .mutate_row(request)
            .await
            .map_err(inspect_grpc_error)?;
        Ok(())
    };

    Retry::new("registering service discovery address")
        .with(bigtable_retries)
        .with_metrics(&metrics, "store_client.discovery.set_address", &[])
        .retry(run, retry_logging!())
        .await
}

fn parse_row_key(b: &[u8]) -> Option<(Url, ServiceKind)> {
    // smallest valid row key is
    // [k]http://1.1.1.1
    if b.len() < 15 {
        return None;
    }
    let (kind, url) = b.split_at(1);
    if let Some(kind) = parse_service_kind(kind[0]) {
        if let Some(url) = url_from_bytes(url) {
            return Some((url, kind));
        }
    }
    None
}

fn service_kind_key(k: ServiceKind) -> u8 {
    match k {
        ServiceKind::Agent => b'a',
        ServiceKind::ClusterManager => b'c',
        ServiceKind::LoadBalancer => b'l',
    }
}

fn parse_service_kind(b: u8) -> Option<ServiceKind> {
    match b {
        b'a' => Some(ServiceKind::Agent),
        b'c' => Some(ServiceKind::ClusterManager),
        b'l' => Some(ServiceKind::LoadBalancer),
        _ => None,
    }
}

fn url_from_bytes(bytes: &[u8]) -> Option<Url> {
    let s = str::from_utf8(bytes).ok()?;
    Url::parse(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn can_parse_row_key() {
        assert_eq!(
            Some((
                "http://localhost:1234/".parse().unwrap(),
                ServiceKind::Agent
            )),
            parse_row_key(b"ahttp://localhost:1234/")
        );
        assert_eq!(
            Some((
                "http://127.0.0.1/".parse().unwrap(),
                ServiceKind::ClusterManager
            )),
            parse_row_key(b"chttp://127.0.0.1/")
        );
        assert_eq!(
            Some((
                "https://10.0.0.1/".parse().unwrap(),
                ServiceKind::LoadBalancer
            )),
            parse_row_key(b"lhttps://10.0.0.1/")
        );
        assert_eq!(None, parse_row_key(b"ahttp:"));
        assert_eq!(None, parse_row_key(b"zhttps://lb.juicebox.xyz"));
        assert_eq!(None, parse_row_key(b"l/lb.juicebox.xyz/some/req"));
    }
}
