use google::bigtable::admin::v2::table::TimestampGranularity;
use google::bigtable::admin::v2::{ColumnFamily, CreateTableRequest, GcRule, Table};
use google::bigtable::v2::row_range::{EndKey, StartKey};
use google::bigtable::v2::{
    mutate_rows_request, mutation, read_rows_request, MutateRowRequest, MutateRowResponse,
    MutateRowsRequest, Mutation, ReadRowsRequest, RowRange, RowSet,
};
use std::collections::HashMap;
use std::str;
use std::time::{Duration, SystemTime};
use tracing::{debug, warn};
use url::Url;

use super::{
    mutate_rows, read_rows, BigtableClient, BigtableTableAdminClient, Instance, RowKey, ServiceKind,
};
use observability::logging::Spew;

/// Agents should register themselves with service discovery this often.
pub const REGISTER_INTERVAL: Duration = Duration::from_secs(60 * 10);

/// After a failure registering with service discovery, agents should wait this
/// long before retrying.
pub const REGISTER_FAILURE_DELAY: Duration = Duration::from_secs(10);

/// Discovery records that haven't been updated in at least this log will be expired and deleted.
pub const EXPIRY_AGE: Duration = Duration::from_secs(60 * 21);

static DISCOVERY_TABLE_SPEW: Spew = Spew::new();

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
) -> Result<Vec<(Url, ServiceKind)>, tonic::Status> {
    let row_set = kind.map(|s| RowSet {
        row_keys: Vec::new(),
        row_ranges: vec![RowRange {
            start_key: Some(StartKey::StartKeyClosed(vec![service_kind_key(s)])),
            end_key: Some(EndKey::EndKeyOpen(vec![service_kind_key(s)
                .checked_add(1)
                .unwrap()])),
        }],
    });
    let rows = match read_rows(
        &mut bigtable,
        ReadRowsRequest {
            table_name: discovery_table(instance),
            app_profile_id: String::new(),
            rows: row_set,
            filter: None,
            rows_limit: 0,
            request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
        },
    )
    .await
    {
        Ok(rows) => rows,
        Err(e) if e.code() == tonic::Code::NotFound => {
            if let Some(suppressed) = DISCOVERY_TABLE_SPEW.ok() {
                warn!(
                    error = e.message(),
                    suppressed,
                    "couldn't read from Bigtable service discovery table \
                    (the cluster manager should create it)"
                );
            }
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
        tokio::spawn(async move {
            let len = expired.len();
            let r = mutate_rows(
                &mut bigtable,
                MutateRowsRequest {
                    table_name,
                    app_profile_id: String::new(),
                    entries: expired
                        .into_iter()
                        .map(|key| mutate_rows_request::Entry {
                            row_key: key.0,
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

    Ok(addresses)
}

pub(super) async fn set_address(
    mut bigtable: BigtableClient,
    instance: &Instance,
    address: &Url,
    kind: ServiceKind,
    // timestamp of the registration, typically SystemTime::now()
    timestamp: SystemTime,
) -> Result<(), tonic::Status> {
    // Timestamps are in microseconds, but need to be rounded to milliseconds
    // (or coarser depending on table schema). Come back before April 11, 2262
    // to fix this.
    let timestamp_micros = (timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        * 1000)
        .try_into()
        .unwrap();

    // Row keys are service_kind_key || url. There's one empty cell that has the timestamp.
    let mut row_key = Vec::with_capacity(1 + address.as_str().as_bytes().len());
    row_key.push(service_kind_key(kind));
    row_key.extend_from_slice(address.as_ref().as_bytes());

    let MutateRowResponse { /* empty */ } =
            bigtable
            .mutate_row(MutateRowRequest {
                table_name: discovery_table(instance),
                app_profile_id: String::new(),
                row_key,
                mutations: vec![Mutation {
                    mutation: Some(mutation::Mutation::DeleteFromFamily(mutation::DeleteFromFamily {
                        family_name: String::from("f"),
                    })),
                },
                Mutation {
                    mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                        family_name: String::from("f"),
                        column_qualifier: b"t".to_vec(),
                        timestamp_micros,
                        value: Vec::new(),
                    })),
               }],
            })
            .await?
            .into_inner();
    Ok(())
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
