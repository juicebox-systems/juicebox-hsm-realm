use crate::autogen::google;

use google::bigtable::admin::v2::table::TimestampGranularity;
use google::bigtable::admin::v2::{ColumnFamily, CreateTableRequest, GcRule, Table};
use google::bigtable::v2::{
    mutate_rows_request, mutation, read_rows_request, row_filter, MutateRowRequest,
    MutateRowResponse, MutateRowsRequest, Mutation, ReadRowsRequest, RowFilter,
};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tracing::{debug, trace, warn};
use url::Url;

use super::{mutate_rows, read_rows, BigtableClient, BigtableTableAdminClient, Instance};
use crate::logging::Spew;
use hsmcore::hsm::types::HsmId;

/// Agents should register themselves with service discovery this often.
pub const REGISTER_INTERVAL: Duration = Duration::from_secs(60 * 10);

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
) -> Result<Vec<(HsmId, Url)>, tonic::Status> {
    let rows = match read_rows(
        &mut bigtable,
        ReadRowsRequest {
            table_name: discovery_table(instance),
            app_profile_id: String::new(),
            rows: None, // read all rows
            filter: Some(RowFilter {
                filter: Some(row_filter::Filter::CellsPerColumnLimitFilter(1)),
            }),
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
                        "couldn't read from Bigtable service discovery table (the cluster manager should create it)"
                    );
            }
            return Ok(Vec::new());
        }
        Err(e) => return Err(e),
    };

    let mut addresses = Vec::with_capacity(rows.len());
    let mut expired = Vec::new();
    let expire_when_before = SystemTime::now() - EXPIRY_AGE;
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
        let mut bigtable = bigtable.clone();
        let table = discovery_table(instance);
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

pub(super) async fn set_address(
    mut bigtable: BigtableClient,
    instance: &Instance,
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

    let MutateRowResponse { /* empty */ } =
            bigtable
            .mutate_row(MutateRowRequest {
                table_name: discovery_table(instance),
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
}
