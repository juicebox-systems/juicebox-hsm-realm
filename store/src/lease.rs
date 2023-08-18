use google::bigtable::admin::v2::table::TimestampGranularity;
use google::bigtable::admin::v2::{ColumnFamily, CreateTableRequest, GcRule, Table};
use google::bigtable::v2::mutation::DeleteFromRow;
use google::bigtable::v2::value_range::{EndValue, StartValue};
use google::bigtable::v2::{
    mutation, row_filter::Filter, CheckAndMutateRowRequest, Mutation, RowFilter, TimestampRange,
    ValueRange,
};
use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::ExtendLeaseError;

use super::{to_micros, BigtableClient, BigtableTableAdminClient, Instance, Lease, LeaseKey};

const FAMILY: &str = "f";
const OWNER_COL: &[u8] = b"o";
const ID_COL: &[u8] = b"id";

fn lease_table(instance: &Instance) -> String {
    format!(
        "projects/{project}/instances/{instance}/tables/lease",
        project = instance.project,
        instance = instance.instance
    )
}

fn lease_table_brief() -> String {
    String::from("lease")
}

/// Creates a little Bigtable table for leases.
pub(super) async fn initialize(
    mut bigtable: BigtableTableAdminClient,
    instance: &Instance,
) -> Result<(), tonic::Status> {
    // This is not realm-specific, so it might already exist.
    if let Err(e) = bigtable
        .create_table(CreateTableRequest {
            parent: instance.path(),
            table_id: lease_table_brief(),
            table: Some(Table {
                name: String::from(""),
                cluster_states: HashMap::new(),
                column_families: HashMap::from([(
                    FAMILY.to_string(),
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

pub(crate) async fn obtain(
    mut bigtable: BigtableClient,
    instance: &Instance,
    key: LeaseKey,
    owner: String,
    duration: Duration,
    timestamp: SystemTime, // Timestamp of the lease start, typically SystemTime::now()
) -> Result<Option<Lease>, tonic::Status> {
    // Timestamps are in microseconds, but need to be rounded to milliseconds
    // (or coarser depending on table schema). Come back before April 11, 2262
    // to fix this.
    let now_micros = to_micros(timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap());
    let expires = now_micros + to_micros(duration);

    let mut id = vec![0u8; 16];
    OsRng.fill_bytes(&mut id);

    let response = bigtable
        .check_and_mutate_row(CheckAndMutateRowRequest {
            table_name: lease_table(instance),
            app_profile_id: String::new(),
            row_key: key.0.clone(),
            predicate_filter: Some(RowFilter {
                filter: Some(Filter::TimestampRangeFilter(TimestampRange {
                    // matches cells where the expires timestamp >= now
                    start_timestamp_micros: now_micros,
                    end_timestamp_micros: 0,
                })),
            }),
            true_mutations: Vec::new(),
            false_mutations: vec![
                Mutation {
                    mutation: Some(mutation::Mutation::DeleteFromRow(DeleteFromRow {})),
                },
                Mutation {
                    mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                        family_name: FAMILY.to_string(),
                        column_qualifier: OWNER_COL.to_vec(),
                        timestamp_micros: expires,
                        value: owner.as_bytes().to_vec(),
                    })),
                },
                Mutation {
                    mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                        family_name: FAMILY.to_string(),
                        column_qualifier: ID_COL.to_vec(),
                        timestamp_micros: expires,
                        value: id.clone(),
                    })),
                },
            ],
        })
        .await?;

    if response.into_inner().predicate_matched {
        Ok(None)
    } else {
        Ok(Some(Lease {
            key: key.0,
            id,
            owner,
        }))
    }
}

pub(crate) async fn extend(
    mut bigtable: BigtableClient,
    instance: &Instance,
    lease: &Lease,
    duration: Duration,
    timestamp: SystemTime,
) -> Result<(), ExtendLeaseError> {
    let now_micros = to_micros(timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap());
    let expires: i64 = now_micros + to_micros(duration);

    let response = bigtable
        .check_and_mutate_row(CheckAndMutateRowRequest {
            table_name: lease_table(instance),
            app_profile_id: String::new(),
            row_key: lease.key.clone(),
            predicate_filter: Some(RowFilter {
                filter: Some(Filter::ValueRangeFilter(ValueRange {
                    start_value: Some(StartValue::StartValueClosed(lease.id.clone())),
                    end_value: Some(EndValue::EndValueClosed(lease.id.clone())),
                })),
            }),
            false_mutations: Vec::new(),
            true_mutations: vec![
                Mutation {
                    mutation: Some(mutation::Mutation::DeleteFromRow(DeleteFromRow {})),
                },
                Mutation {
                    mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                        family_name: FAMILY.to_string(),
                        column_qualifier: OWNER_COL.to_vec(),
                        timestamp_micros: expires,
                        value: lease.owner.as_bytes().to_vec(),
                    })),
                },
                Mutation {
                    mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                        family_name: FAMILY.to_string(),
                        column_qualifier: ID_COL.to_vec(),
                        timestamp_micros: expires,
                        value: lease.id.clone(),
                    })),
                },
            ],
        })
        .await?;

    if response.into_inner().predicate_matched {
        Ok(())
    } else {
        Err(ExtendLeaseError::NotOwner)
    }
}

pub(crate) async fn terminate(
    mut bigtable: BigtableClient,
    instance: &Instance,
    lease: Lease,
) -> Result<(), tonic::Status> {
    bigtable
        .check_and_mutate_row(CheckAndMutateRowRequest {
            table_name: lease_table(instance),
            app_profile_id: String::new(),
            row_key: lease.key,
            predicate_filter: Some(RowFilter {
                filter: Some(Filter::ValueRangeFilter(ValueRange {
                    start_value: Some(StartValue::StartValueClosed(lease.id.clone())),
                    end_value: Some(EndValue::EndValueClosed(lease.id)),
                })),
            }),
            false_mutations: Vec::new(),
            true_mutations: vec![Mutation {
                mutation: Some(mutation::Mutation::DeleteFromRow(DeleteFromRow {})),
            }],
        })
        .await?;
    Ok(())
}
