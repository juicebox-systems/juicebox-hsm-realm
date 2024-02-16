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

use super::{
    to_micros, BigtableClient, BigtableTableAdminClient, ExtendLeaseError, Instance, Lease,
    LeaseKey,
};
use bigtable::{bigtable_retries, inspect_grpc_error};
use observability::{metrics, metrics_tag as tag};
use retry_loop::{retry_logging, AttemptError, Retry, RetryError};
use tracing::warn;

const FAMILY: &str = "f";
const OWNER_COL: &[u8] = b"o";
const ID_COL: &[u8] = b"id";

pub(crate) fn lease_table(instance: &Instance) -> String {
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
    bigtable: &mut BigtableTableAdminClient,
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
                granularity: TimestampGranularity::Unspecified.into(),
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
    bigtable: &BigtableClient,
    instance: &Instance,
    key: LeaseKey,
    owner: String,
    duration: Duration,
    timestamp: SystemTime, // Timestamp of the lease start, typically SystemTime::now()
    metrics: &metrics::Client,
) -> Result<Option<Lease>, RetryError<tonic::Status>> {
    // Timestamps are in microseconds, but need to be rounded to milliseconds
    // (or coarser depending on table schema). Come back before April 11, 2262
    // to fix this.
    let now_micros = to_micros(timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap());
    let expires = now_micros + to_micros(duration);

    let mut id_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut id_bytes);
    let id = hex::encode(id_bytes).into_bytes();
    let key = key.into_bigtable_key();

    let run = |_| async {
        let request = CheckAndMutateRowRequest {
            table_name: lease_table(instance),
            app_profile_id: String::new(),
            row_key: key.clone(),
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
                        value: owner.as_bytes().to_owned(),
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
        };
        let response = bigtable
            .clone()
            .check_and_mutate_row(request)
            .await
            .map_err(inspect_grpc_error)?;
        Ok(!response.into_inner().predicate_matched)
    };

    Ok(Retry::new("obtaining lease")
        .with(bigtable_retries)
        .with_metrics(metrics, "store_client.obtain_lease", metrics::NO_TAGS)
        .retry(run, retry_logging!())
        .await?
        .then_some(Lease {
            key,
            id,
            owner,
            expires: expires.try_into().unwrap(),
        }))
}

pub(crate) async fn extend(
    bigtable: &BigtableClient,
    instance: &Instance,
    lease: Lease,
    duration: Duration,
    timestamp: SystemTime,
    metrics: &metrics::Client,
) -> Result<Lease, RetryError<ExtendLeaseError, tonic::Status>> {
    let now_micros = to_micros(timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap());
    let expires: i64 = now_micros + to_micros(duration);

    let run = |_| async {
        let request = CheckAndMutateRowRequest {
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
        };

        let response = bigtable
            .clone()
            .check_and_mutate_row(request)
            .await
            .map_err(|err| inspect_grpc_error(err).map_fatal_err(ExtendLeaseError::Rpc))?;

        if response.into_inner().predicate_matched {
            Ok(())
        } else {
            Err(AttemptError::Fatal {
                error: ExtendLeaseError::NotOwner,
                tags: vec![tag!("kind": "not_owner")],
            })
        }
    };

    Retry::new("extending lease")
        .with(bigtable_retries)
        .with_metrics(metrics, "store_client.extend_lease", metrics::NO_TAGS)
        .retry(run, retry_logging!())
        .await?;
    Ok(Lease {
        key: lease.key,
        id: lease.id,
        owner: lease.owner,
        expires: expires.try_into().unwrap(),
    })
}

pub(crate) async fn terminate(
    bigtable: &BigtableClient,
    instance: &Instance,
    lease: Lease,
    metrics: &metrics::Client,
) -> Result<(), RetryError<tonic::Status>> {
    let run = |_| async {
        let request = CheckAndMutateRowRequest {
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
            true_mutations: vec![Mutation {
                mutation: Some(mutation::Mutation::DeleteFromRow(DeleteFromRow {})),
            }],
        };
        let response = bigtable
            .clone()
            .check_and_mutate_row(request)
            .await
            .map_err(inspect_grpc_error)?
            .into_inner();
        if !response.predicate_matched {
            warn!("terminated lease had already been deleted");
        }
        Ok(())
    };

    Retry::new("terminating lease")
        .with(bigtable_retries)
        .with_metrics(metrics, "store_client.terminate_lease", metrics::NO_TAGS)
        .retry(run, retry_logging!())
        .await
}
