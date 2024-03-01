use bigtable::read::Reader;
use bigtable::{bigtable_retries, inspect_grpc_error, Instance};
use google::bigtable::admin::v2::table::TimestampGranularity;
use google::bigtable::admin::v2::{ColumnFamily, CreateTableRequest, GcRule, Table};
use google::bigtable::v2::{
    mutation, read_rows_request, MutateRowRequest, Mutation, ReadRowsRequest,
};
use retry_loop::{retry_logging, Retry, RetryError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::warn;

use super::{BigtableTableAdminClient, StoreClient};

const FAMILY: &str = "f";
const COLUMN_NAME: &[u8] = &[b'c'];
const TABLE_NAME: &str = "tenants";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TenantConfiguration {
    pub capacity_ops_per_sec: usize,
}

impl TenantConfiguration {
    pub fn capacity_reqs_per_sec(&self) -> usize {
        self.capacity_ops_per_sec * 3
    }
}

pub fn tenant_config_table(instance: &Instance) -> String {
    format!("{path}/tables/{TABLE_NAME}", path = instance.path(),)
}

pub(crate) async fn initialize(
    bigtable: &mut BigtableTableAdminClient,
    instance: &Instance,
) -> Result<(), tonic::Status> {
    // This is not realm-specific, so it might already exist.
    if let Err(err) = bigtable
        .create_table(CreateTableRequest {
            parent: instance.path(),
            table_id: String::from(TABLE_NAME),
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
        {
            if err.code() != tonic::Code::AlreadyExists {
                return Err(err);
            }
        }
    }
    Ok(())
}

impl StoreClient {
    pub async fn get_tenants(
        &self,
    ) -> Result<Vec<(String, TenantConfiguration)>, RetryError<tonic::Status>> {
        let mut bigtable = self.0.bigtable.clone();
        let rows = match Reader::read_rows(
            &mut bigtable,
            Retry::new("read Bigtable tenant configuration table")
                .with(bigtable_retries)
                .with_metrics(&self.0.metrics, "store_client.tenants.get_tenants", &[]),
            ReadRowsRequest {
                table_name: tenant_config_table(&self.0.instance),
                app_profile_id: String::new(),
                rows: None, // everything
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
                    "couldn't read from Bigtable tenant configuration table \
                (the cluster manager should create it)"
                );
                return Ok(Vec::new());
            }
            Err(e) => return Err(e),
        };

        Ok(rows
            .into_iter()
            .map(|(rowkey, cells)| {
                let cell = cells
                    .into_iter()
                    .find(|c| c.family == FAMILY && c.qualifier == COLUMN_NAME)
                    .unwrap();
                let config = juicebox_marshalling::from_slice(&cell.value).expect("TODO");
                let tenant = String::from_utf8(rowkey.0).unwrap();
                (tenant, config)
            })
            .collect())
    }

    pub async fn update_tenant(
        &self,
        tenant: &str,
        config: &TenantConfiguration,
    ) -> Result<(), RetryError<tonic::Status>> {
        let run = |_| async {
            // Row keys are tenant name. There's one cell with the serialized config object
            let request = MutateRowRequest {
                table_name: tenant_config_table(&self.0.instance),
                app_profile_id: String::new(),
                row_key: tenant.as_bytes().to_vec(),
                mutations: vec![
                    Mutation {
                        mutation: Some(mutation::Mutation::DeleteFromFamily(
                            mutation::DeleteFromFamily {
                                family_name: String::from(FAMILY),
                            },
                        )),
                    },
                    Mutation {
                        mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                            family_name: String::from(FAMILY),
                            column_qualifier: COLUMN_NAME.to_vec(),
                            timestamp_micros: -1,
                            value: juicebox_marshalling::to_vec(config).expect("TODO"),
                        })),
                    },
                ],
            };
            self.0
                .bigtable
                .clone()
                .mutate_row(request)
                .await
                .map_err(inspect_grpc_error)?;
            Ok(())
        };

        Retry::new("updating tenant configuration")
            .with(bigtable_retries)
            .with_metrics(&self.0.metrics, "store_client.tenant.write", &[])
            .retry(run, retry_logging!())
            .await
    }
}
