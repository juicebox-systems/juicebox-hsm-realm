use crate::autogen::google;
use google::bigtable::v2 as bigtable;

use bigtable::bigtable_client::BigtableClient;
use bigtable::mutation;
use bigtable::{
    read_rows_request, row_filter, MutateRowRequest, Mutation, ReadRowsRequest, RowFilter, RowSet,
};
use tracing::info;

pub async fn demo() {
    info!("connecting to bigtable");
    let mut bigtable = BigtableClient::connect(tonic::transport::Endpoint::from_static(
        "http://127.0.0.1:9000/",
    ))
    .await
    .expect("TODO");

    info!("writing to bigtable");
    let resp = bigtable
        .mutate_row(MutateRowRequest {
            table_name: String::from("projects/prj/instances/inst/tables/tab"),
            app_profile_id: String::from("app"),
            row_key: b"key".to_vec(),
            mutations: vec![Mutation {
                mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                    family_name: String::from("fam"),
                    column_qualifier: b"value".to_vec(),
                    timestamp_micros: -1,
                    value: b"hello world".to_vec(),
                })),
            }],
        })
        .await
        .expect("TODO");
    if resp.metadata().get("grpc-status") != Some(&(i32::from(google::rpc::Code::Ok)).into()) {
        todo!("error from mutate_row: {resp:#?}");
    }
    info!("wrote to bigtable");

    let resp = bigtable
        .read_rows(ReadRowsRequest {
            table_name: String::from("projects/prj/instances/inst/tables/tab"),
            app_profile_id: String::from("app"),
            rows: Some(RowSet {
                row_keys: vec![b"key".to_vec()],
                row_ranges: vec![],
            }),
            filter: Some(RowFilter {
                filter: Some(row_filter::Filter::CellsPerRowLimitFilter(1)),
            }),
            rows_limit: 0,
            request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
        })
        .await
        .expect("TODO");

    let message = resp.into_inner().message().await.expect("TODO");
    if let Some(response) = message {
        let mut value = None;
        for chunk in response.chunks {
            if chunk.qualifier.as_deref() == Some(b"value") {
                value = Some(chunk.value);
            }
        }
        match value {
            Some(value) => info!("read from bigtable: {}", String::from_utf8_lossy(&value)),
            None => todo!(),
        }
    } else {
        todo!();
    }
}
