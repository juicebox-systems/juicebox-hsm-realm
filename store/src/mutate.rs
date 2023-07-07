use google::bigtable::v2::MutateRowsRequest;
use tracing::instrument;

use super::BigtableClient;

#[derive(Debug)]
pub enum MutateRowsError {
    Tonic(tonic::Status),
    Mutation(google::rpc::Status),
}

#[instrument(level = "trace", skip(bigtable, request), fields(num_request_mutations = request.entries.len()))]
pub async fn mutate_rows(
    bigtable: &mut BigtableClient,
    request: MutateRowsRequest,
) -> Result<(), MutateRowsError> {
    let num_mutations = request.entries.len();
    let mut stream = bigtable
        .mutate_rows(request)
        .await
        .map_err(MutateRowsError::Tonic)?
        .into_inner();

    let mut acks = 0;
    while let Some(message) = stream.message().await.map_err(MutateRowsError::Tonic)? {
        acks += message.entries.len();
        for entry in message.entries {
            let status = entry
                .status
                .expect("MutateRowsResponse::Entry should have `status` set");
            if status.code != google::rpc::Code::Ok as i32 {
                return Err(MutateRowsError::Mutation(status));
            }
        }
    }

    assert_eq!(
        acks, num_mutations,
        "MutateRowsResponse should have one entry per mutation"
    );
    Ok(())
}
