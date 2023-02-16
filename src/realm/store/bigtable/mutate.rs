use crate::autogen::google;
use google::bigtable::v2::MutateRowsRequest;

use super::BigtableClient;

pub enum MutateRowsError {
    Tonic(tonic::Status),
    Mutation(google::rpc::Status),
}

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
