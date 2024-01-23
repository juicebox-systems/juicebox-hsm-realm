use google::bigtable::v2::MutateRowsRequest;
use tracing::instrument;

use super::inspect_grpc_error;
use super::BigtableClient;
use observability::metrics_tag as tag;
use retry_loop::AttemptError;

#[derive(Debug, thiserror::Error)]
pub enum MutateRowsError {
    #[error("Tonic/gRPC error: {0}")]
    Tonic(tonic::Status),

    /// An individual mutation failed.
    ///
    /// TODO: Can this even happen in practice? If not, we can probably get rid
    /// of this enum.
    #[error("Bigtable mutation error (code: {}): {}", .0.code, .0.message)]
    Mutation(google::rpc::Status),
}

/// This is convenient for [retry loops](`observability::retry_loop`).
impl From<MutateRowsError> for AttemptError<MutateRowsError> {
    fn from(error: MutateRowsError) -> Self {
        match error {
            MutateRowsError::Tonic(error) => {
                inspect_grpc_error(error).map_err(MutateRowsError::Tonic)
            }
            MutateRowsError::Mutation(status) => AttemptError::Fatal {
                tags: vec![tag!("kind": "mutation"), tag!("rpc_status": status.code)],
                error: MutateRowsError::Mutation(status),
            },
        }
    }
}

/// Modifies zero or more rows in a single Bigtable table.
///
/// Callers must handle their own retries. This function doesn't retry the
/// request upon transient errors because not all requests are idempotent. For
/// example, a request could create a new cell, which could accumulate if
/// retried.
#[instrument(level = "trace", skip(bigtable, request), fields(num_request_mutations = request.entries.len()))]
pub async fn mutate_rows(
    bigtable: &mut BigtableClient,
    request: MutateRowsRequest,
) -> Result<(), MutateRowsError> {
    let num_mutations = request.entries.len();
    if num_mutations == 0 {
        return Ok(());
    }

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
