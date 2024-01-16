use tracing::info;

use super::Manager;
use cluster_api::{TransferError, TransferSuccess};
use service_core::rpc::HandlerError;

impl Manager {
    pub(super) async fn handle_transfer(
        &self,
        req: cluster_api::TransferRequest,
    ) -> Result<Result<TransferSuccess, TransferError>, HandlerError> {
        info!(?req, "starting ownership transfer");
        let result = self.handle_transfer_inner(req).await;
        info!(?result, "ownership transfer done");
        Ok(result)
    }

    async fn handle_transfer_inner(
        &self,
        req: cluster_api::TransferRequest,
    ) -> Result<TransferSuccess, TransferError> {
        cluster_core::transfer(
            req.realm,
            req.source,
            req.destination,
            req.range,
            &self.0.store,
        )
        .await?;
        Ok(TransferSuccess {})
    }
}
