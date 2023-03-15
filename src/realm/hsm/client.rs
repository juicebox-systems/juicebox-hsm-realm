use async_trait::async_trait;
use std::fmt::{self, Debug};
use std::sync::Arc;
use tokio::time::Instant;
use tracing::{instrument, span::Span, trace, warn};

use hsmcore::{
    hsm::rpc::HsmRpc,
    marshalling::{self, DeserializationError, SerializationError},
};

/// The HSM signalled that the request processing failed, likely due to
/// serialization or deserialization issues.
#[derive(Debug)]
pub struct HsmRpcError;

#[async_trait]
pub trait Transport: fmt::Debug + Send + Sync {
    type Error: fmt::Debug
        + From<SerializationError>
        + From<DeserializationError>
        + From<HsmRpcError>
        + Send;

    async fn send_rpc_msg(&self, msg_name: &str, msg: Vec<u8>) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug)]
pub struct HsmClient<T> {
    transport: Arc<T>,
}
impl<T> Clone for HsmClient<T> {
    fn clone(&self) -> Self {
        Self {
            transport: self.transport.clone(),
        }
    }
}

impl<T: Transport> HsmClient<T> {
    pub fn new(t: T) -> Self {
        Self {
            transport: Arc::new(t),
        }
    }

    #[instrument(level = "trace", name = "HsmClient::send", skip(r), fields(req_name))]
    pub async fn send<RPC: HsmRpc + Send>(&self, r: RPC) -> Result<RPC::Response, T::Error> {
        let hsm_req = r.to_req();
        let req_name = hsm_req.name();
        Span::current().record("req_name", req_name);
        let req_bytes = marshalling::to_vec(&hsm_req)?;

        trace!(
            num_bytes = req_bytes.len(),
            req = req_name,
            "sending HSM RPC request"
        );
        let start = Instant::now();
        let res_bytes = self.transport.send_rpc_msg(req_name, req_bytes).await?;

        let dur = start.elapsed();
        if res_bytes.is_empty() {
            warn!(req = req_name, "HSM failed to process RPC request");
            return Err(HsmRpcError.into());
        }
        trace!(
            num_bytes = res_bytes.len(),
            req = req_name,
            ?dur,
            "received HSM RPC response"
        );
        let response = marshalling::from_slice(&res_bytes)?;
        Ok(response)
    }
}
