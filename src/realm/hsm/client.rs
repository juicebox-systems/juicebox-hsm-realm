use async_trait::async_trait;
use std::sync::Arc;

use super::super::super::http_client::ClientError;
use hsmcore::{hsm::rpc::HsmRpc, marshalling};

#[async_trait]
pub trait Transport: std::fmt::Debug + Send + Sync {
    async fn send_rpc_msg(&self, msg: Vec<u8>) -> Result<Vec<u8>, ClientError>;
}

#[derive(Debug, Clone)]
pub struct HsmClient {
    transport: Arc<Box<dyn Transport>>,
}
impl HsmClient {
    pub fn new(t: Box<dyn Transport>) -> Self {
        Self {
            transport: Arc::new(t),
        }
    }
    pub async fn send<RPC: HsmRpc + Send>(&self, r: RPC) -> Result<RPC::Response, ClientError> {
        let hsm_req = r.to_req();
        let req_bytes = marshalling::to_vec(&hsm_req)?;
        let res_bytes = self.transport.send_rpc_msg(req_bytes).await?;
        let response = marshalling::from_slice(&res_bytes)?;
        Ok(response)
    }
}
