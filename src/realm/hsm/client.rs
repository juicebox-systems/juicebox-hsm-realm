use async_trait::async_trait;
use std::fmt;
use std::sync::Arc;

use hsmcore::{
    hsm::rpc::HsmRpc,
    marshalling::{self, DeserializationError, SerializationError},
};

#[async_trait]
pub trait Transport: fmt::Debug + Send + Sync {
    type Error: fmt::Debug + From<SerializationError> + From<DeserializationError> + Send;

    async fn send_rpc_msg(&self, msg: Vec<u8>) -> Result<Vec<u8>, Self::Error>;
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
    pub async fn send<RPC: HsmRpc + Send>(&self, r: RPC) -> Result<RPC::Response, T::Error> {
        let hsm_req = r.to_req();
        let req_bytes = marshalling::to_vec(&hsm_req)?;
        let res_bytes = self.transport.send_rpc_msg(req_bytes).await?;
        let response = marshalling::from_slice(&res_bytes)?;
        Ok(response)
    }
}