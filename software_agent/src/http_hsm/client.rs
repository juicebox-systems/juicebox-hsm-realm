use async_trait::async_trait;
use juicebox_marshalling::{self as marshalling, DeserializationError, SerializationError};
use std::fmt::Debug;
use url::Url;

use agent_core::hsm::Transport;

#[derive(Clone)]
pub struct HsmHttpClient {
    hsm: Url,
    http: reqwest::Client,
}

impl HsmHttpClient {
    pub fn new(url: Url) -> Self {
        Self {
            hsm: url.join("/req").unwrap(),
            http: reqwest::Client::builder().build().expect("TODO"),
        }
    }
}

impl Debug for HsmHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HsmHttpClient for {}", self.hsm)
    }
}

#[async_trait]
impl Transport for HsmHttpClient {
    type Error = HsmHttpTransportError;

    async fn send_rpc_msg(
        &self,
        _msg_name: &'static str,
        msg: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        match self.http.post(self.hsm.clone()).body(msg).send().await {
            Err(err) => Err(HsmHttpTransportError::Network(err)),
            Ok(response) if response.status().is_success() => {
                let resp_body = response
                    .bytes()
                    .await
                    .map_err(HsmHttpTransportError::Network)?;
                Ok(resp_body.to_vec())
            }
            Ok(response) => Err(HsmHttpTransportError::HttpStatus(response.status())),
        }
    }
}

#[derive(Debug)]
pub enum HsmHttpTransportError {
    Network(reqwest::Error),
    HttpStatus(reqwest::StatusCode),
    Serialization(marshalling::SerializationError),
    Deserialization(marshalling::DeserializationError),
}

impl From<SerializationError> for HsmHttpTransportError {
    fn from(value: SerializationError) -> Self {
        HsmHttpTransportError::Serialization(value)
    }
}

impl From<DeserializationError> for HsmHttpTransportError {
    fn from(value: DeserializationError) -> Self {
        HsmHttpTransportError::Deserialization(value)
    }
}
