use async_trait::async_trait;
use reqwest::Url;

use super::super::{
    super::super::http_client::ClientError,
    client::{HsmClient, Transport},
};

#[derive(Clone, Debug)]
pub struct HsmHttpClient {
    hsm: Url,
    http: reqwest::Client,
}
impl HsmHttpClient {
    pub fn new_client(url: Url) -> HsmClient<HsmHttpClient> {
        HsmClient::new(Self {
            hsm: url.join("/req").unwrap(),
            http: reqwest::Client::builder().build().expect("TODO"),
        })
    }
}
#[async_trait]
impl Transport for HsmHttpClient {
    type Error = ClientError;

    async fn send_rpc_msg(&self, _msg_name: &str, msg: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
        match self.http.post(self.hsm.clone()).body(msg).send().await {
            Err(err) => Err(ClientError::Network(err)),
            Ok(response) if response.status().is_success() => {
                let resp_body = response.bytes().await.map_err(ClientError::Network)?;
                Ok(resp_body.to_vec())
            }
            Ok(response) => Err(ClientError::HttpStatus(response.status())),
        }
    }
}
