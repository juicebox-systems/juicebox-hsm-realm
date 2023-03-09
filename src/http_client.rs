use std::marker::PhantomData;

use crate::realm::hsm::client::HsmRpcError;

use super::realm::rpc::{Rpc, Service};
use hsmcore::marshalling;
use reqwest::Url;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct EndpointClient<F: Service> {
    client: Client<F>,
    url: Url,
}

#[allow(dead_code)]
impl<F: Service> EndpointClient<F> {
    pub fn new(url: Url) -> Self {
        Self {
            client: Client::new(),
            url,
        }
    }

    pub async fn send<R: Rpc<F>>(&self, request: R) -> Result<R::Response, ClientError> {
        self.client.send(&self.url, request).await
    }
}

#[derive(Clone, Debug, Default)]
pub struct Client<F: Service> {
    // reqwest::Client holds a connection pool. It's reference-counted
    // internally, so this field is relatively cheap to clone.
    http: reqwest::Client,
    _phantom_data: PhantomData<F>,
}

#[derive(Debug)]
pub enum ClientError {
    Network(reqwest::Error),
    HttpStatus(reqwest::StatusCode),
    Serialization(marshalling::SerializationError),
    Deserialization(marshalling::DeserializationError),
    HsmRpcError,
}

impl From<marshalling::SerializationError> for ClientError {
    fn from(value: marshalling::SerializationError) -> Self {
        ClientError::Serialization(value)
    }
}

impl From<marshalling::DeserializationError> for ClientError {
    fn from(value: marshalling::DeserializationError) -> Self {
        ClientError::Deserialization(value)
    }
}

impl From<HsmRpcError> for ClientError {
    fn from(_v: HsmRpcError) -> Self {
        ClientError::HsmRpcError
    }
}

impl<F: Service> Client<F> {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder().build().expect("TODO"),
            _phantom_data: PhantomData {},
        }
    }

    pub async fn send<R: Rpc<F>>(
        &self,
        base_url: &Url,
        request: R,
    ) -> Result<R::Response, ClientError> {
        type Error = ClientError;
        let url = base_url.join(R::PATH).unwrap();
        match self
            .http
            .post(url)
            .body(marshalling::to_vec(&request)?)
            .send()
            .await
        {
            Err(err) => Err(Error::Network(err)),
            Ok(response) if response.status().is_success() => {
                let raw = response.bytes().await.map_err(Error::Network)?;
                let response = marshalling::from_slice(raw.as_ref())?;
                Ok(response)
            }
            Ok(response) => Err(Error::HttpStatus(response.status())),
        }
    }
}
