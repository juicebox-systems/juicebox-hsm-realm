use super::realm::rpc::Rpc;
use reqwest::Url;

#[derive(Clone, Debug)]
pub struct Client {
    // reqwest::Client holds a connection pool. It's reference-counted
    // internally, so this field is relatively cheap to clone.
    http: reqwest::Client,
}

#[derive(Debug)]
pub enum ClientError {
    Network(reqwest::Error),
    HttpStatus(reqwest::StatusCode),
    Serialization(rmp_serde::encode::Error),
    Deserialization(rmp_serde::decode::Error),
}

impl Client {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder().build().expect("TODO"),
        }
    }

    pub async fn send<R: Rpc>(
        &self,
        base_url: &Url,
        request: R,
    ) -> Result<R::Response, ClientError> {
        type Error = ClientError;
        let url = base_url.join(R::PATH).unwrap();
        match self
            .http
            .post(url)
            .body(rmp_serde::to_vec(&request).map_err(Error::Serialization)?)
            .send()
            .await
        {
            Err(err) => Err(Error::Network(err)),
            Ok(response) if response.status().is_success() => {
                let raw = response.bytes().await.map_err(Error::Network)?;
                let response =
                    rmp_serde::from_read(raw.as_ref()).map_err(Error::Deserialization)?;
                Ok(response)
            }
            Ok(response) => Err(Error::HttpStatus(response.status())),
        }
    }
}
