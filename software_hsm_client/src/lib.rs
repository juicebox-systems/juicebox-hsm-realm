use http::{HeaderMap, HeaderName, HeaderValue};
use opentelemetry::propagation::Injector;
use std::fmt::Debug;
use std::str::FromStr;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use agent_core::hsm::Transport;
use jburl::Url;
use juicebox_marshalling::{self as marshalling, DeserializationError, SerializationError};
use observability::metrics_tag as tag;
use retry_loop::AttemptError;

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

impl Transport for HsmHttpClient {
    type FatalError = HsmHttpTransportError;
    type RetryableError = HsmHttpTransportError;

    async fn send_rpc_msg(
        &self,
        _msg_name: &'static str,
        msg: Vec<u8>,
    ) -> Result<Vec<u8>, AttemptError<HsmHttpTransportError>> {
        let mut headers = HeaderMap::new();
        opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.inject_context(
                &Span::current().context(),
                &mut HeaderInjector::new(&mut headers),
            )
        });

        match self
            .http
            .post(self.hsm.as_ref())
            .body(msg)
            .headers(headers)
            .send()
            .await
        {
            Err(err) => Err(HsmHttpTransportError::Network(err).into()),
            Ok(response) if response.status().is_success() => {
                let resp_body = response
                    .bytes()
                    .await
                    .map_err(HsmHttpTransportError::Network)?;
                Ok(resp_body.to_vec())
            }
            Ok(response) => Err(HsmHttpTransportError::HttpStatus(response.status()).into()),
        }
    }
}

struct HeaderInjector<'a> {
    headers: &'a mut HeaderMap,
}

impl<'a> HeaderInjector<'a> {
    fn new(headers: &'a mut HeaderMap) -> Self {
        HeaderInjector { headers }
    }
}

impl<'a> Injector for HeaderInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        self.headers.insert(
            HeaderName::from_str(key).expect("header name not to be bogus"),
            HeaderValue::from_str(&value).expect("header value to not be bogus"),
        );
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

impl From<HsmHttpTransportError> for AttemptError<HsmHttpTransportError> {
    fn from(error: HsmHttpTransportError) -> Self {
        type Error = HsmHttpTransportError;
        match error {
            Error::Network(_) => AttemptError::Retryable {
                error,
                tags: vec![tag!("kind": "network")],
            },
            Error::HttpStatus(code) => AttemptError::Retryable {
                error,
                tags: vec![tag!("kind": "http_status"), tag!("http_code": code)],
            },
            Error::Serialization(_) => AttemptError::Fatal {
                error,
                tags: vec![tag!("kind": "serialization")],
            },
            Error::Deserialization(_) => AttemptError::Fatal {
                error,
                tags: vec![tag!("kind": "deserialization")],
            },
        }
    }
}
