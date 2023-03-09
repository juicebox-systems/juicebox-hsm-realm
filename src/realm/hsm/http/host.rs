use bytes::Bytes;
use futures::Future;
use hsmcore::hsm::{Hsm, HsmError, RealmKey};
use hsmcore::rand::GetRandom;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use reqwest::Url;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::warn;

#[derive(Clone)]
pub struct HttpHsm(Arc<Mutex<Hsm>>);

impl HttpHsm {
    pub fn new(name: String, realm_key: RealmKey, rng: Box<dyn GetRandom>) -> Self {
        HttpHsm(Arc::new(Mutex::new(Hsm::new(name, realm_key, rng))))
    }

    pub async fn listen(
        self,
        address: SocketAddr,
    ) -> Result<(Url, JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(address).await?;
        let url = Url::parse(&format!("http://{address}")).unwrap();

        Ok((
            url,
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Err(e) => warn!("error accepting connection: {e:?}"),
                        Ok((stream, _)) => {
                            let hsm = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(stream, hsm.clone())
                                    .await
                                {
                                    warn!("error serving connection: {e:?}");
                                }
                            });
                        }
                    }
                }
            }),
        ))
    }
}

impl Service<Request<IncomingBody>> for HttpHsm {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&mut self, request: Request<IncomingBody>) -> Self::Future {
        let hsm = self.clone();
        Box::pin(async move {
            match request.uri().path().strip_prefix('/') {
                Some("req") => {}
                None | Some(_) => {
                    return Ok(Response::builder()
                        .status(http::StatusCode::NOT_FOUND)
                        .body(Full::from(Bytes::new()))
                        .unwrap());
                }
            };
            let request_bytes = request.collect().await?.to_bytes();

            match hsm.0.lock().unwrap().handle_request(request_bytes.as_ref()) {
                Err(HsmError::Deserialization(_)) => Ok(Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .body(Full::from(Bytes::new()))
                    .unwrap()),
                Err(HsmError::Serialization(_)) => Ok(Response::builder()
                    .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::from(Bytes::new()))
                    .unwrap()),
                Ok(response_bytes) => Ok(Response::builder()
                    .body(Full::new(Bytes::from(response_bytes)))
                    .unwrap()),
            }
        })
    }
}
