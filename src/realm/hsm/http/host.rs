use anyhow::Context;
use bytes::Bytes;
use futures::Future;
use hsmcore::hal::{Clock, IOError, NVRam, Nanos, MAX_NVRAM_SIZE};
use hsmcore::hsm::{Hsm, HsmError, HsmOptions, MacKey, PersistenceError, RealmKeys};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::ops::Sub;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::warn;
use url::Url;

struct HalInstant(Instant);
impl Sub for HalInstant {
    type Output = Nanos;

    fn sub(self, rhs: Self) -> Self::Output {
        Nanos(
            self.0
                .duration_since(rhs.0)
                .as_nanos()
                .try_into()
                .unwrap_or(Nanos::MAX.0),
        )
    }
}

#[derive(Clone)]
struct StdPlatform {
    // The location of the backing file for 'NVRam'
    state_file: PathBuf,
}

impl Clock for StdPlatform {
    type Instant = HalInstant;

    fn now(&self) -> Option<Self::Instant> {
        Some(HalInstant(Instant::now()))
    }

    fn elapsed(&self, start: Self::Instant) -> Option<Nanos> {
        Some(HalInstant(Instant::now()) - start)
    }
}

impl RngCore for StdPlatform {
    fn next_u32(&mut self) -> u32 {
        OsRng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        OsRng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        OsRng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        OsRng.try_fill_bytes(dest)
    }
}
impl rand::CryptoRng for StdPlatform {}

impl NVRam for StdPlatform {
    fn read(&self) -> Result<Vec<u8>, IOError> {
        match fs::read(&self.state_file) {
            Ok(data) => Ok(data),
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    return Ok(Vec::new());
                }
                Err(IOError(format!(
                    "IO Error reading state from {}: {e}",
                    self.state_file.display()
                )))
            }
        }
    }

    fn write(&self, data: Vec<u8>) -> Result<(), IOError> {
        if data.len() > MAX_NVRAM_SIZE {
            return Err(IOError(format!(
                "data with {} bytes is larger than allowed maximum of {MAX_NVRAM_SIZE}",
                data.len()
            )));
        }
        fs::write(&self.state_file, data).map_err(|e| {
            IOError(format!(
                "IO Error writing to state file {}: {e}",
                self.state_file.display()
            ))
        })
    }
}

#[derive(Clone)]
pub struct HttpHsm(Arc<Mutex<Hsm<StdPlatform>>>);

impl HttpHsm {
    pub fn new(
        state_dir: PathBuf,
        name: String,
        mac_key: MacKey,
    ) -> Result<Self, PersistenceError> {
        let state_file = state_dir.join(&name);
        Ok(HttpHsm(Arc::new(Mutex::new(Hsm::new(
            HsmOptions {
                name,
                tree_overlay_size: 511,
                max_sessions: 511,
            },
            StdPlatform { state_file },
            RealmKeys::insecure_derive(mac_key),
        )?))))
    }

    pub async fn listen(self, address: SocketAddr) -> Result<(Url, JoinHandle<()>), anyhow::Error> {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("failed to bind to {address}"))?;
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

    pub fn is_witness_only(&self) -> bool {
        self.0.lock().unwrap().is_witness_only()
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

#[cfg(test)]
mod test {
    use super::*;
    use std::time::Duration;

    #[test]
    fn instant_sub() {
        let s = Instant::now();
        let e = s + Duration::from_nanos(12345);
        assert_eq!(Nanos(12345), HalInstant(e) - HalInstant(s));
        // Should saturate to zero on sub if RHS > LHS
        assert_eq!(Nanos::ZERO, HalInstant(s) - HalInstant(e));
        let e = s + Duration::from_secs(5);
        // Should saturate to max if too large
        assert_eq!(Nanos::MAX, HalInstant(e) - HalInstant(s));
    }
}
