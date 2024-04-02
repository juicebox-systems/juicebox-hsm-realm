use anyhow::Context;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper_util::rt::TokioIo;
use observability::tracing::TracingMiddleware;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::future::Future;
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

use hsm_api::rpc::Nanos;
use hsm_core::hal::{Clock, IOError, NVRam, MAX_NVRAM_SIZE};
use hsm_core::hsm::{Hsm, HsmError, HsmOptions, MetricsReporting, PersistenceError, RealmKeys};
use jburl::Url;

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
        realm_keys: RealmKeys,
    ) -> Result<Self, PersistenceError> {
        hsm_core::hash::set_global_rng(Box::new(OsRng));
        let state_file = state_dir.join(&name);
        Ok(HttpHsm(Arc::new(Mutex::new(Hsm::new(
            HsmOptions {
                name,
                tree_overlay_size: 1024,
                max_sessions: 8192,
                metrics: MetricsReporting::Enabled,
            },
            StdPlatform { state_file },
            realm_keys,
        )?))))
    }

    pub async fn listen(self, address: SocketAddr) -> Result<(Url, JoinHandle<()>), anyhow::Error> {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("failed to bind to {address}"))?;
        // This allows you to pass port 0 for an OS-assigned port.
        let address = listener.local_addr()?;
        let url = Url::parse(&format!("http://{address}")).unwrap();

        Ok((
            url,
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Err(e) => warn!("error accepting connection: {e:?}"),
                        Ok((stream, _)) => {
                            let io = TokioIo::new(stream);
                            let hsm = TracingMiddleware::new(self.clone());
                            tokio::spawn(async move {
                                if let Err(e) =
                                    http1::Builder::new().serve_connection(io, hsm).await
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

    fn call(&self, request: Request<IncomingBody>) -> Self::Future {
        let hsm = self.clone();
        Box::pin(async move {
            match request.uri().path().strip_prefix('/') {
                Some("req") => {}
                None | Some(_) => {
                    return Ok(Response::builder()
                        .status(hyper::StatusCode::NOT_FOUND)
                        .body(Full::from(Bytes::new()))
                        .unwrap());
                }
            };
            let request_bytes = request.collect().await?.to_bytes();

            let result = {
                let mut locked = hsm.0.lock().unwrap();
                locked.handle_request(request_bytes.as_ref())
            };
            match result {
                Err(HsmError::Deserialization(_)) => Ok(Response::builder()
                    .status(hyper::StatusCode::BAD_REQUEST)
                    .body(Full::from(Bytes::new()))
                    .unwrap()),
                Err(HsmError::Serialization(_)) => Ok(Response::builder()
                    .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
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
mod tests {
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
