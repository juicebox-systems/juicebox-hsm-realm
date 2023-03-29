use async_trait::async_trait;
use hdrhistogram::Histogram;
use std::{
    collections::HashMap,
    fmt::{self, Debug},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;
use tracing::info;
use tracing::{instrument, span::Span, trace, warn};

use hsmcore::hsm::rpc::{HsmRequestContainer, HsmResponseContainer, HsmRpc, MetricsAction};

use loam_sdk_core::marshalling::{self, DeserializationError, SerializationError};
use loam_sdk_networking::requests::ClientError;

/// The HSM signalled that the request processing failed, likely due to
/// serialization or deserialization issues.
#[derive(Debug)]
pub struct HsmRpcError;

impl From<HsmRpcError> for ClientError {
    fn from(_v: HsmRpcError) -> Self {
        ClientError::HsmRpcError
    }
}

#[async_trait]
pub trait Transport: fmt::Debug + Send + Sync {
    type Error: fmt::Debug
        + From<SerializationError>
        + From<DeserializationError>
        + From<HsmRpcError>
        + Send;

    async fn send_rpc_msg(&self, msg_name: &str, msg: Vec<u8>) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug)]
pub struct HsmClient<T>(Arc<HsmClientInner<T>>);

#[derive(Debug)]
struct HsmClientInner<T> {
    transport: T,
    name: String,
    metrics_interval: Option<Duration>,
    metrics: Mutex<MetricsInner>,
}

#[derive(Debug)]
struct MetricsInner {
    last_reported: Instant,
    metrics: HashMap<String, Histogram<u64>>,
}

impl<T> Clone for HsmClient<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Transport> HsmClient<T> {
    pub fn new(t: T, name: String, metrics_reporting_interval: Option<Duration>) -> Self {
        Self(Arc::new(HsmClientInner {
            transport: t,
            name,
            metrics_interval: metrics_reporting_interval,
            metrics: Mutex::new(MetricsInner {
                last_reported: Instant::now(),
                metrics: HashMap::new(),
            }),
        }))
    }

    #[instrument(level = "trace", name = "HsmClient::send", skip(r), fields(req_name))]
    pub async fn send<RPC: HsmRpc + Send>(&self, r: RPC) -> Result<RPC::Response, T::Error> {
        let hsm_req = r.to_req();
        let req_name = hsm_req.name();
        Span::current().record("req_name", req_name);

        let req_bytes = marshalling::to_vec(&HsmRequestContainer {
            req: hsm_req,
            metrics: match self.0.metrics_interval {
                Some(_) => MetricsAction::Record,
                None => MetricsAction::Skip,
            },
        })?;

        trace!(
            num_bytes = req_bytes.len(),
            req = req_name,
            "sending HSM RPC request"
        );
        let start = Instant::now();
        let res_bytes = self.0.transport.send_rpc_msg(req_name, req_bytes).await?;

        let dur = start.elapsed();
        if res_bytes.is_empty() {
            warn!(req = req_name, "HSM failed to process RPC request");
            return Err(HsmRpcError.into());
        }
        trace!(
            num_bytes = res_bytes.len(),
            req = req_name,
            ?dur,
            "received HSM RPC response"
        );
        let response: HsmResponseContainer<RPC::Response> = marshalling::from_slice(&res_bytes)?;

        if !response.metrics.is_empty() {
            let mut m = self.0.metrics.lock().unwrap();
            for (k, dur) in response.metrics {
                let h = m
                    .metrics
                    .entry(k.into_owned())
                    .or_insert_with(|| Histogram::new(1).unwrap());
                h.record(dur.0 as u64).unwrap();
            }
            if let Some(interval) = self.0.metrics_interval {
                let elapsed = m.last_reported.elapsed();
                if elapsed > interval {
                    m.last_reported = Instant::now();
                    for (metric_name, h) in &m.metrics {
                        info!(agent=self.0.name, metric=metric_name, count=?h.len(), min=?h.min(), mean=%format!("{:0.1}",h.mean()), p99=?h.value_at_quantile(0.99), max=?h.max(), "hsm metric");
                    }
                    m.metrics.clear();
                }
            };
        }
        Ok(response.res)
    }
}
