use async_trait::async_trait;
use hdrhistogram::Histogram;
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;
use tracing::info;
use tracing::{instrument, span::Span, trace, warn};

use hsmcore::hsm::rpc::{HsmRequestContainer, HsmResponseContainer, HsmRpc, MetricsAction};
use juicebox_hsm::{metrics, metrics_tag as tag};
use juicebox_sdk_marshalling::{self as marshalling, DeserializationError, SerializationError};
use juicebox_sdk_networking::rpc::RpcError;

/// The HSM signalled that the request processing failed, likely due to
/// serialization or deserialization issues.
#[derive(Debug)]
pub struct HsmRpcError;

impl From<HsmRpcError> for RpcError {
    fn from(_v: HsmRpcError) -> Self {
        RpcError::Network
    }
}

#[async_trait]
pub trait Transport: fmt::Debug + Send + Sync {
    type Error: fmt::Debug
        + From<SerializationError>
        + From<DeserializationError>
        + From<HsmRpcError>
        + Send;

    async fn send_rpc_msg(
        &self,
        msg_name: &'static str,
        msg: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error>;
}

pub struct HsmClient<T>(Arc<HsmClientInner<T>>);

impl<T: Debug> Debug for HsmClient<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HsmClient")
            .field("name", &self.0.name)
            .field("transport", &self.0.transport)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct HsmClientInner<T> {
    transport: T,
    name: String,
    metrics_interval: Option<Duration>,
    metrics: Mutex<MetricsInner>,
    dd_metrics: metrics::Client,
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
    pub fn new(
        t: T,
        name: String,
        metrics_reporting_interval: Option<Duration>,
        dd_metrics: metrics::Client,
    ) -> Self {
        Self(Arc::new(HsmClientInner {
            transport: t,
            name,
            metrics_interval: metrics_reporting_interval,
            metrics: Mutex::new(MetricsInner {
                last_reported: Instant::now(),
                metrics: HashMap::new(),
            }),
            dd_metrics,
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
                self.0.dd_metrics.timing(
                    format!("hsm.{k})"),
                    Duration::from_nanos(dur.0.into()),
                    [tag!(?req_name)],
                );
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
                        info!(
                            agent=self.0.name,
                            metric=metric_name,
                            count=?h.len(),
                            min=?h.min(),
                            mean=format!("{:0.1}", h.mean()),
                            p99=?h.value_at_quantile(0.99),
                            max=?h.max(),
                            units="ns",
                            "hsm metric",
                        );
                    }
                    m.metrics.clear();
                }
            };
        }
        Ok(response.res)
    }
}
