use async_trait::async_trait;
use std::fmt::{self, Debug};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{instrument, span::Span, trace};

use hsm_api::rpc::{HsmRequestContainer, HsmResponseContainer, HsmRpc, MetricsAction};
use juicebox_marshalling::{self as marshalling, DeserializationError, SerializationError};
use observability::{metrics, metrics_tag as tag};

#[async_trait]
pub trait Transport: fmt::Debug + Send + Sync {
    type Error: fmt::Debug + From<SerializationError> + From<DeserializationError> + Send;

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
    metrics_action: MetricsAction,
    dd_metrics: metrics::Client,
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
        metrics_action: MetricsAction,
        dd_metrics: metrics::Client,
    ) -> Self {
        Self(Arc::new(HsmClientInner {
            transport: t,
            name,
            metrics_action,
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
            metrics: self.0.metrics_action,
        })?;

        trace!(
            num_bytes = req_bytes.len(),
            req = req_name,
            "sending HSM RPC request"
        );
        let start = Instant::now();
        let res_bytes = self.0.transport.send_rpc_msg(req_name, req_bytes).await?;

        let dur = start.elapsed();
        trace!(
            num_bytes = res_bytes.len(),
            req = req_name,
            ?dur,
            "received HSM RPC response"
        );
        let response: HsmResponseContainer<RPC::Response> = marshalling::from_slice(&res_bytes)?;
        if !response.metrics.is_empty() {
            for (k, dur) in response.metrics {
                self.0.dd_metrics.timing(
                    format!("hsm.{k})"),
                    Duration::from_nanos(dur.0.into()),
                    [tag!(?req_name)],
                );
            }
        }
        Ok(response.res)
    }
}
