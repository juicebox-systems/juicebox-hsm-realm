use async_trait::async_trait;
use hdrhistogram::Histogram;
use hsmcore::hsm::rpc::HsmMetrics;
use tracing::info;

use std::cell::RefCell;
use std::fmt::{self, Debug};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;
use tracing::{instrument, span::Span, trace, warn};

use hsmcore::{
    hsm::rpc::{HsmRequestContainer, HsmResponseContainer, HsmRpc, MetricsAction},
    marshalling::{self, DeserializationError, SerializationError},
};

/// The HSM signalled that the request processing failed, likely due to
/// serialization or deserialization issues.
#[derive(Debug)]
pub struct HsmRpcError;

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
    metrics: Option<Duration>,
    last_metrics: Mutex<RefCell<Instant>>,
}

impl<T> Clone for HsmClient<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Transport> HsmClient<T> {
    pub fn new(t: T, metrics_reporting_iterval: Option<Duration>) -> Self {
        Self(Arc::new(HsmClientInner {
            transport: t,
            metrics: metrics_reporting_iterval,
            last_metrics: Mutex::new(RefCell::new(Instant::now())),
        }))
    }

    #[instrument(level = "trace", name = "HsmClient::send", skip(r), fields(req_name))]
    pub async fn send<RPC: HsmRpc + Send>(&self, r: RPC) -> Result<RPC::Response, T::Error> {
        let hsm_req = r.to_req();
        let req_name = hsm_req.name();
        Span::current().record("req_name", req_name);

        let metrics = self.0.metrics.as_ref().map(|interval| {
            let lm = self.0.last_metrics.lock().unwrap();
            let elapsed = lm.borrow().elapsed();
            if elapsed > *interval {
                *lm.borrow_mut() = Instant::now();
                MetricsAction::ReportAndReset
            } else {
                MetricsAction::Record
            }
        });

        let req_bytes = marshalling::to_vec(&HsmRequestContainer {
            req: hsm_req,
            metrics,
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
        match response.metrics {
            None => {}
            Some(m) => report_hsm_metrics(m),
        }
        Ok(response.res)
    }
}

fn report_hsm_metrics(m: HsmMetrics) {
    let mut h: Histogram<u32> = Histogram::new(1).unwrap();
    let hsm_name = &m.hsm_name as &str;
    for metric in m.metrics.into_iter() {
        h.reset();
        for p in &metric.points {
            h.record(*p).unwrap();
        }
        info!(hsm=hsm_name, metric=metric.name, units=metric.units, count=?h.len(), min=?h.min(), mean=%format!("{:0.1}",h.mean()), p99=?h.value_at_quantile(0.99), max=?h.max(), "hsm metric");
    }
}
