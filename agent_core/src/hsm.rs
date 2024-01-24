use std::fmt::{self, Debug};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{instrument, span::Span};

use hsm_api::rpc::{HsmRequestContainer, HsmResponseContainer, HsmRpc, MetricsAction};
use juicebox_marshalling::{self as marshalling, DeserializationError, SerializationError};
use observability::{metrics, metrics_tag as tag};
use retry_loop::AttemptError;

pub trait Transport: fmt::Debug + Send + Sync {
    type FatalError: fmt::Debug + From<SerializationError> + From<DeserializationError> + Send;
    type RetryableError: fmt::Debug + Send;

    fn send_rpc_msg(
        &self,
        msg_name: &'static str,
        msg: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, AttemptError<Self::FatalError, Self::RetryableError>>> + Send;
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
    dd_metrics: metrics::Client,
}

impl<T> Clone for HsmClient<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Transport> HsmClient<T> {
    pub fn new(t: T, name: String, dd_metrics: metrics::Client) -> Self {
        Self(Arc::new(HsmClientInner {
            transport: t,
            name,
            dd_metrics,
        }))
    }

    #[instrument(
        level = "trace",
        name = "HsmClient::send",
        skip(r),
        fields(req_name, req_len, resp_len, rpc_dur)
    )]
    pub async fn send<RPC: HsmRpc + Send>(
        &self,
        r: RPC,
    ) -> Result<RPC::Response, AttemptError<T::FatalError, T::RetryableError>> {
        let hsm_req = r.to_req();
        let req_name = hsm_req.name();
        Span::current().record("req_name", req_name);

        let req_bytes = marshalling::to_vec(&HsmRequestContainer {
            req: hsm_req,
            metrics: MetricsAction::Record,
        })
        .map_err(|error| AttemptError::Fatal {
            error: T::FatalError::from(error),
            tags: vec![tag!("kind": "agent_serialization")],
        })?;
        Span::current().record("req_len", req_bytes.len());

        let start = Instant::now();
        let res_bytes = self.0.transport.send_rpc_msg(req_name, req_bytes).await?;

        let dur = start.elapsed();
        Span::current().record("resp_len", res_bytes.len());
        Span::current().record("rpc_dur", format!("{dur:?}"));

        let response: HsmResponseContainer<RPC::Response> = marshalling::from_slice(&res_bytes)
            .map_err(|error| AttemptError::Fatal {
                error: T::FatalError::from(error),
                tags: vec![tag!("kind": "agent_deserialization")],
            })?;
        if !response.metrics.is_empty() {
            for (k, dur) in response.metrics {
                self.0.dd_metrics.timing(
                    format!("hsm.{k}"),
                    Duration::from_nanos(dur.0.into()),
                    [tag!(?req_name)],
                );
            }
        }
        Ok(response.res)
    }
}
