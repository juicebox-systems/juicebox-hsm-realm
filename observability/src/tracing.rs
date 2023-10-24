use hyper::body::Incoming as IncomingBody;
use hyper::service::Service;
use hyper::Request;
use opentelemetry_http::HeaderExtractor;
use tracing::instrument::Instrumented;
use tracing::{span, Instrument, Level};
use tracing_opentelemetry::OpenTelemetrySpanExt;

// TracingMiddleware wraps a Hyper service and deals with setting up the correct
// tracing context and propagating any tracing context from the request.
pub struct TracingMiddleware<S> {
    inner: S,
}

impl<S> TracingMiddleware<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: Clone> Clone for TracingMiddleware<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S> Service<Request<IncomingBody>> for TracingMiddleware<S>
where
    S: Service<Request<IncomingBody>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Instrumented<S::Future>;

    fn call(&mut self, request: Request<IncomingBody>) -> Self::Future {
        let parent_context = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(request.headers()))
        });
        // otel.name will be exported as the span name for open telemetry.
        let root_span = span!(
            Level::TRACE,
            "TracingMiddleware::Call",
            otel.name = format!("{} {}", request.method(), request.uri().path()),
        );
        root_span.set_parent(parent_context);
        root_span
            .in_scope(|| self.inner.call(request))
            .instrument(root_span)
    }
}
