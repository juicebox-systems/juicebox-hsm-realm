use hyper::body::Incoming as IncomingBody;
use hyper::service::Service;
use hyper::Request;
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

    fn call(&self, request: Request<IncomingBody>) -> Self::Future {
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

/// This is a copy of [`opentelemetry_http::HeaderExtractor`] that works with
/// http crate v1.0.
pub struct HeaderExtractor<'a>(pub &'a hyper::HeaderMap);

impl<'a> opentelemetry::propagation::Extractor for HeaderExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0
            .keys()
            .map(|value| value.as_str())
            .collect::<Vec<_>>()
    }
}
