use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{Sampler, ShouldSample};
use opentelemetry_sdk::Resource;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::IsTerminal;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{info, warn, Level, Metadata, Subscriber};
use tracing_core::callsite;
use tracing_subscriber::filter::{FilterFn, LevelFilter};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::{Context, Filter, Layer, SubscriberExt};

struct SpewFilter {
    spewers: Mutex<HashMap<callsite::Identifier, Spew>>,
    interval: Duration,
}

impl SpewFilter {
    fn new(reporting_interval: Duration) -> Self {
        SpewFilter {
            spewers: Mutex::new(HashMap::new()),
            interval: reporting_interval,
        }
    }
}

struct Spew {
    count: usize,
    started: Instant,
}

impl Spew {
    fn new(started: Instant) -> Spew {
        Spew { count: 0, started }
    }
}

impl<S: Subscriber> Filter<S> for SpewFilter {
    fn enabled(&self, meta: &Metadata<'_>, _cx: &Context<'_, S>) -> bool {
        // Higher levels are more verbose, leave INFO, DEBUG & TRACE logging alone.
        if *meta.level() > Level::WARN || meta.fields().field("suppressed").is_some() {
            return true;
        }
        let k = meta.callsite();
        let now = Instant::now();
        let mut spewers = self.spewers.lock().unwrap();
        match spewers.entry(k) {
            Entry::Occupied(mut e) => {
                let spew = e.get_mut();
                if now - spew.started < self.interval {
                    spew.count += 1;
                    false
                } else {
                    let suppressed = spew.count;
                    *spew = Spew::new(now);
                    drop(spewers);
                    if suppressed > 0 {
                        warn!(
                            ?suppressed,
                            "suppressed duplicate log entries from {}",
                            meta.name()
                        );
                    }
                    true
                }
            }
            Entry::Vacant(v) => {
                v.insert(Spew::new(now));
                true
            }
        }
    }
}

// Quiet down some libs.
fn should_log(module_path: Option<&str>) -> bool {
    if let Some(module) = module_path {
        let module = module.split_once("::").map(|(l, _)| l).unwrap_or(module);
        if matches!(
            module,
            "h2" | "hyper"
                | "mio"
                | "reqwest"
                | "rustls"
                | "tokio_util"
                | "tonic"
                | "tower"
                | "want"
        ) {
            return false;
        }
    }
    true
}

pub fn configure(service_name: &str) {
    configure_with_options(Options {
        process_name: service_name.to_owned(),
        ..Options::default()
    })
}

pub struct Options {
    pub process_name: String,
    pub default_log_level: Level,
    pub additional_tags: HashMap<String, String>,
    pub trace_sampler: Sampler,
    pub background_trace_sampler: Sampler,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            process_name: String::new(),
            default_log_level: Level::INFO,
            additional_tags: HashMap::new(),
            trace_sampler: Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(0.1))),
            background_trace_sampler: Sampler::TraceIdRatioBased(0.005),
        }
    }
}

pub fn configure_with_options(options: Options) {
    let log_level = std::env::var("LOGLEVEL")
        .map(|s| match Level::from_str(&s) {
            Ok(level) => level,
            Err(e) => panic!("failed to parse LOGLEVEL: {e}"),
        })
        .unwrap_or(options.default_log_level);

    // By default, opentelemetry spews pretty often to stderr when it can't
    // find a server to submit traces to. This quiets down the errors and sends
    // them to the logger.
    opentelemetry::global::set_error_handler(|e| {
        use opentelemetry::global::Error;
        use opentelemetry::trace::TraceError;
        match e {
            Error::Trace(TraceError::ExportFailed(_))
            | Error::Trace(TraceError::ExportTimedOut(_)) => {
                // These errors are unlikely to cause infinite cycles with logging.
                warn!(
                    error = %e,
                    "opentelemetry error",
                );
            }

            _ => {
                // This goes to stderr so that it's not an infinite cycle with logging.
                eprintln!("opentelemetry error: {e}");
            }
        }
    })
    .unwrap();
    let mut resource_properties = vec![KeyValue::new("service.name", options.process_name)];
    for (k, v) in options.additional_tags {
        resource_properties.push(KeyValue::new(k, v));
    }

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint("http://localhost:4317"),
        )
        .with_trace_config(
            opentelemetry_sdk::trace::config()
                .with_sampler(TracingSourceSampler {
                    default: options.trace_sampler,
                    background: options.background_trace_sampler,
                })
                .with_resource(Resource::new(resource_properties)),
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .expect("TODO");

    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    let terminal = tracing_subscriber::fmt::layer()
        .with_file(true)
        .with_line_number(true)
        .with_span_events(FmtSpan::ACTIVE)
        .with_target(false);

    let terminal = if std::io::stdout().is_terminal() {
        terminal.boxed()
    } else {
        terminal.json().boxed()
    };

    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    let subscriber = tracing_subscriber::registry()
        .with(
            terminal
                .with_filter(SpewFilter::new(Duration::from_millis(1000)))
                .with_filter(LevelFilter::from_level(log_level)),
        )
        .with(telemetry)
        .with(FilterFn::new(|metadata| should_log(metadata.module_path())));

    tracing::subscriber::set_global_default(subscriber).unwrap();

    info!(
        max_level = %log_level,
        "initialized logging to terminal and telemetry to OTLP/Jaeger. you can set verbosity with env var LOGLEVEL."
    );
}

pub fn flush() {
    opentelemetry::global::shutdown_tracer_provider()
}

/// Setting this as a value in the context of a tracing span will determine its
/// and all its child spans sampling rate.
#[derive(Clone, Copy, Debug)]
pub enum TracingSource {
    /// The default/unknown source. Spans in this context get sampled at the default rate.
    Default,
    /// A background job/task that should have different trace sampling.
    BackgroundJob,
}

#[derive(Debug, Clone)]
struct TracingSourceSampler {
    default: Sampler,
    background: Sampler,
}

impl ShouldSample for TracingSourceSampler {
    fn should_sample(
        &self,
        parent_context: Option<&opentelemetry::Context>,
        trace_id: opentelemetry::trace::TraceId,
        name: &str,
        span_kind: &opentelemetry::trace::SpanKind,
        attributes: &[opentelemetry::KeyValue],
        links: &[opentelemetry::trace::Link],
    ) -> opentelemetry::trace::SamplingResult {
        let sampler = match parent_context {
            None => &self.default,
            Some(pc) => match pc.get() {
                None | Some(&TracingSource::Default) => &self.default,
                Some(&TracingSource::BackgroundJob) => &self.background,
            },
        };
        sampler.should_sample(parent_context, trace_id, name, span_kind, attributes, links)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_log() {
        assert!(!should_log(Some("want")));
        assert!(!should_log(Some("want::foo")));
        assert!(should_log(Some("hsm")));
        assert!(should_log(Some("hsm::foo")));
        assert!(should_log(None));
    }
}
