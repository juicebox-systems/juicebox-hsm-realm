use is_terminal::IsTerminal;
use opentelemetry::sdk::propagation::TraceContextPropagator;
use opentelemetry::sdk::trace::Sampler;
use opentelemetry::sdk::Resource;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{info, warn, Level};
use tracing_subscriber::filter::{FilterFn, LevelFilter};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::subscribe::CollectExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Subscribe;

pub struct Spew(Mutex<SpewInner>);

struct SpewInner {
    // The number of messages suppressed since the last log.
    suppressed: usize,
    last_logged: Option<Instant>,
}

impl Spew {
    pub const fn new() -> Self {
        Self(Mutex::new(SpewInner {
            suppressed: 0,
            last_logged: None,
        }))
    }

    /// If it's time to log again, returns Some with the number of suppressed
    /// messages. Otherwise, returns None.
    pub fn ok(&self) -> Option<usize> {
        let now = Instant::now();
        let mut locked = self.0.lock().unwrap();
        let elapsed = locked
            .last_logged
            .map(|last_logged| now.saturating_duration_since(last_logged))
            .unwrap_or(Duration::MAX);
        if elapsed >= Duration::from_secs(30) {
            let were_suppressed = locked.suppressed;
            locked.suppressed = 0;
            locked.last_logged = Some(now);
            Some(were_suppressed)
        } else {
            locked.suppressed += 1;
            None
        }
    }
}

static EXPORT_SPEW: Spew = Spew::new();

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
        default_log_level: Level::INFO,
    })
}

pub struct Options {
    pub process_name: String,
    pub default_log_level: Level,
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
                if let Some(suppressed) = EXPORT_SPEW.ok() {
                    warn!(
                        error = %e,
                        suppressed,
                        "opentelemetry error",
                    );
                }
            }

            _ => {
                // This goes to stderr so that it's not an infinite cycle with logging.
                eprintln!("opentelemetry error: {e}");
            }
        }
    })
    .unwrap();

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint("http://localhost:4317"),
        )
        .with_trace_config(
            opentelemetry::sdk::trace::config()
                .with_sampler(Sampler::TraceIdRatioBased(0.1))
                .with_resource(Resource::new(vec![KeyValue::new(
                    "service.name",
                    options.process_name,
                )])),
        )
        .install_batch(opentelemetry::runtime::Tokio)
        .expect("TODO");

    opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

    if std::io::stdout().is_terminal() {
        let text_terminal = tracing_subscriber::fmt::Subscriber::new()
            .with_file(true)
            .with_line_number(true)
            .with_span_events(FmtSpan::ACTIVE)
            .with_target(false);

        let telemetry = tracing_opentelemetry::subscriber().with_tracer(tracer);

        tracing_subscriber::registry()
            .with(FilterFn::new(|metadata| should_log(metadata.module_path())))
            .with(text_terminal.with_filter(LevelFilter::from_level(log_level)))
            .with(telemetry)
            .init();
    } else {
        let json_terminal = tracing_subscriber::fmt::Subscriber::new()
            .json()
            .with_file(true)
            .with_line_number(true)
            .with_span_events(FmtSpan::ACTIVE)
            .with_target(false);

        let telemetry = tracing_opentelemetry::subscriber().with_tracer(tracer);

        tracing_subscriber::registry()
            .with(FilterFn::new(|metadata| should_log(metadata.module_path())))
            .with(json_terminal.with_filter(LevelFilter::from_level(log_level)))
            .with(telemetry)
            .init();
    }

    info!(
        max_level = %log_level,
        "initialized logging to terminal and telemetry to OTLP/Jaeger. you can set verbosity with env var LOGLEVEL."
    );
}

pub fn flush() {
    opentelemetry::global::shutdown_tracer_provider()
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
