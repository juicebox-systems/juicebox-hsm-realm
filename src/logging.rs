use std::str::FromStr;

use tracing::{info, Level};
use tracing_subscriber::{
    filter::FilterFn, fmt::format::FmtSpan, prelude::__tracing_subscriber_SubscriberExt,
    FmtSubscriber,
};

pub fn configure() {
    let log_level = std::env::var("LOGLEVEL")
        .map(|s| match Level::from_str(&s) {
            Ok(level) => level,
            Err(e) => panic!("failed to parse LOGLEVEL: {e}"),
        })
        .unwrap_or(Level::DEBUG);
    // Quiet down some libs.
    let filter = FilterFn::new(|metadata| {
        if let Some(module) = metadata.module_path() {
            if module.starts_with("h2::")
                || module.starts_with("hyper::")
                || module.starts_with("tokio_util::")
                || module.starts_with("tonic::")
                || module.starts_with("tower::")
            {
                return false;
            }
        }
        true
    });
    let subscriber = FmtSubscriber::builder()
        .with_file(true)
        .with_line_number(true)
        .with_max_level(log_level)
        .with_span_events(FmtSpan::ACTIVE)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber.with(filter)).unwrap();
    info!(
        max_level = %log_level,
        "set up tracing. you can set verbosity with env var LOGLEVEL."
    );
}
