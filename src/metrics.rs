use dogstatsd::DogstatsdResult;
use tracing::warn;

pub trait Warn {
    fn warn_err(&self);
}

impl Warn for DogstatsdResult {
    fn warn_err(&self) {
        if let Err(err) = self {
            warn!(?err, "failed to send metrics to Datadog agent");
        }
    }
}
