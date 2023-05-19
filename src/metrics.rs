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

#[derive(Debug, Default)]
pub struct Tags(pub Vec<String>);

impl Tags {
    pub fn new() -> Self {
        Tags(Vec::new())
    }
    pub fn with_capacity(c: usize) -> Self {
        Tags(Vec::with_capacity(c))
    }
    pub fn push(&mut self, name: &str, val: &str) {
        self.0.push(format!("{}:{}", name, val));
    }
}
