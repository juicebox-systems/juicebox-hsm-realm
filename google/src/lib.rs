pub mod auth;
mod autogen;

use std::time::Duration;
use tonic::transport::Endpoint;

pub use autogen::google::*;

/// Configuration settings for a gRPC Client.
pub struct GrpcConnectionOptions {
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub tcp_keepalive: Option<Duration>,
}

impl Default for GrpcConnectionOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(20),
            connect_timeout: Duration::from_secs(20),
            tcp_keepalive: Some(Duration::from_secs(5)),
        }
    }
}

impl GrpcConnectionOptions {
    pub fn apply(&self, e: Endpoint) -> Endpoint {
        e.timeout(self.timeout)
            .connect_timeout(self.connect_timeout)
            .tcp_keepalive(self.tcp_keepalive)
    }
}
