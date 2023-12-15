pub mod auth;
mod autogen;
pub mod conn;

use std::time::Duration;
use tonic::transport::Endpoint;

pub use autogen::google::*;

/// Configuration settings for a gRPC Client.
#[derive(Clone)]
pub struct GrpcConnectionOptions {
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub http2_keepalive_interval: Duration,
    pub http2_keepalive_timeout: Duration,
    pub http2_keepalive_while_idle: bool,
}

impl Default for GrpcConnectionOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(20),
            connect_timeout: Duration::from_secs(20),
            http2_keepalive_interval: Duration::from_secs(4),
            http2_keepalive_timeout: Duration::from_secs(3),
            http2_keepalive_while_idle: true,
        }
    }
}

impl GrpcConnectionOptions {
    pub fn apply(&self, e: Endpoint) -> Endpoint {
        e.timeout(self.timeout)
            .connect_timeout(self.connect_timeout)
            .keep_alive_timeout(self.http2_keepalive_timeout)
            .http2_keep_alive_interval(self.http2_keepalive_interval)
            .keep_alive_while_idle(self.http2_keepalive_while_idle)
    }
}
