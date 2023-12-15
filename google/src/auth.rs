use gcp_auth::AuthenticationManager;
use http::HeaderValue;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use tonic::body::BoxBody;
use tonic::transport::{Body, Channel};
use tower_service::Service;
use tracing::info;

use observability::metrics;

/// Initializes Google Cloud authentication from Application Default
/// Credentials.
///
/// This looks in environment variables, configuration files, and a local
/// metadata server for credentials that can be used to access Google Cloud.
/// See
/// <https://cloud.google.com/docs/authentication/application-default-credentials>
/// and the [`gcp_auth`] library for details.
pub async fn from_adc() -> Result<AuthenticationManager, gcp_auth::Error> {
    info!("initializing Google Cloud authentication with Application Default Credentials");
    AuthenticationManager::new().await
}

/// Tower middleware used for authenticating with Google Cloud services over
/// GRPC.
///
/// # Note
///
/// This should technically wrap a [`tower::Service`] generically. The current
/// implementation is specialized for a [`tonic::transport::Channel`], since
/// that's how it's currently used.
#[derive(Clone)]
pub struct AuthMiddleware {
    channel: Channel,
    auth_manager: Option<AuthenticationManager>,
    scopes: &'static [&'static str],
    metrics: metrics::Client,
}

impl AuthMiddleware {
    /// Constructor.
    ///
    /// Pass `None` for `auth_manager` to make this middleware have no effect.
    ///
    /// See <https://developers.google.com/identity/protocols/oauth2/scopes>
    /// for a list of possible scopes.
    pub fn new(
        channel: Channel,
        auth_manager: Option<AuthenticationManager>,
        scopes: &'static [&'static str],
        metrics: metrics::Client,
    ) -> Self {
        Self {
            channel,
            auth_manager,
            scopes,
            metrics,
        }
    }
}

impl Service<http::Request<BoxBody>> for AuthMiddleware {
    type Response = http::Response<Body>;
    type Error = AuthMiddlewareError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.channel.poll_ready(cx).map_err(Self::Error::Transport)
    }

    fn call(&mut self, mut request: http::Request<BoxBody>) -> Self::Future {
        // Based on https://github.com/hyperium/tonic/blob/master/examples/src/tower/client.rs:
        //
        //    This is necessary because tonic internally uses `tower::buffer::Buffer`.
        //    See https://github.com/tower-rs/tower/issues/547#issuecomment-767629149
        //    for details on why this is necessary
        let clone = self.channel.clone();
        let mut channel = std::mem::replace(&mut self.channel, clone);

        let auth_manager = self.auth_manager.clone();
        let scopes = self.scopes;
        let metrics = self.metrics.clone();

        Box::pin(async move {
            if let Some(auth_manager) = auth_manager {
                let token = metrics
                    .async_time("gcp.get_token.ns", metrics::NO_TAGS, || {
                        auth_manager.get_token(scopes)
                    })
                    .await
                    .map_err(Self::Error::Auth)?;

                let mut value = HeaderValue::try_from(format!("Bearer {}", token.secret()))
                    .expect("malformed gcp_auth token");
                value.set_sensitive(true);

                request.headers_mut().append("authorization", value);
            }

            channel.call(request).await.map_err(Self::Error::Transport)
        })
    }
}

#[derive(Debug)]
pub enum AuthMiddlewareError {
    Auth(gcp_auth::Error),
    Transport(tonic::transport::Error),
}

impl std::error::Error for AuthMiddlewareError {}

impl fmt::Display for AuthMiddlewareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(e) => e.fmt(f),
            Self::Transport(e) => e.fmt(f),
        }
    }
}
