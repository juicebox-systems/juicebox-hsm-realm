use anyhow::Context;
use bytes::Bytes;
use futures::Future;
use http_body_util::Full;
use hyper::http;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use opentelemetry_http::HeaderExtractor;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{info, instrument, warn, Instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use url::Url;

use agent_api::AgentService;
use hsm_types::GroupId;
use hsmcore::hsm::types as hsm_types;
use juicebox_hsm::realm::rpc::handle_rpc;
use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_networking::reqwest::{Client, ClientOptions};
use juicebox_sdk_networking::rpc::Rpc;
use store::discovery::{REGISTER_FAILURE_DELAY, REGISTER_INTERVAL};
use store::{ServiceKind, StoreClient};

mod leader;
mod stepdown;

#[derive(Clone)]
pub struct Manager(Arc<ManagerInner>);

struct ManagerInner {
    store: StoreClient,
    agents: Client<AgentService>,
    // Groups that are being actively managed through some transition and other
    // management operations on the group should be skipped.
    busy_groups: Mutex<HashSet<(RealmId, GroupId)>>,
}

/// When drop'd will remove the realm/group from the managers busy_groups set.
pub struct ManagementGrant<'a> {
    mgr: &'a Manager,
    pub group: GroupId,
    pub realm: RealmId,
}

impl<'a> Drop for ManagementGrant<'a> {
    fn drop(&mut self) {
        info!(group=?self.group, realm=?self.realm, "management task completed");
        self.mgr
            .0
            .busy_groups
            .lock()
            .unwrap()
            .remove(&(self.realm, self.group));
    }
}

impl Manager {
    pub fn new(store: StoreClient, update_interval: Duration) -> Self {
        let m = Self(Arc::new(ManagerInner {
            store,
            agents: Client::new(ClientOptions::default()),
            busy_groups: Mutex::new(HashSet::new()),
        }));
        let manager = m.clone();
        tokio::spawn(async move {
            loop {
                sleep(update_interval).await;
                manager.run().await;
            }
        });
        m
    }

    pub async fn listen(self, address: SocketAddr) -> Result<(Url, JoinHandle<()>), anyhow::Error> {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("failed to bind to {address}"))?;
        let url = Url::parse(&format!("http://{address}")).unwrap();

        let store = self.0.store.clone();
        let disco_url = url.clone();
        tokio::spawn(async move {
            info!(%disco_url, "registering cluster manager with service discovery");
            loop {
                if let Err(e) = store
                    .set_address(&disco_url, ServiceKind::ClusterManager, SystemTime::now())
                    .await
                {
                    warn!(err = ?e, "failed to register with service discovery");
                    sleep(REGISTER_FAILURE_DELAY).await;
                } else {
                    sleep(REGISTER_INTERVAL).await;
                }
            }
        });
        Ok((
            url,
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Err(e) => warn!("error accepting connection: {e:?}"),
                        Ok((stream, _)) => {
                            let manager = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(stream, manager)
                                    .await
                                {
                                    warn!("error serving connection: {e:?}");
                                }
                            });
                        }
                    }
                }
            }),
        ))
    }
}

impl Service<Request<IncomingBody>> for Manager {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[instrument(level = "trace", skip(self, request))]
    fn call(&mut self, request: Request<IncomingBody>) -> Self::Future {
        let parent_context = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(request.headers()))
        });
        Span::current().set_parent(parent_context);

        let manager = self.clone();
        Box::pin(
            async move {
                let Some(path) = request.uri().path().strip_prefix('/') else {
                    return Ok(Response::builder()
                        .status(http::StatusCode::NOT_FOUND)
                        .body(Full::from(Bytes::new()))
                        .unwrap());
                };
                match path {
                    cluster_api::StepDownRequest::PATH => {
                        handle_rpc(&manager, request, Self::handle_leader_stepdown).await
                    }
                    _ => Ok(Response::builder()
                        .status(http::StatusCode::NOT_FOUND)
                        .body(Full::from(Bytes::new()))
                        .unwrap()),
                }
            }
            // This doesn't look like it should do anything, but it seems to be
            // critical to connecting these spans to the parent.
            .instrument(Span::current()),
        )
    }
}

impl Manager {
    /// Perform one pass of the management tasks.
    async fn run(&self) {
        if let Err(err) = self.ensure_groups_have_leader().await {
            warn!(?err, "Error while checking/updating cluster state")
        }
    }

    // Track that the group is going through some management operation that
    // should block other management operations. Returns None if the group is
    // already busy by some other task. When the returned ManagementGrant is
    // dropped, the group will be removed from the busy set.
    fn mark_as_busy(&self, realm: RealmId, group: GroupId) -> Option<ManagementGrant> {
        let mut locked = self.0.busy_groups.lock().unwrap();
        if locked.insert((realm, group)) {
            info!(?group, ?realm, "marking group as under active management");
            Some(ManagementGrant {
                mgr: self,
                realm,
                group,
            })
        } else {
            None
        }
    }
}
