use bytes::Bytes;
use futures::future::join_all;
use futures::{Future, FutureExt};
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use opentelemetry_http::HeaderExtractor;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, info, instrument, warn, Instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use url::Url;

use super::super::http_client::{Client, ClientOptions};
use super::agent::types::{AgentService, StatusRequest};
use super::rpc::handle_rpc;
use super::store::bigtable::StoreClient;
use hsm_types::{GroupId, GroupStatus, HsmId, LeaderStatus, LogIndex};
use hsmcore::hsm::types as hsm_types;
use loam_sdk_core::types::RealmId;
use loam_sdk_networking::rpc::{self, Rpc, RpcError};

mod leader;
mod realm;
mod stepdown;
mod transfer;
pub mod types;

pub use leader::find_leaders;
pub use realm::{new_group, new_realm, NewGroupError, NewRealmError};
pub use transfer::{transfer, TransferError};

#[derive(Debug)]
pub enum Error {
    Grpc(tonic::Status),
    Rpc(RpcError),
}
impl From<tonic::Status> for Error {
    fn from(value: tonic::Status) -> Self {
        Self::Grpc(value)
    }
}
impl From<RpcError> for Error {
    fn from(value: RpcError) -> Self {
        Self::Rpc(value)
    }
}

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
struct ManagementGrant<'a> {
    mgr: &'a Manager,
    group: GroupId,
    realm: RealmId,
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

    pub async fn listen(
        self,
        address: SocketAddr,
    ) -> Result<(Url, JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(address).await?;
        let url = Url::parse(&format!("https://{address}")).unwrap();

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
                    types::StepDownRequest::PATH => {
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

async fn wait_for_commit(
    leader: &Url,
    realm: RealmId,
    group_id: GroupId,
    agent_client: &Client<AgentService>,
) -> Result<(), RpcError> {
    debug!(?realm, group = ?group_id, "waiting for first log entry to commit");
    loop {
        let status = rpc::send(agent_client, leader, StatusRequest {}).await?;
        let Some(hsm) = status.hsm else { continue };
        let Some(realm_status) = hsm.realm else { continue };
        if realm_status.id != realm {
            continue;
        }
        let group_status = realm_status
            .groups
            .iter()
            .find(|group_status| group_status.id == group_id);
        if let Some(GroupStatus {
            leader:
                Some(LeaderStatus {
                    committed: Some(committed),
                    ..
                }),
            ..
        }) = group_status
        {
            if *committed >= LogIndex::FIRST {
                info!(?realm, group = ?group_id, ?committed, "first log entry committed");
                return Ok(());
            }
        }

        sleep(Duration::from_millis(1)).await;
    }
}

async fn get_hsm_statuses(
    agents: &Client<AgentService>,
    agent_urls: impl Iterator<Item = &Url>,
) -> HashMap<HsmId, (hsm_types::StatusResponse, Url)> {
    join_all(
        agent_urls.map(|url| rpc::send(agents, url, StatusRequest {}).map(|r| (r, url.clone()))),
    )
    .await
    .into_iter()
    .filter_map(|(r, url)| r.ok().and_then(|s| s.hsm).map(|s| (s.id, (s, url))))
    .collect()
}
