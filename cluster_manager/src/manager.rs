use anyhow::Context;
use bytes::Bytes;
use futures::Future;
use http_body_util::Full;
use hyper::http;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use opentelemetry_http::HeaderExtractor;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{info, instrument, warn, Instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use url::Url;

use agent_api::AgentService;
use hsm_api::GroupId;
use juicebox_networking::reqwest::{Client, ClientOptions};
use juicebox_networking::rpc::Rpc;
use juicebox_realm_api::types::RealmId;
use service_core::rpc::handle_rpc;
use store::discovery::{REGISTER_FAILURE_DELAY, REGISTER_INTERVAL};
use store::{Lease, LeaseKey, LeaseType, ServiceKind, StoreClient};

mod leader;
mod stepdown;

const LEASE_DURATION: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct Manager(Arc<ManagerInner>);

struct ManagerInner {
    // Name to use as owner in leases.
    name: String,
    store: StoreClient,
    agents: Client<AgentService>,
}

/// When drop'd will remove the realm/group lease from the store.
pub struct ManagementGrant {
    pub group: GroupId,
    pub realm: RealmId,
    inner: Option<ManagementGrantInner>,
}

struct ManagementGrantInner {
    mgr: Manager, // Manager is cheap to clone.
    lease: Lease,
    renewer: JoinHandle<()>,
}

impl ManagementGrant {
    fn new(mgr: Manager, realm: RealmId, group: GroupId, lease: Lease) -> Self {
        let mgr2 = mgr.clone();
        let lease2 = lease.clone();
        // This task gets aborted when the ManagementGrant is dropped.
        let renewer = tokio::spawn(async move {
            loop {
                sleep(LEASE_DURATION / 3).await;
                mgr2.0
                    .store
                    .extend_lease(&lease2, LEASE_DURATION, SystemTime::now())
                    .await
                    .expect("error while trying to extend lease");
            }
        });
        ManagementGrant {
            group,
            realm,
            inner: Some(ManagementGrantInner {
                mgr,
                lease,
                renewer,
            }),
        }
    }
}

impl Drop for ManagementGrant {
    fn drop(&mut self) {
        info!(group=?self.group, realm=?self.realm, "management task completed");
        let inner = self.inner.take().unwrap();
        inner.renewer.abort();
        tokio::spawn(async move {
            _ = inner.renewer.await;
            _ = inner.mgr.0.store.terminate_lease(inner.lease).await;
        });
    }
}

pub enum ManagementLease {
    RealmGroup(RealmId, GroupId),
}

impl From<ManagementLease> for LeaseKey {
    fn from(value: ManagementLease) -> Self {
        let k = match value {
            ManagementLease::RealmGroup(r, g) => format!("{r:?}-{g:?}").into_bytes(),
        };
        LeaseKey(LeaseType::ClusterManagement, k)
    }
}

impl Manager {
    pub fn new(name: String, store: StoreClient, update_interval: Duration) -> Self {
        let m = Self(Arc::new(ManagerInner {
            name,
            store,
            agents: Client::new(ClientOptions::default()),
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
    // dropped, the group will be removed from the busy set. The grant uses a
    // lease managed by the bigtable store. The grant applies across all cluster
    // managers using the same store, not just this instance.
    async fn mark_as_busy(
        &self,
        realm: RealmId,
        group: GroupId,
    ) -> Result<Option<ManagementGrant>, tonic::Status> {
        let grant = self
            .0
            .store
            .obtain_lease(
                ManagementLease::RealmGroup(realm, group),
                self.0.name.clone(),
                LEASE_DURATION,
                SystemTime::now(),
            )
            .await?
            .map(|lease| {
                info!(?group, ?realm, "marking group as under active management");
                ManagementGrant::new(self.clone(), realm, group, lease)
            });
        Ok(grant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use juicebox_process_group::ProcessGroup;
    use once_cell::sync::Lazy;
    use testing::exec::bigtable::{emulator, BigtableRunner};
    use testing::exec::PortIssuer;

    static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8222));

    #[test]
    fn lease_key() {
        let lk = ManagementLease::RealmGroup(RealmId([9; 16]), GroupId([3; 16]));
        let k: LeaseKey = lk.into();
        assert_eq!(LeaseType::ClusterManagement, k.0);
        assert_eq!(
            b"09090909090909090909090909090909-03030303030303030303030303030303".to_vec(),
            k.1
        );
    }

    #[tokio::test]
    async fn management_grant() {
        let mut pg = ProcessGroup::new();
        let bt_args = emulator(PORT.next());
        BigtableRunner::run(&mut pg, &bt_args).await;

        let store_admin = bt_args
            .connect_admin(None)
            .await
            .expect("failed to connect to bigtable admin service");
        store_admin
            .initialize_leases()
            .await
            .expect("failed to initialize leases table");
        store_admin
            .initialize_discovery()
            .await
            .expect("failed to initialize discovery table");

        let store = bt_args
            .connect_data(None, store::Options::default())
            .await
            .expect("failed to connect to bigtable data service");

        let m1 = Manager::new(
            String::from("one"),
            store.clone(),
            Duration::from_secs(1000),
        );
        let m2 = Manager::new(String::from("two"), store, Duration::from_secs(1000));

        let realm1 = RealmId([1; 16]);
        let realm2 = RealmId([2; 16]);
        let group1 = GroupId([3; 16]);
        let group2 = GroupId([4; 16]);

        let grant = m1.mark_as_busy(realm1, group1).await.unwrap().unwrap();
        // can't get a grant to the same realm/group until grant is dropped.
        assert!(m1.mark_as_busy(realm1, group1).await.unwrap().is_none());
        assert!(m2.mark_as_busy(realm1, group1).await.unwrap().is_none());
        drop(grant);
        // the removal of the lease is async, so we may not be able to grab the lease again
        // exactly right away
        let mut _grant2 = None;
        for tries in 0..10 {
            _grant2 = m2.mark_as_busy(realm1, group1).await.unwrap();
            if _grant2.is_some() {
                break;
            }
            if tries == 10 {
                panic!("failed to get management grant");
            }
            sleep(Duration::from_millis(5)).await;
        }
        // can get a grant to other realm/groups
        let _grant3 = m2.mark_as_busy(realm1, group2).await.unwrap().unwrap();
        let _grant4 = m1.mark_as_busy(realm2, group1).await.unwrap().unwrap();
        // can't get a grant to the same realm/group until grant is dropped.
        assert!(m1.mark_as_busy(realm1, group1).await.unwrap().is_none());
        assert!(m2.mark_as_busy(realm1, group1).await.unwrap().is_none());
        assert!(m1.mark_as_busy(realm1, group2).await.unwrap().is_none());
        assert!(m2.mark_as_busy(realm1, group2).await.unwrap().is_none());
        assert!(m1.mark_as_busy(realm2, group1).await.unwrap().is_none());
        assert!(m2.mark_as_busy(realm2, group1).await.unwrap().is_none());
    }
}
