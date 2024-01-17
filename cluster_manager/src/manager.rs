use anyhow::Context;
use bytes::Bytes;
use http_body_util::Full;
use hyper::http;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{info, span, warn, Instrument, Level, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use url::Url;

use hsm_api::GroupId;
use juicebox_networking::reqwest::ClientOptions;
use juicebox_networking::rpc::Rpc;
use juicebox_realm_api::types::RealmId;
use observability::logging::TracingSource;
use observability::metrics;
use observability::tracing::TracingMiddleware;
use service_core::http::ReqwestClientMetrics;
use service_core::rpc::handle_rpc;
use store::discovery::{REGISTER_FAILURE_DELAY, REGISTER_INTERVAL};
use store::{Lease, LeaseKey, LeaseType, ServiceKind, StoreClient};

mod leader;
mod rebalance;
mod stepdown;
mod transfer;

const LEASE_DURATION: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct Manager(Arc<ManagerInner>);

struct ManagerInner {
    // Name to use as owner in leases.
    name: String,
    store: StoreClient,
    agents: ReqwestClientMetrics,
    // Set when the initial registration in service discovery completes
    // successfully.
    registered: AtomicBool,
}

/// When drop'd will remove the lease from the store.
pub struct ManagementGrant {
    key: ManagementLeaseKey,
    inner: Option<ManagementGrantInner>,
}

struct ManagementGrantInner {
    mgr: Manager, // Manager is cheap to clone.
    lease: Lease,
    renewer: JoinHandle<()>,
}

impl ManagementGrant {
    /// Takes a lease out for some management operation that should block
    /// conflicting management operations.
    ///
    /// Returns None if the lease has already been taken by some other task.
    /// When the returned `ManagementGrant` is dropped, the lease will be
    /// terminated.
    ///
    /// The grant uses a lease managed by the bigtable store. The grant applies
    /// across all cluster managers using the same store, not just this
    /// instance.
    async fn obtain(mgr: Manager, key: ManagementLeaseKey) -> Result<Option<Self>, tonic::Status> {
        Ok(mgr
            .0
            .store
            .obtain_lease(
                key.clone(),
                mgr.0.name.clone(),
                LEASE_DURATION,
                SystemTime::now(),
            )
            .await?
            .map(|lease| {
                info!(?key, "obtained lease for active management");
                ManagementGrant::new(mgr, key, lease)
            }))
    }

    fn new(mgr: Manager, key: ManagementLeaseKey, lease: Lease) -> Self {
        let mgr2 = mgr.clone();
        let lease2 = lease.clone();
        // This task gets aborted when the ManagementGrant is dropped.
        let renewer = tokio::spawn(async move {
            let mut lease = lease2;
            loop {
                sleep(LEASE_DURATION / 3).await;
                let now = SystemTime::now();
                let expires = lease.until();
                lease = tokio::select! {
                    result = mgr2
                    .0
                    .store
                    .extend_lease(lease, LEASE_DURATION, now) => result.expect("failed to extend lease"),
                    _ = sleep(expires.duration_since(now).unwrap()) => panic!("didn't renew lease in time")
                }
            }
        });
        ManagementGrant {
            key,
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
        let inner = self.inner.take().unwrap();
        info!(
            key = ?self.key,
            "management task completed. dropping lease"
        );
        inner.renewer.abort();
        tokio::spawn(async move {
            _ = inner.renewer.await;
            if let Err(err) = inner.mgr.0.store.terminate_lease(inner.lease).await {
                warn!(?err, "gRPC error while trying to terminate lease");
            }
        });
    }
}

#[derive(Clone, Debug)]
pub enum ManagementLeaseKey {
    RealmGroup(RealmId, GroupId),
    Ownership(RealmId),
}

impl From<ManagementLeaseKey> for LeaseKey {
    fn from(value: ManagementLeaseKey) -> Self {
        let k = match value {
            ManagementLeaseKey::RealmGroup(r, g) => format!("{r:?}-{g:?}"),
            ManagementLeaseKey::Ownership(r) => format!("{r:?}-ownership"),
        };
        LeaseKey(LeaseType::ClusterManagement, k)
    }
}

impl Manager {
    pub fn new(
        name: String,
        store: StoreClient,
        update_interval: Duration,
        rebalance_interval: Duration,
        metrics: metrics::Client,
    ) -> Self {
        let m = Self(Arc::new(ManagerInner {
            name,
            store,
            agents: ReqwestClientMetrics::new(metrics, ClientOptions::default()),
            registered: AtomicBool::new(false),
        }));
        let manager = m.clone();
        tokio::spawn(async move {
            let cx = opentelemetry::Context::new().with_value(TracingSource::BackgroundJob);
            loop {
                sleep(update_interval).await;

                let span = span!(Level::TRACE, "ensure_groups_have_leader_loop");
                span.set_parent(cx.clone());

                if let Err(err) = manager.ensure_groups_have_leader().await {
                    warn!(?err, "Error while checking all groups have a leader")
                }
            }
        });

        let manager = m.clone();
        tokio::spawn(async move {
            let cx = opentelemetry::Context::new().with_value(TracingSource::BackgroundJob);
            loop {
                sleep(rebalance_interval).await;

                let span = span!(Level::TRACE, "rebalance_work_loop");
                span.set_parent(cx.clone());

                if let Err(err) = manager.rebalance_work().await {
                    warn!(?err, "Error while rebalancing the cluster")
                }
            }
        });
        m
    }

    pub async fn listen(self, address: SocketAddr) -> Result<(Url, JoinHandle<()>), anyhow::Error> {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("failed to bind to {address}"))?;
        let url = Url::parse(&format!("http://{address}")).unwrap();

        let manager = self.clone();
        let disco_url = url.clone();
        let mut first_registration = true;
        tokio::spawn(async move {
            info!(%disco_url, "registering cluster manager with service discovery");
            loop {
                if let Err(e) = manager
                    .0
                    .store
                    .set_address(&disco_url, ServiceKind::ClusterManager, SystemTime::now())
                    .await
                {
                    warn!(err = ?e, "failed to register with service discovery");
                    sleep(REGISTER_FAILURE_DELAY).await;
                } else {
                    if first_registration {
                        manager
                            .0
                            .registered
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                        first_registration = false;
                    }
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
                            let io = TokioIo::new(stream);
                            let manager = TracingMiddleware::new(self.clone());
                            tokio::spawn(async move {
                                if let Err(e) =
                                    http1::Builder::new().serve_connection(io, manager).await
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

    fn call(&self, request: Request<IncomingBody>) -> Self::Future {
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
                    "livez" => Ok(manager.handle_livez()),
                    cluster_api::StepDownRequest::PATH => {
                        handle_rpc(&manager, request, Self::handle_leader_stepdown).await
                    }
                    cluster_api::RebalanceRequest::PATH => {
                        handle_rpc(&manager, request, Self::handle_rebalance).await
                    }
                    cluster_api::TransferRequest::PATH => {
                        handle_rpc(&manager, request, Self::handle_transfer).await
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
    // This is a very thin wrapper now that should probably go away, but it's
    // called in many places (for tests).
    async fn mark_as_busy(
        &self,
        realm: RealmId,
        group: GroupId,
    ) -> Result<Option<ManagementGrant>, tonic::Status> {
        ManagementGrant::obtain(self.clone(), ManagementLeaseKey::RealmGroup(realm, group)).await
    }

    fn handle_livez(&self) -> Response<Full<Bytes>> {
        if self.0.registered.load(Ordering::Relaxed) {
            Response::builder()
                .status(http::StatusCode::OK)
                .body(Full::from(Bytes::from(format!(
                    "ok\n{}",
                    build_info::get!().livez()
                ))))
                .unwrap()
        } else {
            Response::builder()
                .status(http::StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::from(Bytes::from(format!(
                    "not yet registered with service discovery\n{}",
                    build_info::get!().livez()
                ))))
                .unwrap()
        }
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
        let lk = ManagementLeaseKey::RealmGroup(RealmId([9; 16]), GroupId([3; 16]));
        let k: LeaseKey = lk.into();
        assert_eq!(LeaseType::ClusterManagement, k.0);
        assert_eq!(
            "09090909090909090909090909090909-03030303030303030303030303030303".to_string(),
            k.1
        );
    }

    #[tokio::test]
    async fn management_grant() {
        let mut pg = ProcessGroup::new();
        let bt_args = emulator(PORT.next());
        BigtableRunner::run(&mut pg, &bt_args).await;

        let store_admin = bt_args
            .connect_admin(None, metrics::Client::NONE)
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
            Duration::from_secs(1000),
            metrics::Client::NONE,
        );
        let m2 = Manager::new(
            String::from("two"),
            store,
            Duration::from_secs(1000),
            Duration::from_secs(1000),
            metrics::Client::NONE,
        );

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
