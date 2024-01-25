use anyhow::Context;
use bytes::Bytes;
use cluster_core::{get_hsm_statuses, HsmsStatus, ManagementGrant, ManagementLeaseKey};
use http_body_util::Full;
use hyper::http;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
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
use retry_loop::RetryError;
use service_core::http::ReqwestClientMetrics;
use service_core::rpc::handle_rpc;
use store::discovery::{REGISTER_FAILURE_DELAY, REGISTER_INTERVAL};
use store::{ServiceKind, StoreClient};

mod leader;
mod rebalance;
mod stepdown;
mod transfer;

#[derive(Clone)]
pub struct Manager(Arc<ManagerInner>);

struct ManagerInner {
    // Name to use as owner in leases.
    name: String,
    store: Arc<StoreClient>,
    agents: ReqwestClientMetrics,
    // Set when the initial registration in service discovery completes
    // successfully.
    registered: AtomicBool,
    status: HsmStatusCache,
}

impl Manager {
    pub fn new(
        name: String,
        store: StoreClient,
        update_interval: Duration,
        rebalance_interval: Duration,
        metrics: metrics::Client,
    ) -> Self {
        let store = Arc::new(store);
        let agents = ReqwestClientMetrics::new(metrics.clone(), ClientOptions::default());
        let hsm_status = HsmStatusCache::new(store.clone(), agents.clone());

        let m = Self(Arc::new(ManagerInner {
            name,
            store: store.clone(),
            agents,
            registered: AtomicBool::new(false),
            status: hsm_status,
        }));
        let manager = m.clone();

        tokio::spawn(async move {
            let cx = opentelemetry::Context::new().with_value(TracingSource::BackgroundJob);

            loop {
                sleep(update_interval).await;

                let span = span!(Level::TRACE, "ensure_groups_have_leader_loop");
                span.set_parent(cx.clone());

                if let Err(err) = manager.ensure_groups_have_leader().await {
                    warn!(?err, "Error while checking all groups have a leader");
                }
            }
        });

        let manager = m.clone();
        tokio::spawn(async move {
            let cx = opentelemetry::Context::new().with_value(TracingSource::BackgroundJob);

            loop {
                sleep(update_interval).await;

                let span = span!(Level::TRACE, "ensure_transfers_finished");
                span.set_parent(cx.clone());

                if let Err(err) = manager.ensure_transfers_finished().await {
                    warn!(
                        ?err,
                        "Error while checking that ownership transfers are completed"
                    );
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
    ) -> Result<Option<ManagementGrant>, RetryError<tonic::Status>> {
        ManagementGrant::obtain(
            self.0.store.clone(),
            self.0.name.clone(),
            ManagementLeaseKey::RealmGroup(realm, group),
        )
        .await
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

#[derive(Clone)]
struct HsmStatusCache {
    state: Arc<Mutex<HsmStatusCacheInner>>,
    store: Arc<StoreClient>,
    agent_client: ReqwestClientMetrics,
}

struct HsmStatusCacheInner {
    cache: HsmsStatus,
    updated: Option<Instant>,
}

impl HsmStatusCache {
    fn new(store: Arc<StoreClient>, agent_client: ReqwestClientMetrics) -> Self {
        HsmStatusCache {
            state: Arc::new(Mutex::new(HsmStatusCacheInner {
                cache: HashMap::new(),
                updated: None,
            })),
            store,
            agent_client,
        }
    }

    async fn status(&self, freshness: Duration) -> Result<HsmsStatus, RetryError<tonic::Status>> {
        let cached = {
            let locked = self.state.lock().unwrap();
            if locked
                .updated
                .is_some_and(|last_updated| Instant::now().duration_since(last_updated) < freshness)
            {
                Some(locked.cache.clone())
            } else {
                None
            }
        };
        match cached {
            None => self.refresh().await,
            Some(c) => Ok(c),
        }
    }

    async fn refresh(&self) -> Result<HsmsStatus, RetryError<tonic::Status>> {
        let addresses = self.store.get_addresses(Some(ServiceKind::Agent)).await?;
        let status = get_hsm_statuses(
            &self.agent_client,
            addresses.iter().map(|(url, _)| url),
            Some(Duration::from_secs(5)),
        )
        .await;
        let result = status.clone();
        let mut locked = self.state.lock().unwrap();
        locked.cache = status;
        locked.updated = Some(Instant::now());
        Ok(result)
    }

    fn mark_dirty(&self) {
        self.state.lock().unwrap().updated = None;
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

    #[tokio::test]
    async fn management_grant() {
        // TODO: rewrite to use obtain and move to cluster_core
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
