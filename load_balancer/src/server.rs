use futures::Future;
use hyper::body::{Body, Incoming};
use hyper::rt::bounds::Http2ConnExec;
use hyper::server::conn::{http1, http2};
use hyper::service::HttpService;
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, watch, Mutex};
use tokio::time::{sleep, Instant, Sleep};
use tracing::{debug, info, warn};

pub struct ManagerOptions {
    pub conn: ConnectionOptions,
    // The minimum number of health checks that report shutting down
    // before starting to drain any active requests/connections.
    pub min_health_checks_before_shutdown: usize,
}

impl Default for ManagerOptions {
    fn default() -> Self {
        Self {
            conn: Default::default(),
            min_health_checks_before_shutdown: 2,
        }
    }
}

pub struct ServiceManager {
    conn_mgr: Arc<ConnectionManager>,
    shutting_down: AtomicBool,
    health_checks_since_shutdown: AtomicUsize,
    shutdown_health_checks: Mutex<Option<watch::Sender<usize>>>,
    options: ManagerOptions,
}

impl ServiceManager {
    pub fn new(options: ManagerOptions) -> Self {
        Self {
            conn_mgr: Arc::new(ConnectionManager::new(options.conn.clone())),
            shutting_down: AtomicBool::new(false),
            health_checks_since_shutdown: AtomicUsize::new(0),
            shutdown_health_checks: Mutex::new(None),
            options,
        }
    }

    pub fn connection_manager(&self) -> Arc<ConnectionManager> {
        self.conn_mgr.clone()
    }

    pub async fn health_check(&self) -> HealthCheckStatus {
        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            let count = self
                .health_checks_since_shutdown
                .fetch_add(1, Ordering::SeqCst);

            if let Some(tx) = self.shutdown_health_checks.lock().await.as_ref() {
                if let Err(err) = tx.send(count + 1) {
                    warn!(?err, "failed to send health check count on channel");
                }
            }
            HealthCheckStatus::ShuttingDown
        } else {
            HealthCheckStatus::Ok
        }
    }

    // Perform a graceful shutdown of the service. This performs 2 main steps.
    // It flags the health check as shutting down, so that CloudFlare will stop
    // sending requests to this host. We wait for the health check to have been
    // seen a number of times (see min_health_checks_before_shutdown in
    // ManagerOptions) before proceeding. Then we tell every active connection
    // to do a graceful shutdown and wait til all the connections are closed.
    pub async fn shutdown(&self) {
        let (tx, mut rx) = watch::channel::<usize>(0);
        *self.shutdown_health_checks.lock().await = Some(tx);
        self.health_checks_since_shutdown.store(0, Ordering::SeqCst);
        self.shutting_down.store(true, Ordering::SeqCst);

        info!("shutdown in progress, waiting for health checks");
        if let Err(err) = rx
            .wait_for(|count| *count >= self.options.min_health_checks_before_shutdown)
            .await
        {
            warn!(?err, "failed to wait on the health checks count channel");
        }
        self.conn_mgr.shutdown().await
    }
}

pub enum HealthCheckStatus {
    Ok,
    ShuttingDown,
}

#[derive(Clone)]
pub struct ConnectionOptions {
    pub idle_timeout: Duration,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(5),
        }
    }
}

pub struct ConnectionManager {
    options: ConnectionOptions,
    connections_changed_tx: broadcast::Sender<ConnectionEvent>,
    connections_count_rx: watch::Receiver<usize>,
    shutdown: AtomicBool,
    shutdown_tx: broadcast::Sender<()>,
}

impl ConnectionManager {
    pub fn new(options: ConnectionOptions) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        let (conn_tx, mut conn_rx) = broadcast::channel(32);
        let (count_tx, count_rx) = watch::channel(0);
        let cm = Self {
            shutdown: AtomicBool::new(false),
            shutdown_tx,
            options,
            connections_changed_tx: conn_tx,
            connections_count_rx: count_rx,
        };
        tokio::spawn(async move {
            let mut count: usize = 0;
            while let Ok(e) = conn_rx.recv().await {
                match e {
                    ConnectionEvent::Opened => count += 1,
                    ConnectionEvent::Closed => count -= 1,
                }
                count_tx.send_replace(count);
                debug!(?count, "active HTTP connections");
            }
        });
        cm
    }

    pub fn manage<C: GracefulShutdown>(&self, conn: C) -> GracefulConnection<C> {
        self.connections_changed_tx
            .send(ConnectionEvent::Opened)
            .unwrap();
        GracefulConnection::new(
            conn,
            self.shutdown_tx.subscribe(),
            self.options.idle_timeout,
            self.connections_changed_tx.clone(),
        )
    }

    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    async fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let count = self.shutdown_tx.send(()).unwrap_or_default();
        info!(
            subscribers = count,
            "shutdown in progress, waiting for connections to close"
        );

        let mut count = self.connections_count_rx.clone();
        if let Err(err) = count.wait_for(|count| *count == 0).await {
            warn!(?err, "Error waiting for connection count to reach 0");
        };
    }
}

#[derive(Clone, Copy, Debug)]
enum ConnectionEvent {
    Opened,
    Closed,
}

pin_project! {
    pub struct GracefulConnection<C>
    where
        // This is a hyper http1::Connection or http2::Connection
        C:GracefulShutdown,
    {
        #[pin]
        conn: C,
        #[pin]
        idle_timer:Sleep,
        idle_timeout:Duration,
        shutdown_rx: broadcast::Receiver<()>,
        finished_tx: broadcast::Sender<ConnectionEvent>
    }
}

impl<C: GracefulShutdown> GracefulConnection<C> {
    fn new(
        conn: C,
        shutdown_rx: broadcast::Receiver<()>,
        idle_timeout: Duration,
        finished_tx: broadcast::Sender<ConnectionEvent>,
    ) -> Self {
        Self {
            conn,
            idle_timer: sleep(idle_timeout),
            idle_timeout,
            shutdown_rx,
            finished_tx,
        }
    }
}

impl<C> Future for GracefulConnection<C>
where
    C: GracefulShutdown + Future<Output = hyper::Result<()>>,
{
    type Output = hyper::Result<()>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let mut this = self.project();
        let shutdown =
            this.idle_timer.as_mut().poll(cx).is_ready() || this.shutdown_rx.try_recv().is_ok();
        if shutdown {
            this.conn.as_mut().start_graceful_shutdown();
        } else {
            this.idle_timer
                .as_mut()
                .reset(Instant::now() + *this.idle_timeout);
        }
        let result = this.conn.poll(cx);
        if result.is_ready() {
            // This future is complete which means it has finished processing requests.
            if this.finished_tx.send(ConnectionEvent::Closed).is_err() {
                warn!("failed to send connection closed event on channel");
            }
        }
        result
    }
}

// As hyper http1 & http2 connection objects are different, this trait allows us
// to abstract away the fact that they're different.
pub trait GracefulShutdown {
    fn start_graceful_shutdown(self: Pin<&mut Self>);
}

impl<IO, SVC, B> GracefulShutdown for http1::Connection<IO, SVC>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
    B: Body + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    SVC: HttpService<Incoming, ResBody = B>,
    SVC::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    fn start_graceful_shutdown(self: Pin<&mut Self>) {
        self.graceful_shutdown();
    }
}

impl<IO, SVC, B, EXEC> GracefulShutdown for http2::Connection<IO, SVC, EXEC>
where
    IO: AsyncRead + AsyncWrite + Unpin + 'static,
    B: Body + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    SVC: HttpService<Incoming, ResBody = B>,
    SVC::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    EXEC: Http2ConnExec<SVC::Future, B>,
{
    fn start_graceful_shutdown(self: Pin<&mut Self>) {
        self.graceful_shutdown();
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures::{select_biased, FutureExt};
    use http::StatusCode;
    use http_body_util::Full;
    use hyper::service::Service;
    use hyper::{body::Incoming, Request, Response};
    use std::error::Error;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn graceful_shutdown() {
        let (server, mut active_rx) = TestService::new(4444).await;
        let client = reqwest::Client::new();
        let hc = client.get("http://localhost:4444/livez").send().await;
        assert_eq!("OK".to_string(), hc.unwrap().text().await.unwrap());

        // After we trigger a shutdown, the health should report shutting down
        // but otherwise things should be able to proceed as normal.
        let server2 = server.clone();
        let shutdown_handle = tokio::spawn(async move {
            server2.0.server.mgr.shutdown().await;
        });

        let hc = client.get("http://localhost:4444/livez").send().await;
        assert_eq!(
            "Shutting down".to_string(),
            hc.unwrap().text().await.unwrap()
        );
        assert!(!shutdown_handle.is_finished());

        // We need to manually release responses that are not for the health check
        // this lets is have pending requests while shutting down.
        server.respond_next().await;
        let req = client.get("http://localhost:4444/req").send().await;
        assert_eq!(
            "Test Service".to_string(),
            req.unwrap().text().await.unwrap()
        );

        // can still get new connections
        server.respond_next().await;
        let req = reqwest::Client::new()
            .get("http://localhost:4444/req")
            .send()
            .await;
        assert_eq!(
            "Test Service".to_string(),
            req.unwrap().text().await.unwrap()
        );

        // start a request, but leave it blocking on the server response.
        let pend = tokio::spawn(client.get("http://localhost:4444/req").send());
        // It takes time for the spawned task to get to the point where its blocking on the response.
        active_rx.wait_for(|count| *count == 1).await.unwrap();

        // After the 2nd health check shutdown should proceed, including no longer accepting connections.
        let hc = client.get("http://localhost:4444/livez").send().await;
        assert_eq!(
            "Shutting down".to_string(),
            hc.unwrap().text().await.unwrap()
        );
        assert!(client
            .get("http://localhost:4444/livez")
            .send()
            .await
            .is_err());
        // There's a pending (aka in progress) request still, so shutdown shouldn't finish.
        assert!(!shutdown_handle.is_finished());
        assert!(!pend.is_finished());
        assert_eq!(1, *active_rx.borrow());

        // when that pending request finishes, shutdown should then complete.
        server.respond_next().await;
        assert_eq!(
            "Test Service".to_string(),
            pend.await.unwrap().unwrap().text().await.unwrap()
        );
        assert!(timeout(Duration::from_secs(1), shutdown_handle)
            .await
            .is_ok());
    }

    struct TestServer {
        mgr: ServiceManager,
        respond_next_tx: broadcast::Sender<()>,
    }

    impl TestService {
        // The returned watch rx monitors the number of active requests excluding health checks.
        async fn new(port: u16) -> (Self, watch::Receiver<usize>) {
            let mgr = ServiceManager::new(ManagerOptions {
                conn: ConnectionOptions {
                    idle_timeout: Duration::from_secs(5),
                },
                min_health_checks_before_shutdown: 2,
            });
            let (respond_next_tx, respond_next_rx) = broadcast::channel(1);

            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap();

            let (pending_tx, pending_rx) = watch::channel(0);
            let service = TestService(Arc::new(TestServiceInner {
                respond_next_rx: Mutex::new(respond_next_rx),
                server: TestServer {
                    mgr,
                    respond_next_tx,
                },
                pending_count: AtomicUsize::new(0),
                pending_watch: pending_tx,
            }));
            let conn_mgr = service.0.server.mgr.connection_manager();
            let mut shutdown_rx = conn_mgr.subscribe_shutdown();
            let service2 = service.clone();
            tokio::spawn(async move {
                loop {
                    let (stream, _) = select_biased! {
                        _ = shutdown_rx.recv().fuse() => { return; }
                        result = listener.accept().fuse() => result.unwrap(),
                    };
                    let service = service.clone();
                    let conn_mgr = conn_mgr.clone();
                    tokio::spawn(async move {
                        let c = http1::Builder::new().serve_connection(stream, service);
                        let c = conn_mgr.manage(c);
                        c.await.unwrap();
                    });
                }
            });
            (service2, pending_rx)
        }

        async fn respond_next(&self) {
            self.0.server.respond_next_tx.send(()).unwrap();
        }
    }

    #[derive(Clone)]
    struct TestService(Arc<TestServiceInner>);

    struct TestServiceInner {
        respond_next_rx: Mutex<broadcast::Receiver<()>>,
        pending_count: AtomicUsize,
        pending_watch: watch::Sender<usize>,
        server: TestServer,
    }

    impl Service<Request<Incoming>> for TestService {
        type Response = Response<Full<Bytes>>;
        type Error = Box<dyn Error + Send + Sync>;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn call(&mut self, request: Request<Incoming>) -> Self::Future {
            let s = self.clone();
            Box::pin(async move {
                let count = s.0.pending_count.fetch_add(1, Ordering::SeqCst);
                s.0.pending_watch.send_replace(count + 1);

                let result = if request.uri().path() == "/livez" {
                    let body = match s.0.server.mgr.health_check().await {
                        HealthCheckStatus::Ok => "OK",
                        HealthCheckStatus::ShuttingDown => "Shutting down",
                    };
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::from(Bytes::from(body)))
                        .unwrap())
                } else {
                    s.0.respond_next_rx.lock().await.recv().await.unwrap();
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::from(Bytes::from("Test Service")))
                        .unwrap())
                };

                let count = s.0.pending_count.fetch_sub(1, Ordering::SeqCst);
                s.0.pending_watch.send_replace(count - 1);

                result
            })
        }
    }
}
