use hyper::body::{Body, Incoming};
use hyper::rt::bounds::Http2ServerConnExec;
use hyper::server::conn::{http1, http2};
use hyper::service::HttpService;
use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, Instant, Sleep};
use tracing::{debug, info, warn};

use observability::metrics;

#[derive(Debug)]
pub struct ManagerOptions {
    // After this amount of time an idle connection will be close.
    pub idle_timeout: Duration,
    // The amount of time to spend signalling to health check that we're
    // shutting down before starting to close connections and drain any
    // remaining active requests.
    pub shutdown_notice_period: Duration,
}

impl Default for ManagerOptions {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(60),
            shutdown_notice_period: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServiceManager(Arc<ServiceManagerInner>);

#[derive(Debug)]
struct ServiceManagerInner {
    options: ManagerOptions,
    shutdown_scheduled: AtomicBool,
    connections_changed_tx: mpsc::Sender<ConnectionEvent>,
    connections_count_rx: watch::Receiver<usize>,
    start_draining_tx: watch::Sender<bool>,
}

impl ServiceManager {
    pub fn new(options: ManagerOptions, metrics: metrics::Client) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        let (conn_tx, mut conn_rx) = mpsc::channel(32);
        let (count_tx, count_rx) = watch::channel(0);

        tokio::spawn(async move {
            let mut count: usize = 0;
            while let Some(e) = conn_rx.recv().await {
                match e {
                    ConnectionEvent::Opened => count += 1,
                    ConnectionEvent::Closed => count -= 1,
                }
                count_tx.send_replace(count);
                debug!(?count, "active HTTP connections");
                metrics.gauge("load_balancer.connections.active", count, metrics::NO_TAGS);
            }
        });

        Self(Arc::new(ServiceManagerInner {
            shutdown_scheduled: AtomicBool::new(false),
            options,
            connections_changed_tx: conn_tx,
            connections_count_rx: count_rx,
            start_draining_tx: shutdown_tx,
        }))
    }

    // The returned receiver will receive a value When shutdown reaches the
    // stage where connections should be shutdown.
    pub fn subscribe_start_draining(&self) -> watch::Receiver<bool> {
        self.0.start_draining_tx.subscribe()
    }

    pub async fn health_check(&self) -> HealthCheckStatus {
        if self.0.shutdown_scheduled.load(Relaxed) {
            HealthCheckStatus::ShuttingDown
        } else {
            HealthCheckStatus::Ok
        }
    }

    // Returns a managed version of the supplied hyper connection.
    pub async fn manage<C: GracefulShutdown>(&self, conn: C) -> GracefulConnection<C> {
        self.0
            .connections_changed_tx
            .send(ConnectionEvent::Opened)
            .await
            .unwrap();
        GracefulConnection::new(
            conn,
            self.0.start_draining_tx.subscribe(),
            self.0.options.idle_timeout,
            self.0.connections_changed_tx.clone(),
        )
    }

    // Perform a graceful shutdown of the service. The service goes from live ->
    // notice_period -> draining -> stopped.
    //
    // During the notice period, the health check flags that the service is
    // going away, but otherwise everything proceeds as normal. CloudFlare will
    // notice the health check change and stop sending new traffic to this
    // instance. After the notice period has expired we trigger all the
    // connections to perform a graceful shutdown. Once all the connections have
    // drained the service is fully shutdown.
    pub async fn shut_down(&self) {
        self.shut_down_inner(sleep(self.0.options.shutdown_notice_period))
            .await;
    }

    // Broken out for testing.
    async fn shut_down_inner(&self, sleeper: impl Future<Output = ()>) {
        info!("starting service shutdown");
        self.0.shutdown_scheduled.store(true, Relaxed);
        sleeper.await;

        self.0.start_draining_tx.send_replace(true);
        info!("shutdown in progress, waiting for connections to close");

        let mut count = self.0.connections_count_rx.clone();
        if let Err(err) = count.wait_for(|count| *count == 0).await {
            warn!(?err, "Error waiting for connection count to reach 0");
        };
        info!("service shutdown complete");
    }
}

pub enum HealthCheckStatus {
    Ok,
    ShuttingDown,
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
        C: GracefulShutdown,
    {
        #[pin]
        conn: C,
        #[pin]
        idle_timer: Sleep,
        idle_timeout: Duration,
        start_draining_rx: watch::Receiver<bool>,
        finished: ConnFinishedGuard,
    }
}

struct ConnFinishedGuard {
    tx: Option<mpsc::Sender<ConnectionEvent>>,
}

impl Drop for ConnFinishedGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            tokio::spawn(async move {
                if let Err(err) = tx.send(ConnectionEvent::Closed).await {
                    warn!(?err, "failed to send connection closed event");
                }
            });
        }
    }
}

impl<C: GracefulShutdown> GracefulConnection<C> {
    fn new(
        conn: C,
        shutdown_rx: watch::Receiver<bool>,
        idle_timeout: Duration,
        finished_tx: mpsc::Sender<ConnectionEvent>,
    ) -> Self {
        Self {
            conn,
            idle_timer: sleep(idle_timeout),
            idle_timeout,
            start_draining_rx: shutdown_rx,
            finished: ConnFinishedGuard {
                tx: Some(finished_tx),
            },
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
            this.idle_timer.as_mut().poll(cx).is_ready() || *this.start_draining_rx.borrow();
        if shutdown {
            this.conn.as_mut().start_graceful_shutdown();
        } else {
            this.idle_timer
                .as_mut()
                .reset(Instant::now() + *this.idle_timeout);
        }
        this.conn.poll(cx)
    }
}

// As hyper http1 & http2 connection objects are different, this trait allows us
// to abstract away the fact that they're different.
pub trait GracefulShutdown {
    fn start_graceful_shutdown(self: Pin<&mut Self>);
}

impl<IO, SVC, B> GracefulShutdown for http1::Connection<IO, SVC>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
    B: Body + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    SVC: HttpService<Incoming, ResBody = B>,
{
    fn start_graceful_shutdown(self: Pin<&mut Self>) {
        self.graceful_shutdown();
    }
}

impl<IO, SVC, B, EXEC> GracefulShutdown for http2::Connection<IO, SVC, EXEC>
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
    B: Body + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    SVC: HttpService<Incoming, ResBody = B>,
    EXEC: Http2ServerConnExec<SVC::Future, B>,
{
    fn start_graceful_shutdown(self: Pin<&mut Self>) {
        self.graceful_shutdown();
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures::{select_biased, FutureExt};
    use http_body_util::Full;
    use hyper::service::Service;
    use hyper::StatusCode;
    use hyper::{body::Incoming, Request, Response};
    use hyper_util::rt::TokioIo;
    use std::error::Error;
    use std::net::Ipv4Addr;
    use std::pin::pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio::sync::{broadcast, oneshot, Mutex};
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
        // Use a oneshot channel as a test shutting down timer.
        let (tx, rx) = oneshot::channel();
        let (at_sleep_tx, at_sleep_rx) = oneshot::channel();
        let shutdown_handle = tokio::spawn(async move {
            server2
                .0
                .server
                .mgr
                .shut_down_inner(async {
                    at_sleep_tx.send(()).unwrap();
                    rx.await.unwrap()
                })
                .await;
        });
        // wait for the spawned shutdown to get to the point where its flagged we're shutting down.
        at_sleep_rx.await.unwrap();

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

        // The shutting down timer expires, shutdown should progress to closing
        // idle connections and draining pending requests.
        tx.send(()).unwrap();
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
            let mgr = ServiceManager::new(
                ManagerOptions {
                    idle_timeout: Duration::from_secs(5),
                    shutdown_notice_period: Duration::from_secs(1),
                },
                metrics::Client::new("test_service", None),
            );
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
            let mgr = service.0.server.mgr.clone();
            let mut shutdown_rx = mgr.subscribe_start_draining();
            let service2 = service.clone();
            tokio::spawn(async move {
                let mut shutdown_f = pin!(shutdown_rx.changed().fuse());
                loop {
                    let (stream, _) = select_biased! {
                        _ = shutdown_f => { return; }
                        result = listener.accept().fuse() => result.unwrap(),
                    };
                    let io = TokioIo::new(stream);
                    let service = service.clone();
                    let conn_mgr = mgr.clone();
                    tokio::spawn(async move {
                        let c = http1::Builder::new().serve_connection(io, service);
                        let c = conn_mgr.manage(c).await;
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

        fn call(&self, request: Request<Incoming>) -> Self::Future {
            let s = self.clone();
            Box::pin(async move {
                let count = s.0.pending_count.fetch_add(1, Ordering::Relaxed);
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

                let count = s.0.pending_count.fetch_sub(1, Ordering::Relaxed);
                s.0.pending_watch.send_replace(count - 1);

                result
            })
        }
    }
}
