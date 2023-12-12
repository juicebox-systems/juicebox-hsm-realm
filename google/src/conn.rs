use std::cmp::min;
use std::future::Future;
use std::time::Duration;
use tokio::sync::watch::{channel, Receiver};
use tonic::body::BoxBody;
use tower_service::Service;
use tracing::{info, warn};

pub struct MaxConnectionLifetime<C> {
    current: C,
    next: Receiver<C>,
}

impl<C: Clone> Clone for MaxConnectionLifetime<C> {
    fn clone(&self) -> Self {
        // In typical usage with Tonic a channel middleware is created, and then
        // cloned for each gRPC call. Once used the clone is thrown away. This
        // clone impl ensures that any new connection flows into the clones.
        // Without this the clone gets updated to the new connection when
        // executed, but the original middleware that gets cloned again does not
        // and everything stays on the original connection.
        Self {
            current: self.next.borrow().clone(),
            next: self.next.clone(),
        }
    }
}

impl<C: Service<http::Request<BoxBody>> + Send + Sync + Clone + 'static> MaxConnectionLifetime<C> {
    pub async fn new<E, F, Fut>(max_age: Duration, conn_factory: F) -> Result<Self, E>
    where
        F: Fn() -> Fut + Send + 'static,
        Fut: Future<Output = Result<C, E>> + Send,
        E: std::error::Error,
    {
        const INIT_BACKOFF: Duration = Duration::from_secs(1);

        let init_conn = conn_factory().await?;
        let (tx_conn, rx_conn) = channel(init_conn.clone());
        tokio::spawn(async move {
            tokio::time::sleep(max_age).await;
            let mut backoff = INIT_BACKOFF;
            let mut next_sleep: Duration;
            loop {
                let future_conn = conn_factory();
                (next_sleep, backoff) = match future_conn.await {
                    Ok(new_conn) => {
                        info!("got new connection from factory");
                        match tx_conn.send(new_conn) {
                            Ok(_) => {
                                info!("sent new connection to receivers");
                                (max_age, INIT_BACKOFF)
                            }
                            Err(_err) => {
                                // All receivers have been dropped, which'll happen if the
                                // MaxConnectionLifetime has been dropped. In which case
                                // there's nothing left to do.
                                return;
                            }
                        }
                    }
                    Err(err) => {
                        warn!(%err, "failed to create new connection, will retry");
                        (backoff, min(backoff * 2, Duration::from_secs(30)))
                    }
                };
                tokio::time::sleep(next_sleep).await;
            }
        });
        Ok(Self {
            current: init_conn,
            next: rx_conn,
        })
    }
}

impl<C: Service<http::Request<BoxBody>> + Clone + Send + Sync + 'static>
    Service<http::Request<BoxBody>> for MaxConnectionLifetime<C>
{
    type Response = C::Response;
    type Error = C::Error;
    type Future = C::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.current.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<BoxBody>) -> Self::Future {
        // Based on https://github.com/hyperium/tonic/blob/master/examples/src/tower/client.rs:
        //
        // See https://github.com/tower-rs/tower/issues/547#issuecomment-767629149
        // for details on swapping channel out of self.

        let clone = { self.next.borrow().clone() };
        let mut channel = std::mem::replace(&mut self.current, clone);
        channel.call(request)
    }
}

#[cfg(test)]
mod tests {
    use std::future::{ready, Ready};
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::time::Duration;
    use thiserror::Error;
    use tokio::time::sleep;
    use tonic::body::BoxBody;
    use tower_service::Service;

    use super::MaxConnectionLifetime;

    #[tokio::test]
    async fn test_new_conn() {
        let count = AtomicU8::new(1);

        let c = MaxConnectionLifetime::new(Duration::from_secs(3000), move || {
            let c = count.fetch_add(1, Ordering::Relaxed);
            async move {
                let r: Result<TestCh, TestChError> = Ok(TestCh { payload: vec![c] });
                r
            }
        })
        .await
        .unwrap();

        async fn make_req(mut cc: MaxConnectionLifetime<TestCh>) -> Result<Vec<u8>, TestChError> {
            let req = http::Request::new(BoxBody::default());
            cc.call(req).await
        }

        assert_eq!(Ok(vec![1]), make_req(c.clone()).await);
        assert_eq!(Ok(vec![1]), make_req(c.clone()).await);

        tokio::time::pause();
        sleep(Duration::from_secs(3001)).await;

        assert_eq!(Ok(vec![2]), make_req(c.clone()).await);
        assert_eq!(Ok(vec![2]), make_req(c.clone()).await);
        assert_eq!(Ok(vec![2]), make_req(c.clone()).await);

        sleep(Duration::from_secs(3001)).await;

        assert_eq!(Ok(vec![3]), make_req(c.clone()).await);
        assert_eq!(Ok(vec![3]), make_req(c.clone()).await);
        assert_eq!(Ok(vec![3]), make_req(c.clone()).await);
    }

    #[derive(Clone)]
    struct TestCh {
        payload: Vec<u8>,
    }

    impl Service<http::Request<BoxBody>> for TestCh {
        type Response = Vec<u8>;
        type Error = TestChError;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: http::Request<BoxBody>) -> Self::Future {
            ready(Ok(self.payload.clone()))
        }
    }

    #[derive(Debug, Error, Eq, PartialEq)]
    #[error("boom")]
    struct TestChError;
}
