use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use async_util::ScopedTask;
use juicebox_networking::reqwest;
use juicebox_sdk::{AuthToken, Client, Policy, RealmId, TokioSleeper};

pub type JbClient = Client<TokioSleeper, reqwest::Client, HashMap<RealmId, AuthToken>>;

pub struct BackgroundClientRequests {
    req_tx: Sender<WorkerReq>,
    res_rx: Receiver<WorkerResults>,
    #[allow(unused)] // task is used for its Drop impl to stop the background task.
    task: ScopedTask<()>,
}

impl BackgroundClientRequests {
    pub async fn spawn(client: JbClient) -> Self {
        let (tx, mut rx) = channel(1);
        let (res_tx, res_rx) = channel(1);

        let task = ScopedTask::spawn(async move {
            let mut success_count = 0;
            let mut failures = Vec::new();
            loop {
                match client
                    .register(
                        &vec![1, 2, 3, 4].into(),
                        &b"bob".to_vec().into(),
                        &b"info".to_vec().into(),
                        Policy { num_guesses: 3 },
                    )
                    .await
                {
                    Ok(_) => success_count += 1,
                    Err(e) => failures.push(format!("{e:?}")),
                }

                match client
                    .recover(&vec![1, 2, 3, 4].into(), &b"info".to_vec().into())
                    .await
                {
                    Ok(secret) if secret.expose_secret() == b"bob".to_vec() => success_count += 1,
                    Ok(secret) => failures.push(format!(
                        "expected {:?} got {:?}",
                        b"bob".to_vec(),
                        secret.expose_secret()
                    )),
                    Err(e) => failures.push(format!("{e:?}")),
                }

                match rx.try_recv() {
                    Ok(WorkerReq::Report) => {
                        res_tx
                            .send(WorkerResults {
                                successes: success_count,
                                errors: failures.split_off(0),
                            })
                            .await
                            .unwrap();
                        success_count = 0;
                    }
                    Ok(WorkerReq::Shutdown) => {
                        res_tx
                            .send(WorkerResults {
                                successes: success_count,
                                errors: failures.split_off(0),
                            })
                            .await
                            .unwrap();
                        return;
                    }
                    Err(_) => {
                        // Nothing to read from rx. Keep making more requests.
                    }
                }
            }
        });
        BackgroundClientRequests {
            req_tx: tx,
            res_rx,
            task,
        }
    }

    // Returns the amount of work done since the prior progress request.
    pub async fn progress(&mut self, w: WorkerReq) -> WorkerResults {
        self.req_tx.send(w).await.unwrap();
        self.res_rx.recv().await.unwrap()
    }

    pub async fn wait_for_progress(
        &mut self,
        num_successes: usize,
        timeout: Duration,
    ) -> WorkerResults {
        assert!(num_successes > 0);
        tokio::time::timeout(timeout, async {
            // ensure the background process count is reset.
            self.progress(WorkerReq::Report).await;
            let mut res = WorkerResults::default();
            loop {
                res += self.progress(WorkerReq::Report).await;
                assert!(res.errors.is_empty());
                if res.successes >= num_successes {
                    return res;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }
}

pub enum WorkerReq {
    Report,
    Shutdown,
}

#[derive(Default)]
pub struct WorkerResults {
    pub successes: usize,
    pub errors: Vec<String>,
}

impl std::ops::AddAssign for WorkerResults {
    fn add_assign(&mut self, rhs: Self) {
        self.successes += rhs.successes;
        self.errors.extend(rhs.errors);
    }
}
