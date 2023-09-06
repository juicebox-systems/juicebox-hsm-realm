use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{trace, warn};

use hsm_api::RecordId;
use juicebox_realm_api::types::RealmId;
use observability::metrics;
use store::tenants::{UserAccounting, UserAccountingEvent};
use store::StoreClient;

#[derive(Debug)]
pub struct UserAccountingManager {
    tx: mpsc::Sender<(RealmId, UserAccounting)>,
}

const MAX_BATCH_SIZE: usize = 200;

impl UserAccountingManager {
    pub fn new(store: StoreClient, metrics: metrics::Client) -> Self {
        let (tx, mut rx) = mpsc::channel(256);
        tokio::spawn(async move {
            loop {
                let mut records: HashMap<RealmId, Vec<UserAccounting>> = HashMap::new();
                let (realm, next) = rx.recv().await.unwrap();
                records.entry(realm).or_default().push(next);
                let mut count = 1;
                while let Ok((realm, next)) = rx.try_recv() {
                    records.entry(realm).or_default().push(next);
                    count += 1;
                    if count >= MAX_BATCH_SIZE {
                        break;
                    }
                }
                metrics.gauge("agent.accounting.batch_size", count, metrics::NO_TAGS);

                for (realm, mut events) in records {
                    events.sort_by_key(|e| e.when);
                    for retries in 0..3 {
                        trace!(len = events.len(), ?realm, "writing user accounting batch");
                        match metrics
                            .async_time("agent.accounting.write_time", metrics::NO_TAGS, || {
                                store.write_user_accounting(&realm, &events)
                            })
                            .await
                        {
                            Ok(_) => break,
                            Err(err) => {
                                warn!(
                                    ?err,
                                    ?retries,
                                    "error writing to tenant user table in bigtable"
                                );
                                sleep(Duration::from_millis(25)).await;
                            }
                        }
                    }
                }
            }
        });
        UserAccountingManager { tx }
    }

    pub async fn secret_registered(&self, realm: RealmId, tenant: String, id: RecordId) {
        self.tx
            .send((
                realm,
                UserAccounting {
                    tenant,
                    id,
                    when: SystemTime::now(),
                    event: UserAccountingEvent::SecretRegistered,
                },
            ))
            .await
            .unwrap();
    }

    pub async fn secret_deleted(&self, realm: RealmId, tenant: String, id: RecordId) {
        self.tx
            .send((
                realm,
                UserAccounting {
                    tenant,
                    id,
                    when: SystemTime::now(),
                    event: UserAccountingEvent::SecretDeleted,
                },
            ))
            .await
            .unwrap();
    }
}
