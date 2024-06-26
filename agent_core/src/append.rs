use std::time::{Duration, Instant};
use tracing::warn;

use super::commit::UncompactedRowsStats;
use super::hsm::Transport;
use super::with_lock;
use super::{group_state_mut, Agent};
use agent_api::StepDownRequest;
use hsm_api::merkle::StoreDelta;
use hsm_api::{DataHash, GroupId, LogEntry, LogIndex};
use juicebox_realm_api::types::RealmId;
use observability::metrics::Tag;
use observability::metrics_tag as tag;
use AppendingState::*;

#[derive(Debug)]
pub(super) struct Append {
    pub entry: LogEntry,
    pub delta: StoreDelta<DataHash>,
}

#[derive(Debug)]
pub(super) enum AppendingState {
    NotAppending { next: LogIndex },
    Appending,
}

impl<T: Transport + 'static> Agent<T> {
    pub(super) fn append(&self, realm: RealmId, group: GroupId, append_request: Append) {
        if let Some(NotAppending { next }) = with_lock!(&self.0.state, |locked| {
            match group_state_mut(&mut locked.groups, realm, group)
                .leader
                .as_mut()
            {
                None => None,
                Some(leader) => {
                    let existing = leader
                        .append_queue
                        .insert(append_request.entry.index, append_request);
                    assert!(existing.is_none());
                    Some(std::mem::replace(&mut leader.appending, Appending))
                }
            }
        }) {
            let agent = self.clone();
            tokio::spawn(async move { agent.keep_appending(realm, group, next).await });
        }
    }

    pub(super) const MAX_APPEND_BATCH_SIZE: usize = 100;

    /// Precondition: `leader.appending` is Appending because this task is the one
    /// doing the appending.
    async fn keep_appending(&self, realm: RealmId, group: GroupId, next: LogIndex) {
        let mut next = next;
        let mut log_batch = Vec::new();
        let mut delta_batch = Vec::new();
        let metric_tags = [tag!(?realm), tag!(?group)];
        let mut queue_depth: usize = 0;

        loop {
            log_batch.clear();
            delta_batch.clear();
            with_lock!(&self.0.state, |locked| {
                let Some(leader) = group_state_mut(&mut locked.groups, realm, group)
                    .leader
                    .as_mut()
                else {
                    return;
                };
                assert!(matches!(leader.appending, Appending));
                while let Some(request) = leader.append_queue.remove(&next) {
                    log_batch.push(request.entry);
                    delta_batch.push(request.delta);
                    next = next.next();
                    if log_batch.len() >= Self::MAX_APPEND_BATCH_SIZE {
                        break;
                    }
                }
                if log_batch.is_empty() {
                    leader.appending = NotAppending { next };
                    return;
                }
                queue_depth = leader.append_queue.len();
            });
            if log_batch.is_empty() {
                return;
            }
            let mut delta = StoreDelta::default();
            for d in delta_batch.drain(..) {
                delta.squash(d);
            }
            let start = Instant::now();
            match self.0.store.append(&realm, &group, &log_batch, delta).await {
                Err(store::AppendError::LogPrecondition) => {
                    warn!(
                        name = self.0.name,
                        "detected dueling leaders, stepping down"
                    );
                    {
                        let mut locked = self.0.state.lock().unwrap();

                        // Empty the queue so we don't try and append anything else.
                        if let Some(leader) = group_state_mut(&mut locked.groups, realm, group)
                            .leader
                            .as_mut()
                        {
                            leader.append_queue.clear();
                            leader.appending = NotAppending {
                                next: LogIndex(u64::MAX),
                            };
                        }
                    }
                    self.handle_stepdown_as_leader(StepDownRequest { realm, group })
                        .await
                        .expect("error during leader stepdown");
                    return;
                }

                Err(err) => todo!("{err:?}"),

                Ok(row) => {
                    let elapsed = start.elapsed();
                    let batch_size = log_batch.len();
                    let stats = with_lock!(&self.0.state, |locked| {
                        if let Some(leader) = group_state_mut(&mut locked.groups, realm, group)
                            .leader
                            .as_mut()
                        {
                            leader.uncompacted_rows.push_back(row);
                            leader.last_appended = log_batch.pop();
                            Some(UncompactedRowsStats::new(leader))
                        } else {
                            None
                        }
                    });
                    if let Some(stats) = stats {
                        stats.publish(&self.0.metrics, &metric_tags);
                    }
                    self.record_append_metrics(elapsed, batch_size, queue_depth, &metric_tags);
                }
            }
        }
    }

    fn record_append_metrics(
        &self,
        elapsed: Duration,
        batch_size: usize,
        queue_depth: usize,
        tags: &[Tag],
    ) {
        self.0.metrics.timing("bigtable.append.time", elapsed, tags);

        self.0
            .metrics
            .distribution("bigtable.append.batch.size", batch_size, tags);

        self.0
            .metrics
            .distribution("bigtable.append.queue.size", queue_depth, tags);
    }
}
