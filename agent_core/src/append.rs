use std::time::{Duration, Instant};
use tracing::warn;

use super::hsm::Transport;
use agent_api::StepDownRequest;
use hsmcore::hsm::types::{DataHash, GroupId, LogEntry, LogIndex};
use hsmcore::merkle::agent::StoreDelta;
use juicebox_hsm::metrics::Tag;
use juicebox_hsm::metrics_tag as tag;
use juicebox_hsm::realm::store::bigtable;
use juicebox_sdk_core::types::RealmId;

use super::Agent;
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
    /// Precondition: agent is leader.
    pub(super) fn append(&self, realm: RealmId, group: GroupId, append_request: Append) {
        let appending = {
            let mut locked = self.0.state.lock().unwrap();
            let leader = locked.leader.get_mut(&(realm, group)).unwrap();
            let existing = leader
                .append_queue
                .insert(append_request.entry.index, append_request);
            assert!(existing.is_none());
            std::mem::replace(&mut leader.appending, Appending)
        };

        if let NotAppending { next } = appending {
            let agent = self.clone();

            tokio::spawn(async move { agent.keep_appending(realm, group, next).await });
        }
    }

    pub(super) const MAX_APPEND_BATCH_SIZE: usize = 100;

    /// Precondition: `leader.appending` is Appending because this task is the one
    /// doing the appending.
    async fn keep_appending(&self, realm: RealmId, group: GroupId, next: LogIndex) {
        let mut next = next;
        let mut batch = Vec::new();
        let metric_tags = [tag!(?realm), tag!(?group)];
        let mut queue_depth: usize;

        loop {
            let mut delta = StoreDelta::default();
            batch.clear();
            {
                let mut locked = self.0.state.lock().unwrap();
                let Some(leader) = locked.leader.get_mut(&(realm, group)) else {
                    return;
                };
                assert!(matches!(leader.appending, Appending));
                while let Some(request) = leader.append_queue.remove(&next) {
                    batch.push(request.entry);
                    if delta.is_empty() {
                        delta = request.delta;
                    } else {
                        delta.squash(request.delta);
                    }
                    next = next.next();
                    if batch.len() >= Self::MAX_APPEND_BATCH_SIZE {
                        break;
                    }
                }
                if batch.is_empty() {
                    leader.appending = NotAppending { next };
                    return;
                }
                queue_depth = leader.append_queue.len();
            }

            let start = Instant::now();
            match self.0.store.append(&realm, &group, &batch, delta).await {
                Err(bigtable::AppendError::LogPrecondition) => {
                    warn!(
                        name = self.0.name,
                        "detected dueling leaders, stepping down"
                    );
                    {
                        let mut locked = self.0.state.lock().unwrap();
                        // Empty the queue so we don't try and append anything else.
                        if let Some(leader) = locked.leader.get_mut(&(realm, group)) {
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

                Ok(()) => {
                    let batch_size = batch.len();
                    {
                        let mut locked = self.0.state.lock().unwrap();
                        if let Some(leader) = locked.leader.get_mut(&(realm, group)) {
                            leader.last_appended = batch.pop();
                        }
                    }
                    self.record_append_metrics(
                        start.elapsed(),
                        batch_size,
                        queue_depth,
                        &metric_tags,
                    );
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
            .histogram("bigtable.append.batch.size", batch_size, tags);

        self.0
            .metrics
            .histogram("bigtable.append.queue.size", queue_depth, tags);
    }
}
