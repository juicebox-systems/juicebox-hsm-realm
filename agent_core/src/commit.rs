use futures::stream::FuturesUnordered;
use futures::{Stream, StreamExt};
use std::collections::{HashMap, VecDeque};
use std::mem;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{info, instrument, span, trace, warn, Instrument, Level, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use super::hsm::Transport;
use super::peers::DiscoveryWatcher;
use super::{group_state, group_state_mut, Agent, LeaderState};
use agent_api::{ReadCapturedRequest, ReadCapturedResponse};
use async_util::ScopedTask;
use cluster_core::hsm_ids;
use election::HsmElection;
use hsm_api::{
    AppResultType, Captured, CommitRequest, CommitResponse, EntryMac, GroupId, GroupMemberRole,
    HsmId, LogIndex, PersistStateRequest, PersistStateResponse,
};
use jburl::Url;
use juicebox_networking::rpc::{self, SendOptions};
use juicebox_realm_api::requests::NoiseResponse;
use juicebox_realm_api::types::RealmId;
use observability::logging::TracingSource;
use observability::metrics::{self, Tag};
use observability::metrics_tag as tag;
use service_core::http::ReqwestClientMetrics;
use store::log::LogRow;
use store::ServiceKind;

/// Returned by [`Agent::commit_maybe`] and its helper [`Agent::do_commit`].
#[derive(Debug, Eq, PartialEq)]
enum CommitResult {
    /// The HSM returned its current commit index.
    ///
    /// Note that the log index may be the same as one previously committed,
    /// which should be handled the same as `NoChange`.
    Committed(LogIndex),
    NoChange,
    NoLongerLeader,
}

impl<T: Transport + 'static> Agent<T> {
    pub(super) fn start_nvram_writer(&self) {
        trace!(agent = self.0.name, "starting nvram writer task");
        let agent = self.clone();

        tokio::spawn(async move {
            const WRITE_INTERVAL_MILLIS: u64 = 100;
            let cx = opentelemetry::Context::new().with_value(TracingSource::BackgroundJob);

            loop {
                sleep(how_long_to_wait(SystemTime::now(), WRITE_INTERVAL_MILLIS)).await;
                let span = span!(Level::TRACE, "nvram_writer_loop");
                span.set_parent(cx.clone());

                match agent
                    .0
                    .hsm
                    .send(PersistStateRequest {})
                    .instrument(span)
                    .await
                {
                    Err(err) => {
                        warn!(?err, "failed to request HSM to write to NVRAM");
                    }
                    Ok(PersistStateResponse::Ok { captured, .. }) => {
                        agent.0.state.lock().unwrap().captures = captured
                    }
                };
            }
        });
    }

    /// Main function for leader commit task.
    pub(super) async fn group_committer(
        self,
        realm: RealmId,
        group: GroupId,
        config: Vec<HsmId>,
        starting_index: LogIndex,
    ) {
        let tags = [tag!(?realm), tag!(?group)];
        let agent_discovery = AgentDiscoveryCache::new(
            &self.0.discovery,
            self.0.peer_client.clone(),
            Duration::from_secs(10),
        )
        .await;
        // Spawn the log compactor task. The channel tracks the latest compact
        // index (see `get_compact_index`). The ScopedTask's Drop impl aborts
        // the task when the committer task exits.
        let (compaction_tx, compaction_rx) = watch::channel(None);
        let _compaction_task = ScopedTask::spawn(self.clone().compactor(
            realm,
            group,
            compaction_rx,
            starting_index,
            config.clone(),
            agent_discovery.clone(),
        ));

        let cx = opentelemetry::Context::new().with_value(TracingSource::BackgroundJob);

        loop {
            let span = span!(Level::TRACE, "committer_loop");
            span.set_parent(cx.clone());

            match self
                .commit_maybe(realm, group, &config, &agent_discovery)
                .instrument(span)
                .await
            {
                CommitResult::NoLongerLeader => {
                    info!(name=?self.0.name, ?realm, ?group, "No longer leader, stopping committer");
                    return;
                }
                CommitResult::NoChange | CommitResult::Committed(_) => { /* fall through */ }
            };

            // Notify the compaction task of updates.
            //
            // When PersistState updates the captured info, `compaction_tx`
            // won't be notified until this loop gets back here. This loops
            // frequently so that's OK for now.
            let compact_index = self.get_compact_index(realm, group);
            let modified = compaction_tx.send_if_modified(|state| {
                if *state == compact_index {
                    false
                } else {
                    *state = compact_index;
                    true
                }
            });
            if modified {
                self.0.metrics.gauge(
                    "agent.compaction.compact_index",
                    match compact_index {
                        Some(compact_index) => compact_index.0,
                        None => 0,
                    },
                    &tags,
                );
            }

            sleep(Duration::from_millis(2)).await;
        }
    }

    #[instrument(level = "trace", skip(self, config, peers), fields(quorum))]
    async fn commit_maybe(
        &self,
        realm: RealmId,
        group: GroupId,
        config: &[HsmId],
        peers: &AgentDiscoveryCache,
    ) -> CommitResult {
        // Verify we're acting as leader and get the last commit index.
        let last_committed = {
            let locked = self.0.state.lock().unwrap();
            let group = group_state(&locked.groups, realm, group);
            match &group.leader {
                Some(leader) => leader.committed,
                None => return CommitResult::NoLongerLeader,
            }
        };

        // See if we can move the commit index forward.
        let mut captures = Vec::with_capacity(config.len());
        let mut captures_stream = pin!(self.get_captures(realm, group, config, peers).await);

        // Calculate a commit index.
        let mut election = HsmElection::new(config);
        while let Some(c) = captures_stream.next().await {
            election.vote(c.hsm, c.index);
            captures.push(c);
            if let Ok(idx) = election.outcome() {
                if Some(idx) > last_committed {
                    // We can move the commit index forward. Wait a small amount
                    // of time for any additional votes, as they may improve how
                    // far forward we can go.
                    let _ = tokio::time::timeout(Duration::from_millis(10), async {
                        while let Some(c) = captures_stream.next().await {
                            election.vote(c.hsm, c.index);
                            captures.push(c);
                        }
                    })
                    .await;
                    break;
                }
            }
        }

        let commit_index: Option<LogIndex> = election.outcome().ok();
        if commit_index <= last_committed {
            return CommitResult::NoChange;
        }
        // `commit_index` must be `Some` to be greater than `last_committed`.
        Span::current().record("quorum", commit_index.unwrap().0);

        // Request the HSM to commit. This will update the leader's committed
        // state before returning.
        self.do_commit(CommitRequest {
            realm,
            group,
            captures,
        })
        .await
    }

    /// Issues [`ReadCapturedRequest`] to a set of agents, and returns only the
    /// successful results.
    #[instrument(level = "trace", skip(self, hsms, peers))]
    async fn get_captures(
        &self,
        realm: RealmId,
        group: GroupId,
        hsms: &[HsmId],
        peers: &AgentDiscoveryCache,
    ) -> impl Stream<Item = Captured> + '_ {
        let f: FuturesUnordered<_> = hsms
            .iter()
            .filter_map(|hsm| peers.url(hsm))
            .map(move |url| async move {
                rpc::send_with_options(
                    &self.0.peer_client,
                    &url,
                    ReadCapturedRequest { realm, group },
                    SendOptions::default().with_timeout(Duration::from_millis(500)),
                )
                .await
            })
            .collect();

        f.filter_map(|r| async { r.ok() }).filter_map(|r| async {
            match r {
                ReadCapturedResponse::Ok(captured) => captured,
            }
        })
    }

    // Ask the HSM to do the commit.
    #[instrument(level = "trace", skip(self, request), fields(released_count))]
    async fn do_commit(&self, request: CommitRequest) -> CommitResult {
        let realm = request.realm;
        let group = request.group;
        let response = self.0.hsm.send(request).await;
        let commit_state = match response {
            Ok(CommitResponse::Ok(state)) => {
                trace!(
                    agent = self.0.name,
                    committed=?state.committed,
                    num_responses=?state.responses.len(),
                    "HSM committed entry"
                );
                self.0.metrics.gauge(
                    "agent.commit.log.index",
                    state.committed.0,
                    [tag!(?realm), tag!(?group)],
                );
                state
            }
            Ok(CommitResponse::NotLeader(role)) => {
                info!(agent = self.0.name, ?realm, ?group, "Leader stepped down");
                self.maybe_role_changed(realm, group, role);
                return CommitResult::NoLongerLeader;
            }
            _ => {
                warn!(agent = self.0.name, ?response, "commit response not ok");
                return CommitResult::NoChange;
            }
        };

        let committed = commit_state.committed;
        let released_count = self.release_client_responses(
            realm,
            group,
            commit_state.responses,
            commit_state.abandoned,
        );
        Span::current().record("released_count", released_count);

        self.maybe_role_changed(realm, group, commit_state.role);

        let mut locked = self.0.state.lock().unwrap();
        if let Some(leader) = group_state_mut(&mut locked.groups, realm, group)
            .leader
            .as_mut()
        {
            if leader.committed < Some(committed) {
                leader.committed = Some(committed);
                CommitResult::Committed(committed)
            } else {
                CommitResult::NoChange
            }
        } else {
            CommitResult::NoLongerLeader
        }
    }

    // Returns the number of released responses.
    fn release_client_responses(
        &self,
        realm: RealmId,
        group: GroupId,
        responses: Vec<(EntryMac, NoiseResponse, AppResultType)>,
        abandoned: Vec<EntryMac>,
    ) -> usize {
        let mut released_count = 0;
        let mut locked = self.0.state.lock().unwrap();
        if let Some(leader) = group_state_mut(&mut locked.groups, realm, group)
            .leader
            .as_mut()
        {
            for (mac, client_response, event) in responses {
                if let Some(sender) = leader.response_channels.remove(&mac.into()) {
                    if sender.send((client_response, event)).is_err() {
                        warn!("dropping response on the floor: client no longer waiting");
                    }
                    released_count += 1;
                } else {
                    warn!("dropping response on the floor: client never waiting");
                }
            }
            for mac in abandoned {
                if let Some(sender) = leader.response_channels.remove(&mac.into()) {
                    // This closes the sender without having sent, which'll have
                    // the waiter get an error and report NotLeader to the
                    // load balancer.
                    drop(sender);
                }
            }
        } else if !responses.is_empty() {
            warn!("dropping responses on the floor: no leader state");
        }
        released_count
    }

    /// Calculates the current compaction index based on cached state.
    ///
    /// The compaction task may compact up through the compact index, defined
    /// as the lower of: the index preceding the commit index, or the leader
    /// HSM's captured index. The first constraint keeps the critically useful
    /// entries in the log, and the second prevents the leader HSM from needing
    /// a CaptureJump RPC due to its own compactions.
    fn get_compact_index(&self, realm: RealmId, group: GroupId) -> Option<LogIndex> {
        let locked = self.0.state.lock().unwrap();
        let last_committed: LogIndex = locked
            .groups
            .get(&(realm, group))?
            .leader
            .as_ref()?
            .committed?;
        let local_captured: LogIndex = locked
            .captures
            .iter()
            .find(|captured| captured.realm == realm && captured.group == group)?
            .index;
        Some(LogIndex::min(last_committed.prev()?, local_captured))
    }

    /// Main function for the leader's log compaction task.
    async fn compactor(
        self,
        realm: RealmId,
        group: GroupId,
        mut compaction_rx: watch::Receiver<Option<LogIndex>>,
        leader_start_index: LogIndex,
        config: Vec<HsmId>,
        agent_discovery: AgentDiscoveryCache,
    ) {
        let cx = opentelemetry::Context::new().with_value(TracingSource::BackgroundJob);

        {
            let span = span!(Level::TRACE, "compact_init");
            span.set_parent(cx.clone());
            self.compact_init(
                &realm,
                &group,
                leader_start_index,
                &config,
                &agent_discovery,
            )
            .instrument(span)
            .await;
        }

        // When the compaction index advances, replace more log entry rows with
        // tombstones.
        let mut last_compacted: Option<LogIndex> = None;
        loop {
            let compact_index = match compaction_rx.wait_for(|c| c > &last_compacted).await {
                Ok(c) => c.unwrap(),
                Err(_) => return, // no longer leader
            };

            let span = span!(Level::TRACE, "compact_once");
            span.set_parent(cx.clone());
            self.compact_once(realm, group, compact_index)
                .instrument(span)
                .await;

            last_compacted = Some(compact_index);
        }
    }

    /// Sets up to begin log compaction.
    #[instrument(level = "trace", skip(self, agent_discovery))]
    async fn compact_init(
        &self,
        realm: &RealmId,
        group: &GroupId,
        leader_start_index: LogIndex,
        config: &[HsmId],
        agent_discovery: &AgentDiscoveryCache,
    ) {
        // Give the prior leader(s) a chance to step down, before we start
        // overwriting log entries they might need in order to release
        // responses to clients.
        let start = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(60), async {
            while !self
                .all_peers_witnesses(realm, group, config, agent_discovery)
                .await
            {
                // Wait to discover peers in service discovery or for peers to
                // step down.
                sleep(Duration::from_millis(500)).await;
            }
        })
        .await;
        info!(
            ?realm,
            ?group,
            elapsed = ?start.elapsed(),
            reason = match result {
                Err(_) => "timed out confirming all peers are witnesses",
                Ok(()) => "confirmed all peers are witnesses",
            },
            "starting log compaction"
        );

        // Read existing rows from the store to learn what entries were written
        // by previous leaders. This will stop before any entries written by
        // this current leader.
        let start = Instant::now();
        let mut rows_read = VecDeque::from(
            self.0
                .store
                .list_log_rows(realm, group, leader_start_index)
                .await
                .expect("failed to read log rows to compact"),
        );
        info!(
            ?realm,
            ?group,
            count = rows_read.len(),
            lowest = ?rows_read.front().map(|row| row.index),
            highest = ?rows_read.back().map(|row| row.index),
            elapsed = ?start.elapsed(),
            "log compactor finished reading existing log rows"
        );

        // Concatenate the rows read (`< leader_start_index`) with any rows the
        // leader already appended (`>= leader_start_index`).
        let stats = {
            let mut locked = self.0.state.lock().unwrap();
            let Some(leader) = group_state_mut(&mut locked.groups, *realm, *group)
                .leader
                .as_mut()
            else {
                return; // no longer leader
            };
            if let Some(row) = rows_read.back() {
                assert!(row.index < leader_start_index);
            }
            if let Some(row) = leader.uncompacted_rows.front() {
                assert_eq!(row.index, leader_start_index);
            }
            rows_read.append(&mut leader.uncompacted_rows);
            leader.uncompacted_rows = rows_read;
            UncompactedRowsStats::new(leader)
        };
        stats.publish(&self.0.metrics, &[tag!(?realm), tag!(?group)]);
    }

    /// Compacts the log a single time.
    #[instrument(level = "trace", skip(self), fields(rows))]
    async fn compact_once(&self, realm: RealmId, group: GroupId, compact_index: LogIndex) {
        let (to_compact, stats): (Vec<LogRow>, UncompactedRowsStats) = {
            let mut locked = self.0.state.lock().unwrap();
            let Some(leader) = group_state_mut(&mut locked.groups, realm, group)
                .leader
                .as_mut()
            else {
                return; // no longer leader
            };
            (
                split_off_compactible_prefix(&mut leader.uncompacted_rows, compact_index),
                UncompactedRowsStats::new(leader),
            )
        };

        stats.publish(&self.0.metrics, &[tag!(?realm), tag!(group)]);
        Span::current().record("rows", to_compact.len());

        if !to_compact.is_empty() {
            self.0
                .store
                .replace_oldest_rows_with_tombstones(&realm, &group, &to_compact)
                .await
                .expect("failed to compact log rows");
        }
    }

    /// Returns true if all the other HSMs in the group (excluding the local
    /// one) are in the witness role, and false if they couldn't be reached or
    /// aren't witnesses.
    async fn all_peers_witnesses(
        &self,
        realm: &RealmId,
        group: &GroupId,
        config: &[HsmId],
        agent_discovery: &AgentDiscoveryCache,
    ) -> bool {
        let local_hsm_id = self
            .0
            .state
            .lock()
            .unwrap()
            .hsm_id
            .expect("local HSM always known for leaders");
        assert!(config.contains(&local_hsm_id));

        let urls: Vec<Url> = config
            .iter()
            .filter(|id| **id != local_hsm_id)
            .filter_map(|id| agent_discovery.url(id))
            .collect();

        if urls.len() + 1 < config.len() {
            return false;
        }

        let witnesses = cluster_core::get_hsm_statuses(
            &self.0.peer_client,
            urls.iter(),
            Some(Duration::from_secs(2)),
        )
        .await
        .into_values()
        .filter(|(sr, _)| {
            sr.realm.as_ref().is_some_and(|rs| {
                rs.id == *realm
                    && rs
                        .groups
                        .iter()
                        .any(|gs| gs.id == *group && gs.role.role == GroupMemberRole::Witness)
            })
        })
        .count();

        witnesses + 1 == config.len()
    }
}

/// Removes the rows that should be replaced with tombstones from the front of
/// `rows` and returns those.
fn split_off_compactible_prefix(
    rows: &mut VecDeque<LogRow>,
    compact_index: LogIndex,
) -> Vec<LogRow> {
    // Multiple log entries are written in each row, and we only track the row
    // start indexes. Any entries after `compact_index` in the same row must
    // not be compacted, so only compact that row if the next row starts with
    // `compact_index + 1`. See the unit tests for examples.
    //
    // `past` is the offset of the first row with `index > compact_index`.
    let past = rows.partition_point(|row| row.index <= compact_index);
    if past == 0 {
        return Vec::new();
    }
    let keep = if past < rows.len() && rows[past].index == compact_index.next() {
        rows.split_off(past)
    } else {
        rows.split_off(past - 1)
    };
    Vec::from(mem::replace(rows, keep))
}

/// Used to report metrics whenever [`LeaderState::uncompacted_rows`] changes.
#[derive(Debug)]
pub(crate) struct UncompactedRowsStats {
    count: usize,
    first_index: Option<LogIndex>,
}

impl UncompactedRowsStats {
    pub(crate) fn new(leader: &LeaderState) -> Self {
        Self {
            count: leader.uncompacted_rows.len(),
            first_index: leader.uncompacted_rows.front().map(|row| row.index),
        }
    }

    pub(crate) fn publish(&self, metrics: &metrics::Client, tags: &[Tag]) {
        metrics.distribution("agent.compaction.uncompacted_rows.count", self.count, tags);
        if let Some(first_index) = self.first_index {
            metrics.gauge(
                "agent.compaction.uncompacted_rows.first_index",
                first_index.0,
                tags,
            );
        }
    }
}

#[derive(Clone)]
struct AgentDiscoveryCache {
    inner: Arc<Mutex<AgentDiscoveryCacheInner>>,
}

struct AgentDiscoveryCacheInner {
    peers: HashMap<HsmId, Url>,
    /// This is included for its `Drop` implementation, which aborts the
    /// background task. It's always `Some` after initialization.
    task: Option<ScopedTask<()>>,
}

impl AgentDiscoveryCache {
    async fn new(
        disco: &DiscoveryWatcher,
        client: ReqwestClientMetrics,
        interval: Duration,
    ) -> Self {
        let mut disco_rx = disco.subscribe(ServiceKind::Agent);
        let agents = disco_rx.borrow_and_update().clone();
        let init_peers: HashMap<HsmId, Url> = hsm_ids(&client, &agents.0).await.collect();
        info!(?init_peers, "initialized agent discovery cache");

        let c = Self {
            inner: Arc::new(Mutex::new(AgentDiscoveryCacheInner {
                peers: init_peers.clone(),
                task: None,
            })),
        };

        let clone = c.clone();
        let task = Some(ScopedTask::spawn(async move {
            let mut last = init_peers;
            loop {
                // If an agent is down or unreachable, it'll get dropped from
                // the peers cache. This means callers using the cache will skip
                // that agent entirely until this loops spots that its available
                // again. This is useful particularly for get_captures as it
                // prevents it from having to wait for the timeout each time its
                // called. Otherwise this would only need to call hsm_ids again
                // if the set of discovery urls changed.
                sleep(interval).await;
                let agents = disco_rx.borrow_and_update().clone();
                let new_peers: HashMap<HsmId, Url> = hsm_ids(&client, &agents.0).await.collect();
                if new_peers != last {
                    last = new_peers.clone();
                    info!(?new_peers, "updated peers in AgentDiscoveryCache");
                    let mut locked = clone.inner.lock().unwrap();
                    locked.peers = new_peers;
                }
            }
        }));
        c.inner.lock().unwrap().task = task;
        c
    }

    fn url(&self, id: &HsmId) -> Option<Url> {
        let locked = self.inner.lock().unwrap();
        locked.peers.get(id).cloned()
    }
}

// How long should we wait to do the next NVRAM write? We want to do the
// write at the same time on each agent/hsm in the cluster so that we can
// commit as many log entries as possible. Because of this they're aligned
// to the clock rather than a rolling monotonic interval.
fn how_long_to_wait(time: SystemTime, interval_millis: u64) -> Duration {
    let interval = u128::from(interval_millis);
    let now = time.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let r = now.as_millis() % interval;
    if r == 0 {
        Duration::from_millis(2)
    } else {
        Duration::from_millis(u64::try_from(interval - r).expect(
            "the value can't be larger than supplied interval_millis value which was a u64",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use store::log::testing::new_log_row;

    #[test]
    fn test_split_off_compactible_prefix() {
        #[derive(Debug)]
        struct TestCase {
            expected: &'static [u64],
            input: &'static [u64],
            compact_index: u64,
        }

        for case in [
            TestCase {
                expected: &[],
                input: &[],
                compact_index: 0,
            },
            TestCase {
                expected: &[],
                input: &[1],
                compact_index: 0,
            },
            TestCase {
                expected: &[],
                input: &[1],
                compact_index: 1,
            },
            TestCase {
                expected: &[],
                input: &[1],
                compact_index: 2,
            },
            TestCase {
                expected: &[1],
                input: &[1, 3],
                compact_index: 2,
            },
            TestCase {
                expected: &[1],
                input: &[1, 3, 5],
                compact_index: 3,
            },
            TestCase {
                expected: &[1, 3],
                input: &[1, 3, 5],
                compact_index: 4,
            },
            TestCase {
                expected: &[1, 3],
                input: &[1, 3, 5],
                compact_index: 5,
            },
            TestCase {
                expected: &[1, 2],
                input: &[1, 2, 3, 4],
                compact_index: 2,
            },
            TestCase {
                expected: &[1, 2, 3],
                input: &[1, 2, 3, 4],
                compact_index: 3,
            },
            TestCase {
                expected: &[1, 2, 3],
                input: &[1, 2, 3, 4],
                compact_index: 4,
            },
            TestCase {
                expected: &[1, 2, 3],
                input: &[1, 2, 3, 4],
                compact_index: 5,
            },
            TestCase {
                expected: &[1],
                input: &[1, 3, 10],
                compact_index: 6,
            },
            TestCase {
                expected: &[1, 3],
                input: &[1, 3, 10],
                compact_index: 9,
            },
        ] {
            let expected: Vec<LogRow> = case
                .expected
                .iter()
                .map(|i| new_log_row(LogIndex(*i), false))
                .collect();

            let full_input: VecDeque<LogRow> = case
                .input
                .iter()
                .map(|i| new_log_row(LogIndex(*i), false))
                .collect();

            let mut input = full_input.clone();
            let compactible =
                split_off_compactible_prefix(&mut input, LogIndex(case.compact_index));
            assert_eq!(
                compactible, expected,
                "compactible rows did not match expected. {case:?}"
            );

            assert_eq!(
                compactible
                    .into_iter()
                    .chain(input)
                    .collect::<VecDeque<LogRow>>(),
                full_input,
                "did not split fully. {case:?}"
            );
        }
    }

    #[test]
    fn test_how_long_to_wait() {
        assert_eq!(
            Duration::from_millis(2),
            how_long_to_wait(
                SystemTime::UNIX_EPOCH + Duration::from_millis(10000000),
                100
            )
        );
        assert_eq!(
            Duration::from_millis(12),
            how_long_to_wait(SystemTime::UNIX_EPOCH + Duration::from_millis(11088), 100)
        );
        assert_eq!(
            Duration::from_millis(112),
            how_long_to_wait(SystemTime::UNIX_EPOCH + Duration::from_millis(11088), 200)
        );
        assert_eq!(
            Duration::from_millis(12),
            how_long_to_wait(SystemTime::UNIX_EPOCH + Duration::from_millis(11088), 300)
        );
        assert_eq!(
            Duration::from_millis(48),
            how_long_to_wait(SystemTime::UNIX_EPOCH + Duration::from_millis(11052), 300)
        );
        assert_eq!(
            Duration::from_millis(248),
            how_long_to_wait(SystemTime::UNIX_EPOCH + Duration::from_millis(11152), 300)
        );
        assert_eq!(
            Duration::from_millis(148),
            how_long_to_wait(SystemTime::UNIX_EPOCH + Duration::from_millis(11252), 300)
        );
        assert_eq!(
            Duration::from_millis(48),
            how_long_to_wait(SystemTime::UNIX_EPOCH + Duration::from_millis(11352), 300)
        );
        assert_eq!(
            Duration::from_millis(248),
            how_long_to_wait(SystemTime::UNIX_EPOCH + Duration::from_millis(12352), 300)
        );
        for int in [50, 100, 150, 200, 250, 300, 350, 450, 650] {
            let w = how_long_to_wait(SystemTime::now(), int);
            assert!(w.as_millis() <= u128::from(int));
        }
    }
}
