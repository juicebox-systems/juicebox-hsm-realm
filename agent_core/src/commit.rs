use futures::future::join_all;
use reqwest::Url;
use std::collections::{HashMap, VecDeque};
use std::mem;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tracing::{info, instrument, span, trace, warn, Instrument, Level, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use super::hsm::Transport;
use super::{Agent, LeaderState};
use agent_api::{ReadCapturedRequest, ReadCapturedResponse};
use cluster_core::discover_hsm_ids;
use election::HsmElection;
use hsm_api::{
    AppResultType, Captured, CommitRequest, CommitResponse, EntryMac, GroupId, GroupMemberRole,
    HsmId, LogIndex, PersistStateRequest, PersistStateResponse,
};
use juicebox_networking::rpc::{self, SendOptions};
use juicebox_realm_api::requests::NoiseResponse;
use juicebox_realm_api::types::RealmId;
use observability::logging::TracingSource;
use observability::metrics::{self, Tag};
use observability::metrics_tag as tag;
use service_core::http::ReqwestClientMetrics;
use store::{LogRow, StoreClient};

// This is a feature flag to toggle whether the leader actually writes out
// tombstones.
const LOG_COMPACTION_ENABLED: bool = true;

#[derive(Debug, Eq, PartialEq)]
enum CommitterStatus {
    Committing { committed: Option<LogIndex> },
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
            self.0.store.clone(),
            self.0.peer_client.clone(),
            Duration::from_secs(10),
        )
        .await;

        // Spawn the log compactor task. The channel tracks the latest
        // compact index. The JoinSet's Drop impl aborts the task when the
        // committer task exits.
        let (compaction_tx, compaction_rx) = watch::channel(None);
        let mut compaction_task = JoinSet::new();
        compaction_task.spawn(self.clone().compactor(
            realm,
            group,
            compaction_rx,
            starting_index,
            config.clone(),
            agent_discovery.clone(),
        ));

        let cx = opentelemetry::Context::new().with_value(TracingSource::BackgroundJob);

        let mut last_committed: Option<LogIndex> = None;
        loop {
            let span = span!(Level::TRACE, "committer_loop");
            span.set_parent(cx.clone());

            match self
                .commit_maybe(realm, group, &config, &agent_discovery, last_committed)
                .instrument(span)
                .await
            {
                CommitterStatus::NoLongerLeader => {
                    info!(name=?self.0.name, ?realm, ?group, "No longer leader, stopping committer");
                    return;
                }
                CommitterStatus::Committing { committed: c } => {
                    if last_committed < c {
                        last_committed = c;
                    }
                }
            };

            // Notify the compaction task of updates. The compaction task
            // may compact up to the commit index (exclusive) and the
            // leader HSM's captured state (inclusive), whichever is
            // lowest. The first constraint keeps the critically useful
            // entries in the log, and the second prevents the leader HSM
            // from needing a CaptureJump RPC due to its own compactions.
            //
            // When PersistState updates the captured info, `compaction_tx`
            // won't be notified until this loop gets back here. This loops
            // frequently so that's OK for now.
            let local_captured = {
                let locked = self.0.state.lock().unwrap();
                locked
                    .captures
                    .iter()
                    .find(|captured| captured.realm == realm && captured.group == group)
                    .map(|captured| captured.index)
            };
            let compact_index = Option::<LogIndex>::min(
                last_committed.and_then(|index| index.prev()),
                local_captured,
            );
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
        last_committed: Option<LogIndex>,
    ) -> CommitterStatus {
        if self
            .0
            .state
            .lock()
            .unwrap()
            .leader
            .get(&(realm, group))
            .is_none()
        {
            return CommitterStatus::NoLongerLeader;
        }

        // We're still leader for this group. See if we can move the commit index forward.
        let captures = self.get_captures(realm, group, config, peers).await;

        // Calculate a commit index.
        let mut election = HsmElection::new(config);
        for c in &captures {
            election.vote(c.hsm, c.index);
        }
        let Ok(commit_index) = election.outcome() else {
            return CommitterStatus::Committing {
                committed: last_committed,
            };
        };
        if let Some(commit) = last_committed {
            // We've already committed this.
            if commit_index <= commit {
                return CommitterStatus::Committing {
                    committed: last_committed,
                };
            }
        }
        Span::current().record("quorum", commit_index.0);

        self.do_commit(
            CommitRequest {
                realm,
                group,
                captures,
            },
            last_committed,
        )
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
    ) -> Vec<Captured> {
        let urls: Vec<Url> = hsms.iter().filter_map(|hsm| peers.url(hsm)).collect();
        join_all(urls.iter().map(|url| {
            rpc::send_with_options(
                &self.0.peer_client,
                url,
                ReadCapturedRequest { realm, group },
                SendOptions::default().with_timeout(Duration::from_millis(500)),
            )
        }))
        .await
        .into_iter()
        // skip network failures
        .filter_map(|r| r.ok())
        .filter_map(|r| match r {
            ReadCapturedResponse::Ok(captured) => captured,
        })
        .collect()
    }

    // Ask the HSM to do the commit.
    #[instrument(level = "trace", skip(self, request), fields(released_count))]
    async fn do_commit(
        &self,
        request: CommitRequest,
        last_committed: Option<LogIndex>,
    ) -> CommitterStatus {
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
                self.0.maybe_role_changed(realm, group, role);
                return CommitterStatus::NoLongerLeader;
            }
            _ => {
                warn!(agent = self.0.name, ?response, "commit response not ok");
                return CommitterStatus::Committing {
                    committed: last_committed,
                };
            }
        };

        let role = commit_state.role;
        let committed = commit_state.committed;
        let released_count = self.release_client_responses(
            realm,
            group,
            commit_state.responses,
            commit_state.abandoned,
        );
        Span::current().record("released_count", released_count);

        // See if we're done stepping down
        self.0.maybe_role_changed(realm, group, role);
        if role == GroupMemberRole::Witness {
            info!(?group, "Leader stepped down");
            CommitterStatus::NoLongerLeader
        } else {
            CommitterStatus::Committing {
                committed: Some(committed),
            }
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
        if let Some(leader) = locked.leader.get_mut(&(realm, group)) {
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

        if !LOG_COMPACTION_ENABLED {
            // We want to run compact_init even when log compaction is disabled
            // because we want to see it scan the log and eat up RAM.
            return;
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
    #[instrument(level = "trace", skip(self, agent_discovery), fields(rows))]
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
            elapsed = ?start.elapsed(),
            LOG_COMPACTION_ENABLED,
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
            let Some(leader) = locked.leader.get_mut(&(*realm, *group)) else {
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
            let Some(leader) = locked.leader.get_mut(&(realm, group)) else {
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
            .flat_map(|id| agent_discovery.url(id))
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
                        .any(|gs| gs.id == *group && gs.role == GroupMemberRole::Witness)
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
        metrics.gauge("agent.compaction.uncompacted_rows.count", self.count, tags);
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
    // This is included for its `Drop` implementation, which aborts the
    // background task(s).
    tasks: JoinSet<()>,
}

impl AgentDiscoveryCache {
    async fn new(
        store: StoreClient,
        agent_client: ReqwestClientMetrics,
        interval: Duration,
    ) -> Self {
        let init_peers: HashMap<HsmId, Url> = match discover_hsm_ids(&store, &agent_client).await {
            Ok(it) => it.collect(),
            Err(_) => HashMap::new(),
        };

        let c = Self {
            inner: Arc::new(Mutex::new(AgentDiscoveryCacheInner {
                peers: init_peers,
                tasks: JoinSet::new(),
            })),
        };
        let clone = c.clone();
        c.inner.lock().unwrap().tasks.spawn(async move {
            let mut next_interval = interval;
            loop {
                sleep(next_interval).await;
                match discover_hsm_ids(&store, &agent_client).await {
                    Ok(it) => {
                        let new_peers: HashMap<HsmId, Url> = it.collect();
                        let mut locked = clone.inner.lock().unwrap();
                        locked.peers = new_peers;
                        next_interval = interval;
                    }
                    Err(err) => {
                        warn!(?err, "failed to fetch service discovery info from bigtable");
                        next_interval = interval / 10;
                    }
                }
            }
        });
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
