use futures::future::join_all;
use reqwest::Url;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::task::JoinSet;
use tokio::time::sleep;
use tracing::{info, instrument, span, trace, warn, Instrument, Level, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use super::hsm::Transport;
use super::Agent;
use agent_api::{AgentService, ReadCapturedRequest, ReadCapturedResponse};
use hsmcore::hsm::commit::HsmElection;
use hsmcore::hsm::types::{
    Captured, CommitRequest, CommitResponse, EntryMac, GroupId, GroupMemberRole, HsmId, LogIndex,
    PersistStateRequest, PersistStateResponse,
};
use juicebox_hsm::realm::cluster::discover_hsm_ids;
use juicebox_hsm::realm::store::bigtable::StoreClient;
use juicebox_sdk_core::requests::NoiseResponse;
use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_networking::reqwest::Client;
use juicebox_sdk_networking::rpc;
use observability::logging::{Spew, TracingSource};
use observability::metrics_tag as tag;

#[derive(Debug, Eq, PartialEq)]
enum CommitterStatus {
    Committing { committed: Option<LogIndex> },
    NoLongerLeader,
}

static NVRAM_WRITER_SPEW: Spew = Spew::new();

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
                        if let Some(suppressed) = NVRAM_WRITER_SPEW.ok() {
                            warn!(?err, suppressed, "failed to request HSM to write to NVRAM");
                        }
                    }
                    Ok(PersistStateResponse::Ok { captured, .. }) => {
                        agent.0.state.lock().unwrap().captures = captured
                    }
                };
            }
        });
    }

    pub(super) fn start_group_committer(&self, realm: RealmId, group: GroupId, config: Vec<HsmId>) {
        info!(name=?self.0.name, ?realm, ?group, "Starting group committer");

        let agent = self.clone();

        tokio::spawn(async move {
            let interval = Duration::from_millis(2);
            let mut last_committed: Option<LogIndex> = None;
            let peers = PeerCache::new(
                agent.0.store.clone(),
                agent.0.peer_client.clone(),
                Duration::from_secs(10),
            )
            .await;

            let cx = opentelemetry::Context::new().with_value(TracingSource::BackgroundJob);

            loop {
                let span = span!(Level::TRACE, "committer_loop");
                span.set_parent(cx.clone());

                match agent
                    .commit_maybe(realm, group, &config, &peers, last_committed)
                    .instrument(span)
                    .await
                {
                    CommitterStatus::NoLongerLeader => {
                        info!(name=?agent.0.name, ?realm, ?group, "No longer leader, stopping committer");
                        return;
                    }
                    CommitterStatus::Committing { committed: c } => last_committed = c,
                };
                sleep(interval).await;
            }
        });
    }

    #[instrument(level = "trace", skip(self, config, peers), fields(quorum))]
    async fn commit_maybe(
        &self,
        realm: RealmId,
        group: GroupId,
        config: &[HsmId],
        peers: &PeerCache,
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

    // Go get the captures from all the group members for this realm/group.
    #[instrument(level = "trace", skip(self, config, peers))]
    async fn get_captures(
        &self,
        realm: RealmId,
        group: GroupId,
        config: &[HsmId],
        peers: &PeerCache,
    ) -> Vec<Captured> {
        let urls: Vec<Url> = config.iter().filter_map(|hsm| peers.url(hsm)).collect();
        join_all(urls.iter().map(|url| {
            rpc::send(
                &self.0.peer_client,
                url,
                ReadCapturedRequest { realm, group },
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
        let (new_committed, responses, role) = match response {
            Ok(CommitResponse::Ok {
                committed,
                responses,
                role,
            }) => {
                trace!(
                    agent = self.0.name,
                    ?committed,
                    num_responses=?responses.len(),
                    "HSM committed entry"
                );
                self.0.metrics.gauge(
                    "agent.commit.log.index",
                    committed.0,
                    [tag!(?realm), tag!(?group)],
                );
                (committed, responses, role)
            }
            Ok(CommitResponse::AlreadyCommitted { committed: c }) => {
                info!(
                    agent = self.0.name,
                    ?response,
                    "commit response already committed"
                );
                return CommitterStatus::Committing { committed: Some(c) };
            }
            _ => {
                warn!(agent = self.0.name, ?response, "commit response not ok");
                return CommitterStatus::Committing {
                    committed: last_committed,
                };
            }
        };

        let released_count = self.release_client_responses(realm, group, responses);
        Span::current().record("released_count", released_count);

        // See if we're done stepping down
        if role == GroupMemberRole::Witness {
            info!(?group, "Leader stepped down");
            self.0.state.lock().unwrap().leader.remove(&(realm, group));
            CommitterStatus::NoLongerLeader
        } else {
            CommitterStatus::Committing {
                committed: Some(new_committed),
            }
        }
    }

    // Returns the number of released responses.
    fn release_client_responses(
        &self,
        realm: RealmId,
        group: GroupId,
        responses: Vec<(EntryMac, NoiseResponse)>,
    ) -> usize {
        let mut released_count = 0;
        let mut locked = self.0.state.lock().unwrap();
        if let Some(leader) = locked.leader.get_mut(&(realm, group)) {
            for (mac, client_response) in responses {
                if let Some(sender) = leader.response_channels.remove(&mac.into()) {
                    if sender.send(client_response).is_err() {
                        warn!("dropping response on the floor: client no longer waiting");
                    }
                    released_count += 1;
                } else {
                    warn!("dropping response on the floor: client never waiting");
                }
            }
        } else if !responses.is_empty() {
            warn!("dropping responses on the floor: no leader state");
        }
        released_count
    }
}

struct PeerCache {
    peers: Arc<Mutex<HashMap<HsmId, Url>>>,
    // This is included for its `Drop` implementation, which aborts the
    // background task(s).
    tasks: JoinSet<()>,
}
impl PeerCache {
    async fn new(
        store: StoreClient,
        agent_client: Client<AgentService>,
        interval: Duration,
    ) -> Self {
        let init_peers: HashMap<HsmId, Url> = match discover_hsm_ids(&store, &agent_client).await {
            Ok(it) => it.collect(),
            Err(_) => HashMap::new(),
        };

        let mut c = Self {
            peers: Arc::new(Mutex::new(init_peers)),
            tasks: JoinSet::new(),
        };
        let peers = c.peers.clone();
        c.tasks.spawn(async move {
            let mut next_interval = interval;
            loop {
                sleep(next_interval).await;
                match discover_hsm_ids(&store, &agent_client).await {
                    Ok(it) => {
                        let new_peers: HashMap<HsmId, Url> = it.collect();
                        let mut locked = peers.lock().unwrap();
                        *locked = new_peers;
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
        self.peers.lock().unwrap().get(id).cloned()
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
mod test {
    use super::how_long_to_wait;
    use std::time::{Duration, SystemTime};

    #[test]
    fn wait_calc() {
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
