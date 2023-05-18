use futures::future::join_all;
use hsmcore::hsm::types::{Captured, EntryHmac, GroupMemberRole};
use loam_sdk_core::requests::NoiseResponse;
use loam_sdk_networking::rpc;
use reqwest::Url;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::task::JoinSet;
use tokio::time::sleep;
use tracing::{info, trace, warn, Span};

use super::types::{ReadCapturedRequest, ReadCapturedResponse};
use super::{Agent, MetricsWarn};
use hsmcore::hsm::{
    commit::HsmElection,
    types::{
        CommitRequest, CommitResponse, Configuration, GroupId, HsmId, LogIndex,
        PersistStateRequest, PersistStateResponse,
    },
};
use loam_mvp::logging::Spew;
use loam_mvp::realm::{hsm::client::Transport, store::bigtable::StoreClient};
use loam_sdk::RealmId;

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
            loop {
                sleep(how_long_to_wait(SystemTime::now(), WRITE_INTERVAL_MILLIS)).await;
                match agent.0.hsm.send(PersistStateRequest {}).await {
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

    pub(super) fn start_group_committer(
        &self,
        realm: RealmId,
        group: GroupId,
        config: Configuration,
    ) {
        info!(name=?self.0.name, ?realm, ?group, "Starting group committer");

        let agent = self.clone();

        tokio::spawn(async move {
            let interval = Duration::from_millis(2);
            let mut last_committed: Option<LogIndex> = None;
            let peers = PeerCache::new(agent.0.store.clone(), Duration::from_secs(10)).await;
            loop {
                match agent
                    .commit_maybe(realm, group, &config, &peers, last_committed)
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

    async fn commit_maybe(
        &self,
        realm: RealmId,
        group: GroupId,
        config: &Configuration,
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

        // Go get the captures from all the group members for this realm/group.
        let urls: Vec<Url> = config.0.iter().filter_map(|hsm| peers.url(hsm)).collect();
        let captures: Vec<Captured> = join_all(urls.iter().map(|url| {
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
        .collect();

        // Calculate a commit index.
        let mut election = HsmElection::new(&config.0);
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
        trace!(?group, index=?commit_index, "election has quorum");
        let commit_request = CommitRequest {
            realm,
            group,
            captures,
        };

        // Ask the HSM to do the commit
        let response = self.0.hsm.send(commit_request).await;
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
                self.0
                    .metrics
                    .gauge(
                        "agent.commit.log.index",
                        committed.0.to_string(),
                        [&format!("realm:{:?}", realm), &format!("group:{:?}", group)],
                    )
                    .warn_err();
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
        responses: Vec<(EntryHmac, NoiseResponse)>,
    ) -> i32 {
        let mut released_count = 0;
        let mut locked = self.0.state.lock().unwrap();
        let metric_tags = &[&format!("realm:{:?}", realm), &format!("group:{:?}", group)];
        if let Some(leader) = locked.leader.get_mut(&(realm, group)) {
            for (hmac, client_response) in responses {
                if let Some((start, sender)) = leader.response_channels.remove(&hmac) {
                    if sender.send(client_response).is_err() {
                        warn!("dropping response on the floor: client no longer waiting");
                    }
                    released_count += 1;
                    self.0
                        .metrics
                        .timing(
                            "agent.commit.latency.ms",
                            start.elapsed().as_millis() as i64,
                            metric_tags,
                        )
                        .warn_err();
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
    async fn new(store: StoreClient, interval: Duration) -> Self {
        let init_peers: HashMap<HsmId, Url> = store
            .get_addresses()
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut c = Self {
            peers: Arc::new(Mutex::new(init_peers)),
            tasks: JoinSet::new(),
        };
        let peers = c.peers.clone();
        c.tasks.spawn(async move {
            let mut next_interval = interval;
            loop {
                sleep(next_interval).await;
                match store.get_addresses().await {
                    Ok(a) => {
                        let mut locked = peers.lock().unwrap();
                        for (id, url) in a {
                            locked.insert(id, url);
                        }
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
