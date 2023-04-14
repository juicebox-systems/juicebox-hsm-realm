use futures::future::join_all;
use loam_sdk_networking::rpc;
use std::collections::HashSet;
use std::time::{Duration, SystemTime};
use tokio::time::sleep;
use tracing::{info, trace, warn, Span};

use super::super::hsm::client::Transport;
use super::types::{ReadCapturedRequest, ReadCapturedResponse};
use super::Agent;
use hsmcore::hsm::{
    commit::HsmElection,
    types::{
        CommitRequest, CommitResponse, Configuration, GroupId, HsmId, LogIndex,
        PersistStateRequest, PersistStateResponse,
    },
};
use loam_sdk::RealmId;

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
            loop {
                sleep(how_long_to_wait(SystemTime::now(), WRITE_INTERVAL_MILLIS)).await;
                match agent.0.hsm.send(PersistStateRequest {}).await {
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

    pub(super) fn start_group_committer(
        &self,
        realm: RealmId,
        group: GroupId,
        config: Configuration,
    ) {
        info!(?realm, ?group, "Starting group committer");

        let agent = self.clone();

        tokio::spawn(async move {
            let interval = Duration::from_millis(2);
            let mut committed: Option<LogIndex> = None;
            loop {
                committed = match agent.commit_maybe(realm, group, &config, committed).await {
                    CommitterStatus::NoLongerLeader => {
                        info!(?realm, ?group, "No longer leader, stopping committer");
                        return;
                    }
                    CommitterStatus::Committing { committed: c } => c,
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
        committed: Option<LogIndex>,
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

        // We're still leader for this group, go collect up all the capture results from all the group members.
        let peers: HashSet<&HsmId> = config.0.iter().collect();

        // TODO, we need to cache the peer mapping
        let addresses = match self.0.store.get_addresses().await {
            Err(e) => {
                warn!(err=?e, "failed to get peer addresses from service discovery");
                return CommitterStatus::Committing { committed };
            }
            Ok(addresses) => addresses,
        };

        // Go get the captures, and filter them down to just this realm/group.
        let captures = join_all(addresses.iter().filter(|(id, _)| peers.contains(id)).map(
            |(_, url)| {
                rpc::send(
                    &self.0.peer_client,
                    url,
                    ReadCapturedRequest { realm, group },
                )
            },
        ))
        .await
        .into_iter()
        // skip network failures
        .filter_map(|r| r.ok())
        .filter_map(|r| match r {
            ReadCapturedResponse::Ok(captured) => captured,
        })
        .collect::<Vec<_>>();

        // Calculate a commit index.
        let mut election = HsmElection::new(&config.0);
        for c in &captures {
            election.vote(c.hsm, c.index);
        }
        let outcome = election.outcome();
        if !outcome.has_quorum || outcome.index.is_none() {
            return CommitterStatus::Committing { committed };
        }
        if let Some(commit) = committed {
            // We've already committed this.
            if outcome.index.unwrap() <= commit {
                return CommitterStatus::Committing { committed };
            }
        }
        trace!(?group, index=?outcome.index.unwrap(), "election has quorum");
        let commit_request = CommitRequest {
            realm,
            group,
            captures,
        };

        // Ask the HSM to do the commit
        let response = self.0.hsm.send(commit_request).await;
        let (new_committed, responses) = match response {
            Ok(CommitResponse::Ok {
                committed,
                responses,
            }) => {
                trace!(
                    agent = self.0.name,
                    ?committed,
                    num_responses=?responses.len(),
                    "HSM committed entry"
                );
                (committed, responses)
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
                return CommitterStatus::Committing { committed };
            }
        };

        // Release responses to the clients.
        let mut released_count = 0;
        let mut locked = self.0.state.lock().unwrap();
        if let Some(leader) = locked.leader.get_mut(&(realm, group)) {
            for (hmac, client_response) in responses {
                if let Some(sender) = leader.response_channels.remove(&hmac) {
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
        Span::current().record("released_count", released_count);
        CommitterStatus::Committing {
            committed: Some(new_committed),
        }
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
        Duration::ZERO
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
            Duration::from_millis(0),
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
