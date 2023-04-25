extern crate alloc;

use alloc::vec::Vec;
use hashbrown::HashMap;
use tracing::{info, trace, warn};

use super::super::hal::Platform;
use super::types::{Captured, CommitRequest, CommitResponse, GroupMemberRole, HsmId, LogIndex};
use super::{CapturedStatementBuilder, Hsm, Metrics};

impl<P: Platform> Hsm<P> {
    pub(super) fn handle_commit(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: CommitRequest,
    ) -> CommitResponse {
        type Response = CommitResponse;
        trace!(hsm = self.options.name, ?request);

        let response = (|| {
            let Some(realm) = &self.persistent.realm else {
                return Response::InvalidRealm;
            };
            if realm.id != request.realm {
                return Response::InvalidRealm;
            }

            let Some(group) = realm.groups.get(&request.group) else {
                return Response::InvalidGroup;
            };

            let (leader_log, committed) = match self.volatile.leader.get_mut(&request.group) {
                Some(leader) => (&mut leader.log, &mut leader.committed),
                None => match self.volatile.stepping_down.get_mut(&request.group) {
                    Some(steppingdown) => (&mut steppingdown.log, &mut steppingdown.committed),
                    None => return Response::NotLeader,
                },
            };

            let mut election = HsmElection::new(&group.configuration.0);
            let verify_capture = |captured: &Captured| -> bool {
                match (CapturedStatementBuilder {
                    hsm: captured.hsm,
                    realm: captured.realm,
                    group: captured.group,
                    index: captured.index,
                    entry_hmac: &captured.hmac,
                }
                .verify(&self.persistent.realm_key, &captured.statement))
                {
                    Ok(_) => true,
                    Err(err) => {
                        warn!(?err, ?captured, "failed to verify capture statement");
                        false
                    }
                }
            };
            for captured in &request.captures {
                if captured.group == request.group
                    && captured.realm == request.realm
                    && verify_capture(captured)
                {
                    // Ensure the entry HMAC is valid for this log by checking
                    // it against entries we have. For a new leader this won't
                    // be able to commit until the witnesses catch up to a log
                    // entry written by the new leader.
                    if let Some(offset) = captured.index.0.checked_sub(leader_log[0].entry.index.0)
                    {
                        if let Ok(offset) = usize::try_from(offset) {
                            if offset < leader_log.len()
                                && leader_log[offset].entry.entry_hmac == captured.hmac
                            {
                                election.vote(captured.hsm, captured.index);
                            }
                        }
                    }
                }
            }

            let Ok(commit_index) = election.outcome() else {
                warn!(
                    hsm = self.options.name,
                    commit_request = ?request,
                    "no quorum. buggy caller?"
                );
                return Response::NoQuorum;
            };

            if let Some(committed) = committed {
                if *committed >= commit_index {
                    return Response::AlreadyCommitted {
                        committed: *committed,
                    };
                }
            }

            trace!(hsm = self.options.name, group=?request.group, index = ?commit_index, prev_index=?committed, "leader committed entries");
            // trim the prefix of leader.log and collect up the responses
            let mut responses = Vec::new();
            loop {
                match leader_log.pop_front() {
                    None => panic!("We should never empty leader.log entirely"),
                    Some(e) if e.entry.index < commit_index => {
                        if let Some(r) = e.response {
                            responses.push((e.entry.entry_hmac, r));
                        }
                    }
                    Some(mut e) => {
                        assert!(e.entry.index == commit_index);
                        if let Some(r) = e.response.take() {
                            responses.push((e.entry.entry_hmac.clone(), r));
                        }
                        // If there's still something in the log then we
                        // don't need to put this one back. But it seems
                        // safer to be consistent and always have this
                        // one in the log.
                        leader_log.push_front(e);
                        break;
                    }
                }
            }
            *committed = Some(commit_index);

            // See if we're finished stepping down.
            let role = if let Some(sd) = self.volatile.stepping_down.get(&request.group) {
                if commit_index >= sd.stepdown_at {
                    info!(group=?request.group, hsm=self.options.name, "Completed leader stepdown");
                    self.volatile.stepping_down.remove(&request.group);
                    GroupMemberRole::Witness
                } else {
                    GroupMemberRole::SteppingDown
                }
            } else {
                GroupMemberRole::Leader
            };

            Response::Ok {
                committed: commit_index,
                responses,
                role,
            }
        })();

        trace!(hsm = self.options.name, ?response);
        response
    }
}

pub struct HsmElection {
    votes: HashMap<HsmId, Option<LogIndex>>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ElectionNoQuorum;

impl HsmElection {
    pub fn new(voters: &[HsmId]) -> HsmElection {
        assert!(!voters.is_empty());
        HsmElection {
            votes: HashMap::from_iter(voters.iter().map(|id| (*id, None))),
        }
    }

    pub fn vote(&mut self, voter: HsmId, index: LogIndex) {
        self.votes.entry(voter).and_modify(|f| *f = Some(index));
    }

    pub fn outcome(self) -> Result<LogIndex, ElectionNoQuorum> {
        let mut indexes = self
            .votes
            .values()
            .filter_map(|v| *v)
            .collect::<Vec<LogIndex>>();
        // largest to smallest
        indexes.sort_by(|a, b| b.cmp(a));
        let m = self.votes.len() / 2;
        if indexes.len() > m {
            Ok(indexes[m])
        } else {
            Err(ElectionNoQuorum)
        }
    }
}

#[cfg(test)]
mod test {
    use core::iter::zip;

    use super::{
        super::types::{HsmId, LogIndex},
        ElectionNoQuorum, HsmElection,
    };

    #[test]
    #[should_panic]
    fn empty_election() {
        HsmElection::new(&[]);
    }

    #[test]
    fn election_index() {
        fn run_election(members: &[HsmId], indexes: &[u64]) -> Result<LogIndex, ElectionNoQuorum> {
            let mut e = HsmElection::new(members);
            for (hsm, index) in zip(members, indexes) {
                e.vote(*hsm, LogIndex(*index));
            }
            e.outcome()
        }
        let ids = (0..5).map(|b| HsmId([b; 16])).collect::<Vec<_>>();
        assert_eq!(run_election(&ids, &[15, 15, 15, 14, 13]), Ok(LogIndex(15)));
        assert_eq!(run_election(&ids, &[13, 14, 15, 14, 13]), Ok(LogIndex(14)));
        assert_eq!(run_election(&ids, &[13, 13, 15, 14, 13]), Ok(LogIndex(13)));
        assert_eq!(run_election(&ids, &[13, 14, 15, 14]), Ok(LogIndex(14)));
        assert_eq!(run_election(&ids, &[13, 15, 14]), Ok(LogIndex(13)));
        assert_eq!(run_election(&ids, &[13, 15]), Err(ElectionNoQuorum));
        assert_eq!(run_election(&ids, &[13]), Err(ElectionNoQuorum));
        assert_eq!(run_election(&ids, &[]), Err(ElectionNoQuorum));

        assert_eq!(run_election(&ids[..4], &[11, 12, 13, 14]), Ok(LogIndex(12)));
        assert_eq!(run_election(&ids[..4], &[11, 12, 14]), Ok(LogIndex(11)));
        assert_eq!(run_election(&ids[..4], &[11, 12]), Err(ElectionNoQuorum));
        assert_eq!(run_election(&ids[..4], &[12]), Err(ElectionNoQuorum));
        assert_eq!(run_election(&ids[..4], &[]), Err(ElectionNoQuorum));

        assert_eq!(run_election(&ids[..3], &[15, 13, 14]), Ok(LogIndex(14)));
        assert_eq!(run_election(&ids[..3], &[15, 15, 15]), Ok(LogIndex(15)));
        assert_eq!(run_election(&ids[..3], &[11, 11, 15]), Ok(LogIndex(11)));
        assert_eq!(run_election(&ids[..3], &[11, 15]), Ok(LogIndex(11)));
        assert_eq!(run_election(&ids[..3], &[11]), Err(ElectionNoQuorum));
        assert_eq!(run_election(&ids[..3], &[]), Err(ElectionNoQuorum));

        assert_eq!(run_election(&ids[..2], &[13, 15]), Ok(LogIndex(13)));
        assert_eq!(run_election(&ids[..2], &[13]), Err(ElectionNoQuorum));
        assert_eq!(run_election(&ids[..2], &[]), Err(ElectionNoQuorum));

        assert_eq!(run_election(&ids[..1], &[42]), Ok(LogIndex(42)));
        assert_eq!(run_election(&ids[..1], &[]), Err(ElectionNoQuorum));
    }

    #[test]
    fn election_voters() {
        let ids = (0..6).map(|b| HsmId([b; 16])).collect::<Vec<_>>();
        fn has_q(ids: &[HsmId], voters: &[HsmId]) -> bool {
            let mut q = HsmElection::new(ids);
            for v in voters.iter() {
                q.vote(*v, LogIndex(42));
            }
            q.outcome().is_ok()
        }
        // 1 member
        assert!(has_q(&ids[..1], &ids[..1]));
        assert!(!has_q(&ids[..1], &ids[..0]));
        // 2 members
        assert!(has_q(&ids[..2], &ids[..2]));
        assert!(!has_q(&ids[..2], &ids[..1]));
        assert!(!has_q(&ids[..2], &ids[..0]));
        // 3 members
        assert!(has_q(&ids[..3], &ids[..3]));
        assert!(has_q(&ids[..3], &ids[..2]));
        assert!(!has_q(&ids[..3], &ids[..1]));
        assert!(!has_q(&ids[..3], &ids[..0]));
        // 4
        assert!(has_q(&ids[..4], &ids[..4]));
        assert!(has_q(&ids[..4], &ids[..3]));
        assert!(!has_q(&ids[..4], &ids[..2]));
        assert!(!has_q(&ids[..4], &ids[..1]));
        assert!(!has_q(&ids[..4], &ids[..0]));
        // 5
        assert!(has_q(&ids[..5], &ids[..5]));
        assert!(has_q(&ids[..5], &ids[..4]));
        assert!(has_q(&ids[..5], &ids[..3]));
        assert!(!has_q(&ids[..5], &ids[..2]));
        assert!(!has_q(&ids[..5], &ids[..1]));
        assert!(!has_q(&ids[..5], &ids[..0]));
        // 6
        assert!(has_q(&ids[..6], &ids[..6]));
        assert!(has_q(&ids[..6], &[ids[0], ids[4], ids[1], ids[5], ids[3]]));
        assert!(has_q(&ids[..6], &[ids[5], ids[0], ids[2], ids[3]]));
        assert!(!has_q(&ids[..6], &[ids[4], ids[0], ids[2]]));
        assert!(!has_q(&ids[..6], &ids[3..5]));
        assert!(!has_q(&ids[..6], &[ids[5], ids[1]]));
        assert!(!has_q(&ids[..6], &ids[4..5]));
        assert!(!has_q(&ids[..6], &ids[..0]));
    }

    #[test]
    fn election_non_voters() {
        let ids = (0..10).map(|b| HsmId([b; 16])).collect::<Vec<_>>();
        let mut q = HsmElection::new(&ids[..5]);
        for not_member in &ids[5..] {
            q.vote(*not_member, LogIndex(42));
        }
        assert_eq!(Err(ElectionNoQuorum), q.outcome());
    }

    #[test]
    fn election_vote_only_counts_once() {
        let ids = (0..5).map(|b| HsmId([b; 16])).collect::<Vec<_>>();
        let mut q = HsmElection::new(&ids);
        q.vote(ids[0], LogIndex(13));
        q.vote(ids[0], LogIndex(13));
        q.vote(ids[0], LogIndex(13));
        q.vote(ids[1], LogIndex(13));
        assert_eq!(Err(ElectionNoQuorum), q.outcome());
    }
}
