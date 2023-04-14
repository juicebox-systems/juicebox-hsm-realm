extern crate alloc;

use alloc::vec::Vec;
use core::fmt::{self, Debug};
use hashbrown::HashMap;
use tracing::{trace, warn};

use super::super::hal::Platform;
use super::types::{CommitRequest, CommitResponse, HsmId, LogIndex};
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
                return CommitResponse::InvalidGroup;
            };

            let Some(leader) = self.volatile.leader.get_mut(&request.group) else {
                return CommitResponse::NotLeader;
            };

            let mut election = HsmElection::new(&group.configuration.0);
            for captured in &request.captures {
                if captured.group == request.group &&
                    captured.realm == request.realm &&
                    (CapturedStatementBuilder {
                        hsm: captured.hsm,
                        realm: captured.realm,
                        group: captured.group,
                        index: captured.index,
                        entry_hmac: &captured.hmac,
                    }
                    .verify(&self.persistent.realm_key, &captured.statement)
                    .map_err(|e|warn!(err=?e, hsm=?captured.hsm, group=?captured.group, ?captured.index, "failed to verify capture statement"))
                    .is_ok())
                    {
                        // Ensure the entry hmac matches, so that we know this is a vote for a log entry we wrote.
                        // For a new leader this won't be able to commit until the witnesses catch up to a log entry written by the new leader.
                        if let Some(offset) = captured.index.0.checked_sub(leader.log[0].entry.index.0) {
                            let offset = usize::try_from(offset).unwrap();
                            if offset < leader.log.len() && leader.log[offset].entry.entry_hmac == captured.hmac {
                                election.vote(captured.hsm, captured.index);
                            }
                        }
                    }
            }

            let election_outcome = election.outcome();
            if !election_outcome.has_quorum || election_outcome.index.is_none() {
                warn!(
                    hsm = self.options.name,
                    election = ?election_outcome,
                    commit_request = ?request,
                    "no quorum. buggy caller?"
                );
                return CommitResponse::NoQuorum;
            }

            let commit_index = election_outcome.index.unwrap();
            if let Some(committed) = leader.committed {
                if committed >= commit_index {
                    return CommitResponse::AlreadyCommitted { committed };
                }
            }

            trace!(hsm = self.options.name, group=?request.group, index = ?commit_index, "leader committed entry");
            // todo: skip already committed entries
            let responses = leader
                .log
                .iter_mut()
                .filter(|entry| entry.entry.index <= commit_index)
                .filter_map(|entry| {
                    entry
                        .response
                        .take()
                        .map(|r| (entry.entry.entry_hmac.clone(), r))
                })
                .collect();
            leader.committed = Some(commit_index);
            CommitResponse::Ok {
                committed: commit_index,
                responses,
            }
        })();

        trace!(hsm = self.options.name, ?response);
        response
    }
}

pub struct HsmElection {
    votes: HashMap<HsmId, Option<LogIndex>>,
}

#[derive(PartialEq, Eq)]
pub struct HsmElectionOutcome {
    pub has_quorum: bool,
    pub vote_count: usize,
    pub member_count: usize,
    pub index: Option<LogIndex>,
}

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

    pub fn outcome(self) -> HsmElectionOutcome {
        let mut indexes = self
            .votes
            .values()
            .filter_map(|v| *v)
            .collect::<Vec<LogIndex>>();
        indexes.sort_by(|a, b| b.cmp(a));
        let m = self.votes.len() / 2;
        let index = if indexes.len() > m {
            indexes[m]
        } else {
            return HsmElectionOutcome {
                has_quorum: false,
                member_count: self.votes.len(),
                vote_count: indexes.len(),
                index: if indexes.is_empty() {
                    None
                } else {
                    Some(indexes[0])
                },
            };
        };

        let yay = self
            .votes
            .iter()
            .filter(|(_, v)| match v {
                None => false,
                Some(i) => *i >= index,
            })
            .count();
        let all = self.votes.len();
        HsmElectionOutcome {
            has_quorum: yay * 2 > all,
            vote_count: yay,
            member_count: all,
            index: Some(index),
        }
    }
}

impl Debug for HsmElectionOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HsmElectionOutcome votes {} out of {} for index {:?}, {}",
            self.vote_count,
            self.member_count,
            self.index,
            if self.has_quorum {
                "Quorum"
            } else {
                "NoQuorum"
            }
        )
    }
}

#[cfg(test)]
mod test {
    use core::iter::zip;

    use super::{
        super::types::{HsmId, LogIndex},
        HsmElection, HsmElectionOutcome,
    };

    #[test]
    #[should_panic]
    fn empty_election() {
        HsmElection::new(&[]);
    }

    #[test]
    fn election_index() {
        let ids = (0..5).map(|b| HsmId([b; 16])).collect::<Vec<_>>();

        let mut e = HsmElection::new(&ids);
        for (hsm, index) in zip(ids.iter(), [15, 15, 15, 14, 13]) {
            e.vote(*hsm, LogIndex(index));
        }
        assert_eq!(
            HsmElectionOutcome {
                has_quorum: true,
                vote_count: 3,
                member_count: 5,
                index: Some(LogIndex(15)),
            },
            e.outcome()
        );

        let mut e = HsmElection::new(&ids);
        for (hsm, index) in zip(ids.iter(), [15, 13, 15, 14, 13]) {
            e.vote(*hsm, LogIndex(index));
        }
        assert_eq!(
            HsmElectionOutcome {
                has_quorum: true,
                vote_count: 3,
                member_count: 5,
                index: Some(LogIndex(14))
            },
            e.outcome()
        );

        let mut e = HsmElection::new(&ids);
        for (hsm, index) in zip(ids.iter(), [13, 15, 14]) {
            e.vote(*hsm, LogIndex(index));
        }
        assert_eq!(
            HsmElectionOutcome {
                has_quorum: true,
                vote_count: 3,
                member_count: 5,
                index: Some(LogIndex(13))
            },
            e.outcome()
        );

        let mut e = HsmElection::new(&ids);
        e.vote(ids[0], LogIndex(15));
        e.vote(ids[2], LogIndex(15));
        assert_eq!(
            HsmElectionOutcome {
                has_quorum: false,
                vote_count: 2,
                member_count: 5,
                index: Some(LogIndex(15)),
            },
            e.outcome()
        );

        let mut e = HsmElection::new(&ids[..3]);
        for (hsm, index) in zip(ids.iter(), [15, 14, 13]) {
            e.vote(*hsm, LogIndex(index));
        }
        assert_eq!(
            HsmElectionOutcome {
                has_quorum: true,
                vote_count: 2,
                member_count: 3,
                index: Some(LogIndex(14))
            },
            e.outcome()
        );

        let mut e = HsmElection::new(&ids[..4]);
        for (hsm, index) in zip(ids.iter(), [15, 14, 13, 12]) {
            e.vote(*hsm, LogIndex(index));
        }
        assert_eq!(
            HsmElectionOutcome {
                has_quorum: true,
                vote_count: 3,
                member_count: 4,
                index: Some(LogIndex(13)),
            },
            e.outcome()
        );

        let mut e = HsmElection::new(&ids[..2]);
        e.vote(ids[0], LogIndex(15));
        e.vote(ids[1], LogIndex(13));
        assert_eq!(
            HsmElectionOutcome {
                has_quorum: true,
                vote_count: 2,
                member_count: 2,
                index: Some(LogIndex(13))
            },
            e.outcome()
        );
    }

    #[test]
    fn election_voters() {
        let ids = (0..6).map(|b| HsmId([b; 16])).collect::<Vec<_>>();
        fn has_q(ids: &[HsmId], voters: &[HsmId]) -> bool {
            let mut q = HsmElection::new(ids);
            for v in voters.iter() {
                q.vote(*v, LogIndex(42));
            }
            let o = q.outcome();
            assert_eq!(voters.len(), o.vote_count);
            assert_eq!(ids.len(), o.member_count);
            o.has_quorum
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
        assert_eq!(
            HsmElectionOutcome {
                has_quorum: false,
                vote_count: 0,
                member_count: 5,
                index: None,
            },
            q.outcome()
        );
    }

    #[test]
    fn election_vote_only_counts_once() {
        let ids = (0..5).map(|b| HsmId([b; 16])).collect::<Vec<_>>();
        let mut q = HsmElection::new(&ids);
        q.vote(ids[0], LogIndex(13));
        q.vote(ids[0], LogIndex(13));
        q.vote(ids[0], LogIndex(13));
        q.vote(ids[1], LogIndex(13));
        assert_eq!(
            HsmElectionOutcome {
                has_quorum: false,
                vote_count: 2,
                member_count: 5,
                index: Some(LogIndex(13)),
            },
            q.outcome()
        );
    }
}
