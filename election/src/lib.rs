#![no_std]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use hsm_api::{HsmId, LogIndex};

extern crate alloc;

pub struct HsmElection {
    /// State per eligible voter.
    ///
    votes: BTreeMap<HsmId, Option<LogIndex>>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ElectionNoQuorum;

impl HsmElection {
    pub fn new<'a, I>(voters: I) -> HsmElection
    where
        I: IntoIterator<Item = &'a HsmId>,
    {
        let votes = BTreeMap::from_iter(voters.into_iter().map(|id| (*id, None)));
        assert!(!votes.is_empty());
        HsmElection { votes }
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
mod tests {
    use core::iter::zip;

    use super::{ElectionNoQuorum, HsmElection};
    use alloc::vec::Vec;
    use hsm_api::{HsmId, LogIndex};

    #[test]
    #[should_panic]
    fn empty_election() {
        HsmElection::new([]);
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
