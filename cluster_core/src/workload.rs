use hsm_api::{GroupId, HsmId, LogIndex};
use juicebox_realm_api::types::RealmId;

#[derive(Debug)]
pub struct HsmWorkload {
    pub id: HsmId,
    pub groups: Vec<GroupWorkload>,
}

impl HsmWorkload {
    pub fn new(s: &hsm_api::StatusResponse) -> Option<HsmWorkload> {
        s.realm.as_ref().map(|rs| {
            let groups = rs
                .groups
                .iter()
                .map(|gs| GroupWorkload::new(rs.id, gs))
                .collect();
            HsmWorkload { id: s.id, groups }
        })
    }

    pub fn work(&self) -> WorkAmount {
        self.groups.iter().map(|g| g.work()).sum()
    }

    pub fn moveable_workloads(&self) -> Vec<&GroupWorkload> {
        self.groups
            .iter()
            .filter(|w| w.members.len() > 1 && w.leader.is_some())
            .collect()
    }

    // Returns true if 'self' is in a state where it could reasonably become
    // leader for the 'target' group.
    pub fn can_lead(&self, target: &GroupWorkload) -> bool {
        if !target.members.contains(&self.id) {
            return false;
        }
        const MAX_CAPTURE_TRAILING: u64 = 1000;

        self.groups
            .iter()
            .find(|g| g.group == target.group && g.realm == target.realm)
            .is_some_and(|my_group| {
                matches!(
                    (my_group.last_captured, target.last_captured),
                    (Some(mine), Some(target))
                    if mine.0 > target.0.saturating_sub(MAX_CAPTURE_TRAILING))
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupWorkload {
    pub witness: WorkAmount,
    pub leader: Option<WorkAmount>,
    pub members: Vec<HsmId>,
    pub last_captured: Option<LogIndex>,
    pub group: GroupId,
    pub realm: RealmId,
}

impl GroupWorkload {
    pub fn new(realm: RealmId, gs: &hsm_api::GroupStatus) -> GroupWorkload {
        let leader = gs.leader.as_ref().map(|l| {
            let mut w = WorkAmount(2);
            if let Some(part) = &l.owned_range {
                let part_size = part.end.0[0] - part.start.0[0];
                w += WorkAmount(part_size as usize);
            }
            w
        });
        GroupWorkload {
            witness: WorkAmount(1),
            leader,
            last_captured: gs.captured.as_ref().map(|(idx, _mac)| *idx),
            members: gs.configuration.clone(),
            group: gs.id,
            realm,
        }
    }

    pub fn work(&self) -> WorkAmount {
        self.witness + self.leader.unwrap_or(WorkAmount(0))
    }
}

/// Represents the amount of work/load a task is estimated to consume. Larger is busier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WorkAmount(usize);

impl WorkAmount {
    pub fn new(v: usize) -> WorkAmount {
        WorkAmount(v)
    }

    pub fn abs_diff(&self, o: Self) -> Self {
        WorkAmount(self.0.abs_diff(o.0))
    }

    pub fn avg(iter: impl Iterator<Item = WorkAmount>) -> WorkAmount {
        let mut total = WorkAmount(0);
        let mut count = 0;
        for w in iter {
            total += w;
            count += 1;
        }
        if count == 0 {
            WorkAmount(0)
        } else {
            WorkAmount((total.0 as f64 / count as f64) as usize)
        }
    }
}

impl std::fmt::Display for WorkAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::Add for WorkAmount {
    type Output = WorkAmount;

    fn add(self, rhs: Self) -> Self::Output {
        WorkAmount(self.0 + rhs.0)
    }
}

impl std::ops::Sub for WorkAmount {
    type Output = WorkAmount;

    fn sub(self, rhs: Self) -> Self::Output {
        WorkAmount(self.0.saturating_sub(rhs.0))
    }
}

impl std::ops::AddAssign for WorkAmount {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl std::ops::SubAssign for WorkAmount {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0
    }
}

impl std::iter::Sum for WorkAmount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut t = WorkAmount(0);
        for w in iter {
            t += w;
        }
        t
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use super::*;

    #[test]
    fn workload_avg() {
        assert_eq!(
            WorkAmount::new(10),
            WorkAmount::avg([10, 5, 15].into_iter().map(WorkAmount::new))
        );
        assert_eq!(
            WorkAmount::new(11),
            WorkAmount::avg([30, 1, 4].into_iter().map(WorkAmount::new))
        );
        assert_eq!(WorkAmount::new(0), WorkAmount::avg(iter::empty()));
    }

    #[test]
    fn workload_sum() {
        assert_eq!(
            WorkAmount::new(100),
            [50, 10, 1, 15, 4, 12, 8]
                .into_iter()
                .map(WorkAmount::new)
                .sum()
        );
        assert_eq!(WorkAmount::new(0), iter::empty().sum())
    }
}
