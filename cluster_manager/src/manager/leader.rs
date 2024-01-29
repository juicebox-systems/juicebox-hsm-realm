use std::cmp::Ordering;
use std::collections::HashMap;
use tracing::{info, instrument, trace, warn};

use super::{ManagementGrant, Manager};
use agent_api::{BecomeLeaderRequest, BecomeLeaderResponse};
use cluster_core::workload::{HsmWorkload, WorkAmount};
use cluster_core::{discover_hsm_statuses, Error, HsmStatuses};
use hsm_api::{GroupId, HsmId, LogIndex};
use juicebox_networking::rpc::{self, RpcError};
use juicebox_realm_api::types::RealmId;
use service_core::http::ReqwestClientMetrics;

impl Manager {
    #[instrument(level = "trace", skip(self))]
    pub(super) async fn ensure_groups_have_leader(&self) -> Result<(), Error> {
        let hsm_status = discover_hsm_statuses(&self.0.store, &self.0.agents).await?;

        let mut groups: HashMap<(RealmId, GroupId), Option<HsmId>> = HashMap::new();
        for (hsm, _url) in hsm_status.values() {
            if let Some(realm) = &hsm.realm {
                for g in &realm.groups {
                    if g.leader.is_some() {
                        groups.insert((realm.id, g.id), Some(hsm.id));
                    } else {
                        groups.entry((realm.id, g.id)).or_insert(None);
                    }
                }
            }
        }

        trace!(count=?groups.len(), "found groups");

        for ((realm_id, group_id), _leader) in
            groups.into_iter().filter(|(_, leader)| leader.is_none())
        {
            info!(?group_id, ?realm_id, "Group has no leader");
            // TODO: hsm_status is out of date after the first assignment.
            match self.mark_as_busy(realm_id, group_id).await {
                Ok(None) => {
                    info!(
                        ?group_id,
                        ?realm_id,
                        "Skipping group being managed by some other task"
                    );
                }
                Ok(Some(grant)) => {
                    // This group doesn't have a leader, we'll pick one and ask it to become leader.
                    assign_group_a_leader(
                        &self.0.agents,
                        realm_id,
                        group_id,
                        &grant,
                        None,
                        &hsm_status,
                        None,
                    )
                    .await?;
                }
                Err(err) => {
                    warn!(?err, "GRPC error trying to obtain lease");
                }
            }
        }
        Ok(())
    }
}

/// Assigns a new leader for the group, using our workload scoring. The caller
/// is responsible for deciding that the group needs a leader.
#[instrument(level = "trace", skip_all)]
pub(super) async fn assign_group_a_leader(
    agent_client: &ReqwestClientMetrics,
    realm: RealmId,
    group: GroupId,
    _: &ManagementGrant,
    skipping: Option<HsmId>,
    hsm_status: &HsmStatuses,
    last: Option<LogIndex>,
) -> Result<Option<HsmId>, RpcError> {
    // We calculate a score for each group member based on how much work we
    // think its doing. Then use that to control the order in which we try to
    // make a member the leader.
    let group_members = &hsm_status
        .values()
        .filter_map(|(sr, _url)| sr.realm.as_ref())
        .filter(|rs| rs.id == realm)
        .flat_map(|rs| rs.groups.iter())
        .find(|gs| gs.id == group)
        .unwrap()
        .configuration;

    let mut scored: Vec<Score> = hsm_status
        .values()
        .filter(|(status, _url)| skipping != Some(status.id) && group_members.contains(&status.id))
        .flat_map(|(status, _url)| {
            HsmWorkload::new(status).map(|w| Score {
                id: w.id,
                workload: w.work(),
                last_captured: w
                    .groups
                    .iter()
                    .find(|g| g.group == group && g.realm == realm)
                    .map(|g| g.last_captured)
                    .unwrap_or_default(),
            })
        })
        .collect();

    scored.sort();

    let mut last_result: Result<Option<HsmId>, RpcError> = Ok(None);

    for hsm_id in scored.into_iter().map(|s| s.id) {
        if let Some((_, url)) = hsm_status.get(&hsm_id) {
            info!(?hsm_id, ?realm, ?group, "Asking hsm to become leader");
            match rpc::send(
                agent_client,
                url,
                BecomeLeaderRequest { realm, group, last },
            )
            .await
            {
                Ok(BecomeLeaderResponse::Ok) => {
                    info!(?hsm_id, ?realm, ?group, "Now leader");
                    return Ok(Some(hsm_id));
                }
                Ok(reply) => {
                    warn!(?reply, "BecomeLeader replied not okay");
                }
                Err(e) => {
                    warn!(err=?e, "BecomeLeader error");
                    last_result = Err(e);
                }
            }
        }
    }
    last_result
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Score {
    // total workload on the HSM
    workload: WorkAmount,
    last_captured: Option<LogIndex>,
    id: HsmId,
}

impl Ord for Score {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.workload.cmp(&other.workload) {
            Ordering::Equal => {}
            ord => return ord,
        }
        other.last_captured.cmp(&self.last_captured)
    }
}

impl PartialOrd for Score {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::{Score, WorkAmount};
    use hsm_api::{HsmId, LogIndex};

    #[test]
    fn score_order() {
        let a = Score {
            workload: WorkAmount::new(20),
            last_captured: Some(LogIndex(14)),
            id: HsmId([1; 16]),
        };
        let b = Score {
            workload: WorkAmount::new(10),
            last_captured: Some(LogIndex(13)),
            id: HsmId([2; 16]),
        };
        let c = Score {
            workload: WorkAmount::new(10),
            last_captured: Some(LogIndex(1)),
            id: HsmId([3; 16]),
        };
        let d = Score {
            workload: WorkAmount::new(10),
            last_captured: None,
            id: HsmId([4; 16]),
        };
        let e = Score {
            workload: WorkAmount::new(42),
            last_captured: Some(LogIndex(1)),
            id: HsmId([5; 16]),
        };
        let mut scores = vec![a.clone(), b.clone(), c.clone(), d.clone(), e.clone()];
        scores.sort();
        assert_eq!(vec![b, c, d, a, e], scores);
    }
}
