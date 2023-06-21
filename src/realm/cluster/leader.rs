use futures::future::join_all;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::iter::zip;
use tracing::{info, trace, warn};
use url::Url;

use super::super::super::http_client::Client;
use super::super::agent::types::{
    AgentService, BecomeLeaderRequest, BecomeLeaderResponse, StatusRequest, StatusResponse,
};
use super::super::store::bigtable::StoreClient;
use super::{Error, ManagementGrant, Manager};
use hsm_types::{GroupId, HsmId, LogIndex};
use hsmcore::hsm::types as hsm_types;
use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_networking::rpc::{self, RpcError};

impl Manager {
    pub(super) async fn ensure_groups_have_leader(&self) -> Result<(), Error> {
        trace!("checking that all groups have a leader");
        let addresses = self.0.store.get_addresses().await?;
        let hsm_status =
            super::get_hsm_statuses(&self.0.agents, addresses.iter().map(|(_, url)| url)).await;

        let mut groups: HashMap<GroupId, (Vec<HsmId>, RealmId, Option<HsmId>)> = HashMap::new();
        for (hsm, _url) in hsm_status.values() {
            if let Some(realm) = &hsm.realm {
                for g in &realm.groups {
                    groups
                        .entry(g.id)
                        .or_insert_with(|| (g.configuration.clone(), realm.id, None));
                    if let Some(_leader) = &g.leader {
                        groups.entry(g.id).and_modify(|v| v.2 = Some(hsm.id));
                    }
                }
            }
        }

        trace!(count=?groups.len(), "found groups");

        for (group_id, (config, realm_id, _)) in groups
            .into_iter()
            .filter(|(_, (_, _, leader))| leader.is_none())
        {
            info!(?group_id, ?realm_id, "Group has no leader");
            match self.mark_as_busy(realm_id, group_id) {
                None => {
                    info!(
                        ?group_id,
                        ?realm_id,
                        "Skipping group being managed by some other task"
                    );
                }
                Some(grant) => {
                    // This group doesn't have a leader, we'll pick one and ask it to become leader.
                    assign_group_a_leader(&self.0.agents, &grant, config, None, &hsm_status, None)
                        .await?;
                }
            }
        }
        Ok(())
    }
}

pub async fn find_leaders(
    store: &StoreClient,
    agent_client: &Client<AgentService>,
) -> Result<HashMap<(RealmId, GroupId), (HsmId, Url)>, tonic::Status> {
    trace!("refreshing cluster information");
    let addresses = store.get_addresses().await?;

    let responses = join_all(
        addresses
            .iter()
            .map(|(_, address)| rpc::send(agent_client, address, StatusRequest {})),
    )
    .await;

    let mut leaders: HashMap<(RealmId, GroupId), (HsmId, Url)> = HashMap::new();
    for ((_, agent), response) in zip(addresses, responses) {
        match response {
            Ok(StatusResponse {
                hsm:
                    Some(hsm_types::StatusResponse {
                        realm: Some(status),
                        id: hsm_id,
                        ..
                    }),
                ..
            }) => {
                for group in status.groups {
                    if group.leader.is_some() {
                        leaders.insert((status.id, group.id), (hsm_id, agent.clone()));
                    }
                }
            }

            Ok(_) => {}

            Err(err) => {
                warn!(%agent, ?err, "could not get status");
            }
        }
    }
    trace!("done refreshing cluster information");
    Ok(leaders)
}

/// Assigns a new leader for the group, using our workload scoring. The caller
/// is responsible for deciding that the group needs a leader.
pub(super) async fn assign_group_a_leader(
    agent_client: &Client<AgentService>,
    grant: &ManagementGrant<'_>,
    config: Vec<HsmId>,
    skipping: Option<HsmId>,
    hsm_status: &HashMap<HsmId, (hsm_types::StatusResponse, Url)>,
    last: Option<LogIndex>,
) -> Result<Option<HsmId>, RpcError> {
    // We calculate a score for each group member based on how much work we
    // think its doing. Then use that to control the order in which we try to
    // make a member the leader.
    let mut scored: Vec<Score> = config
        .into_iter()
        .filter(|id| match skipping {
            Some(hsm) if *id == hsm => false,
            None | Some(_) => true,
        })
        .filter_map(|id| hsm_status.get(&id))
        .map(|(m, _)| score(&grant.group, m))
        .collect();
    scored.sort();

    let mut last_result: Result<Option<HsmId>, RpcError> = Ok(None);

    for hsm_id in scored.into_iter().map(|s| s.id) {
        if let Some((_, url)) = hsm_status.get(&hsm_id) {
            info!(?hsm_id, realm=?grant.realm, group=?grant.group, "Asking hsm to become leader");
            match rpc::send(
                agent_client,
                url,
                BecomeLeaderRequest {
                    realm: grant.realm,
                    group: grant.group,
                    last,
                },
            )
            .await
            {
                Ok(BecomeLeaderResponse::Ok) => {
                    info!(?hsm_id, realm=?grant.realm, group=?grant.group, "Now leader");
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

fn score(group: &GroupId, m: &hsm_types::StatusResponse) -> Score {
    let mut work: usize = 0;
    let mut last_captured = None;
    if let Some(r) = &m.realm {
        // group member scores +1, leader scores + 2 + MSB of the partition size. (0-255)
        for g in &r.groups {
            work += 1;
            if let Some(leader) = &g.leader {
                work += 2;
                if let Some(part) = &leader.owned_range {
                    let part_size = part.end.0[0] - part.start.0[0];
                    work += part_size as usize;
                }
            }
            if g.id == *group {
                last_captured = g.captured.as_ref().map(|(index, _)| *index);
            }
        }
    }
    Score {
        workload: work,
        last_captured,
        id: m.id,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Score {
    // larger is busier
    workload: usize,
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
mod test {
    use super::Score;
    use hsmcore::hsm::types::{HsmId, LogIndex};

    #[test]
    fn score_order() {
        let a = Score {
            workload: 20,
            last_captured: Some(LogIndex(14)),
            id: HsmId([1; 16]),
        };
        let b = Score {
            workload: 10,
            last_captured: Some(LogIndex(13)),
            id: HsmId([2; 16]),
        };
        let c = Score {
            workload: 10,
            last_captured: Some(LogIndex(1)),
            id: HsmId([3; 16]),
        };
        let d = Score {
            workload: 10,
            last_captured: None,
            id: HsmId([4; 16]),
        };
        let e = Score {
            workload: 42,
            last_captured: Some(LogIndex(1)),
            id: HsmId([5; 16]),
        };
        let mut scores = vec![a.clone(), b.clone(), c.clone(), d.clone(), e.clone()];
        scores.sort();
        assert_eq!(vec![b, c, d, a, e], scores);
    }
}
