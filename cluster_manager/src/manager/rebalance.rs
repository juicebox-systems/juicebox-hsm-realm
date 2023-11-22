use cluster_api::RebalancedLeader;
use std::collections::HashMap;
use tracing::{info, warn};
use url::Url;

use super::{HsmWorkload, Manager, WorkAmount};
use agent_api::{BecomeLeaderRequest, BecomeLeaderResponse, StepDownRequest, StepDownResponse};
use cluster_core::get_hsm_statuses;
use hsm_api::{GroupId, HsmId};
use juicebox_networking::rpc::{self, RpcError};
use juicebox_realm_api::types::RealmId;
use service_core::rpc::HandlerError;
use store::ServiceKind;

#[derive(Debug)]
pub(super) enum RebalanceError {
    NoStore,
    StepDownFailed,
    LeadershipTransferFailed,
    LeadershipTransferRolledBack,
    Busy(RealmId, GroupId),
    Rpc(RpcError),
}

impl From<RpcError> for RebalanceError {
    fn from(value: RpcError) -> Self {
        RebalanceError::Rpc(value)
    }
}

impl Manager {
    pub(super) async fn handle_rebalance(
        &self,
        _req: cluster_api::RebalanceRequest,
    ) -> Result<cluster_api::RebalanceResponse, HandlerError> {
        type Response = cluster_api::RebalanceResponse;

        match self.rebalance_work().await {
            Ok(None) => Ok(Response::AlreadyBalanced),
            Ok(Some(r)) => Ok(Response::Rebalanced(r)),
            Err(RebalanceError::NoStore) => Ok(Response::NoStore),
            Err(RebalanceError::Rpc(rpc)) => Ok(Response::RpcError(rpc)),
            Err(RebalanceError::Busy(realm, group)) => Ok(Response::Busy { realm, group }),
            Err(RebalanceError::LeadershipTransferRolledBack) => {
                Ok(Response::LeadershipTransferRolledBack)
            }
            Err(RebalanceError::LeadershipTransferFailed) => Ok(Response::LeadershipTransferFailed),
            Err(RebalanceError::StepDownFailed) => Ok(Response::StepDownFailed),
        }
    }

    /// Performs a single rebalance pass on the cluster. To take full advantage
    /// of all the capacity of the HSMs in the cluster we'd like the total
    /// workload to be evenly spread across them. This looks to see if there a
    /// group leadership role that can be moved to a different HSM so that the
    /// work is more evenly spread across the HSMs. If it finds a possible move
    /// it handles the leadership handoff between the two HSMs. See
    /// [`next_rebalance()`] for more details on how it determines what to move.
    pub(super) async fn rebalance_work(&self) -> Result<Option<RebalancedLeader>, RebalanceError> {
        let addresses = self
            .0
            .store
            .get_addresses(Some(ServiceKind::Agent))
            .await
            .map_err(|_| RebalanceError::NoStore)?;

        let hsm_status =
            get_hsm_statuses(&self.0.agents, addresses.iter().map(|(url, _)| url)).await;

        let hsm_urls: HashMap<HsmId, Url> = hsm_status
            .iter()
            .map(|(id, (_sr, url))| (*id, url.clone()))
            .collect();

        let mut hsm_workloads: Vec<HsmWorkload> = hsm_status
            .into_iter()
            .flat_map(|(_, (sr, _))| HsmWorkload::new(&sr))
            .collect();

        if let Some(rebalance) = next_rebalance(&mut hsm_workloads) {
            let (realm, group) = rebalance.leader;
            let grant = self
                .mark_as_busy(realm, group)
                .await
                .map_err(|_| RebalanceError::NoStore)?;

            if grant.is_none() {
                info!(?realm, ?group, "group busy, skipping re-balance attempt");
                return Err(RebalanceError::Busy(realm, group));
            };
            info!(?realm, ?group, from=?rebalance.from, to=?rebalance.to, "rebalance is moving group leadership");
            match rpc::send(
                &self.0.agents,
                &hsm_urls[&rebalance.from],
                StepDownRequest { realm, group },
            )
            .await?
            {
                StepDownResponse::Ok { last } => {
                    match rpc::send(
                        &self.0.agents,
                        &hsm_urls[&rebalance.to],
                        BecomeLeaderRequest {
                            realm,
                            group,
                            last: Some(last),
                        },
                    )
                    .await?
                    {
                        BecomeLeaderResponse::Ok => {
                            info!(?realm, ?group, from=?rebalance.from, to=?rebalance.to, "rebalanced group leader");
                            return Ok(Some(RebalancedLeader {
                                realm,
                                group,
                                from: rebalance.from,
                                to: rebalance.to,
                            }));
                        }
                        n => {
                            warn!(
                                ?realm,
                                ?group,
                                from=?rebalance.from, to=?rebalance.to,
                                ?n,
                                "destination did not become new leader"
                            );
                            // try and make the original leader leader again.
                            match rpc::send(
                                &self.0.agents,
                                &hsm_urls[&rebalance.from],
                                BecomeLeaderRequest {
                                    realm,
                                    group,
                                    last: Some(last),
                                },
                            )
                            .await?
                            {
                                BecomeLeaderResponse::Ok => {
                                    warn!(?realm, ?group, leader=?rebalance.from, "leadership change rolled back to original location");
                                    return Err(RebalanceError::LeadershipTransferRolledBack);
                                }
                                n => {
                                    warn!(
                                        ?realm,
                                        ?group,
                                        to=?rebalance.from,
                                        ?n,
                                        "did not become leader"
                                    );
                                    // give the regular leadership assignment a pass at it.
                                    drop(grant);
                                    _ = self.ensure_groups_have_leader().await;
                                    return Err(RebalanceError::LeadershipTransferFailed);
                                }
                            }
                        }
                    }
                }
                response => {
                    warn!(?response, ?realm, ?group, from=?rebalance.from, "stepdown not okay");
                    return Err(RebalanceError::StepDownFailed);
                }
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Rebalance {
    leader: (RealmId, GroupId),
    from: HsmId,
    to: HsmId,
}

/// Returns a group leadership move that would make the workload across the HSMs
/// more even. The workload for a HSM is relative to number of groups its a
/// member of. The workload for a particular group on a HSM depends on if the
/// HSM is leader and the size of the key range that the group owns.
///
/// This looks for a group leadership workload that can be moved that would
/// result in the 2 HSMs involved having total workloads closer to the overall
/// average after the move. The algorithm is stable in that it will only make
/// moves that improve the balance. It may take multiple moves to get to a final
/// configuration, but it should settle into a stable state. It is also
/// deterministic such that if multiple cluster managers call this at the same
/// time they'll get the same result. This means they fight over the lease as to
/// who makes the change, rather than the managers simultaneously moving the
/// workloads in different directions.
fn next_rebalance(mut hsm_workloads: &mut [HsmWorkload]) -> Option<Rebalance> {
    if hsm_workloads.len() < 2 {
        return None;
    }
    hsm_workloads.sort_by_key(HsmWorkload::work);
    while hsm_workloads.len() >= 2 {
        let total: WorkAmount = hsm_workloads.iter().map(|w| w.work()).sum();
        let avg = WorkAmount((total.0 as f64 / hsm_workloads.len() as f64) as usize);

        let busiest = hsm_workloads.last().unwrap();
        let busiest_work = busiest.work();
        assert!(busiest_work >= avg);
        // We examine workloads to move in order of how close to the average
        // workload the HSM would have after the move.
        let target_move_size = busiest_work - avg;
        let mut moveable = busiest.moveable_workloads();
        moveable.sort_by_key(|w| target_move_size.abs_diff(w.work()));

        for to_move in moveable {
            if let Some(dest) = hsm_workloads
                .iter()
                .filter(|dest| {
                    dest.work() + to_move.work() < busiest_work && dest.can_lead(to_move)
                })
                .min_by_key(|dest| dest.work())
            {
                return Some(Rebalance {
                    leader: (to_move.realm, to_move.group),
                    from: busiest.id,
                    to: dest.id,
                });
            }
        }
        // Under some scenario's it may not be possible to move anything off the
        // busiest node, but the remaining nodes may be unbalanced. So retry
        // with the busiest one removed. e.g. If you have a large group that
        // can't currently be moved and bunch of smaller groups that can.
        let len = hsm_workloads.len();
        hsm_workloads = &mut hsm_workloads[..len - 1];
    }
    None
}

#[cfg(test)]
mod tests {
    use hsm_api::LogIndex;

    use super::super::GroupWorkload;
    use super::*;

    const REALM: RealmId = RealmId([1; 16]);

    // 3 hsms, 3 groups.
    // the unused single hsm group from the realm creation + 2 active groups
    #[test]
    fn rebalance_3() {
        let ids = vec![HsmId([1; 16]), HsmId([2; 16]), HsmId([3; 16])];
        let groups = make_test_groups(3, ids.clone());
        let mut workloads = vec![
            HsmWorkload {
                id: ids[0],
                groups: vec![
                    GroupWorkload {
                        leader: Some(WorkAmount(2)),
                        ..groups[0].clone()
                    },
                    GroupWorkload {
                        leader: Some(WorkAmount(2 + 0x080)),
                        ..groups[1].clone()
                    },
                    groups[2].clone(),
                ],
            },
            HsmWorkload {
                id: ids[1],
                groups: vec![
                    groups[1].clone(),
                    GroupWorkload {
                        leader: Some(WorkAmount(2 + 0x80)),
                        ..groups[2].clone()
                    },
                ],
            },
            HsmWorkload {
                id: ids[2],
                groups: vec![groups[1].clone(), groups[2].clone()],
            },
        ];
        let to_move = next_rebalance(&mut workloads);
        assert_eq!(
            Some(Rebalance {
                leader: (REALM, groups[1].group),
                from: ids[0],
                to: ids[2]
            }),
            to_move
        );
        // after applying the change, there shouldn't be anymore things to move
        apply_rebalance(&mut workloads, to_move);
        assert_eq!(None, next_rebalance(&mut workloads));
    }

    // 3 hsms, 3 groups, 1 hsm doing all the leadership.
    #[test]
    fn rebalance_1_to_3() {
        let ids = vec![HsmId([1; 16]), HsmId([2; 16]), HsmId([3; 16])];
        let realm = RealmId([1; 16]);
        let groups = make_test_groups(3, ids.clone());
        let mut workloads = vec![
            HsmWorkload {
                id: ids[0],
                groups: vec![
                    GroupWorkload {
                        leader: Some(WorkAmount(2)),
                        ..groups[0].clone()
                    },
                    GroupWorkload {
                        leader: Some(WorkAmount(2 + 0x80)),
                        ..groups[1].clone()
                    },
                    GroupWorkload {
                        leader: Some(WorkAmount(2 + 0x080)),
                        ..groups[2].clone()
                    },
                ],
            },
            HsmWorkload {
                id: ids[1],
                groups: vec![groups[1].clone(), groups[2].clone()],
            },
            HsmWorkload {
                id: ids[2],
                groups: vec![groups[1].clone(), groups[2].clone()],
            },
        ];
        let to_move = next_rebalance(&mut workloads);
        assert_eq!(
            Some(Rebalance {
                leader: (realm, groups[1].group),
                from: ids[0],
                to: ids[1]
            }),
            to_move
        );

        // 2nd pass should move another group
        apply_rebalance(&mut workloads, to_move);
        let to_move = next_rebalance(&mut workloads);
        assert_eq!(
            Some(Rebalance {
                leader: (realm, groups[2].group),
                from: ids[0],
                to: ids[2]
            }),
            to_move
        );
        // after applying the change, there shouldn't be anymore things to move
        apply_rebalance(&mut workloads, to_move);
        assert_eq!(None, next_rebalance(&mut workloads));
    }

    // 3 hsms, 6 groups of different sizes, check the optimally sized one is moved
    #[test]
    fn rebalance_size_selection() {
        let ids = vec![HsmId([1; 16]), HsmId([2; 16]), HsmId([3; 16])];
        let groups = make_test_groups(6, ids.clone());
        let mut workloads = vec![
            HsmWorkload {
                id: ids[0],
                groups: vec![
                    GroupWorkload {
                        leader: Some(WorkAmount(2)),
                        ..groups[0].clone()
                    },
                    GroupWorkload {
                        leader: Some(WorkAmount(2 + 0x10)),
                        ..groups[1].clone()
                    },
                    GroupWorkload {
                        leader: Some(WorkAmount(2 + 0x040)),
                        ..groups[2].clone()
                    },
                    GroupWorkload {
                        leader: Some(WorkAmount(2 + 0x50)),
                        ..groups[3].clone()
                    },
                    groups[4].clone(),
                    groups[5].clone(),
                ],
            },
            HsmWorkload {
                id: ids[1],
                groups: vec![
                    groups[0].clone(),
                    groups[1].clone(),
                    groups[2].clone(),
                    groups[3].clone(),
                    GroupWorkload {
                        leader: Some(WorkAmount(2 + 0x50)),
                        ..groups[4].clone()
                    },
                    groups[5].clone(),
                ],
            },
            HsmWorkload {
                id: ids[2],
                groups: vec![
                    groups[0].clone(),
                    groups[1].clone(),
                    groups[2].clone(),
                    groups[3].clone(),
                    groups[4].clone(),
                    GroupWorkload {
                        leader: Some(WorkAmount(2 + 0x30)),
                        ..groups[5].clone()
                    },
                ],
            },
        ];
        let to_move = next_rebalance(&mut workloads);
        assert_eq!(
            Some(Rebalance {
                leader: (REALM, groups[2].group),
                from: ids[0],
                to: ids[2]
            }),
            to_move
        );

        apply_rebalance(&mut workloads, to_move);
        let to_move = next_rebalance(&mut workloads);
        assert_eq!(
            Some(Rebalance {
                leader: (REALM, groups[1].group),
                from: ids[0],
                to: ids[1]
            }),
            to_move
        );

        apply_rebalance(&mut workloads, to_move);
        assert_eq!(None, next_rebalance(&mut workloads));
    }

    // verify that the rebalance is to another member of the group.
    #[test]
    fn moves_to_group_member() {
        let ids = vec![HsmId([1; 16]), HsmId([2; 16]), HsmId([3; 16])];
        let mut groups = make_test_groups(4, ids.clone());
        groups[1].members = vec![ids[0], ids[1]];
        groups[2].members = vec![ids[0], ids[2]];
        let mut workloads = vec![
            HsmWorkload {
                id: ids[0],
                groups: vec![
                    GroupWorkload {
                        leader: Some(WorkAmount(2)),
                        ..groups[0].clone()
                    },
                    GroupWorkload {
                        leader: Some(WorkAmount(2 + 0x10)),
                        ..groups[1].clone()
                    },
                    GroupWorkload {
                        leader: Some(WorkAmount(2 + 0x80)),
                        ..groups[2].clone()
                    },
                ],
            },
            HsmWorkload {
                id: ids[1],
                groups: vec![groups[1].clone(), groups[3].clone()],
            },
            HsmWorkload {
                id: ids[2],
                groups: vec![
                    groups[2].clone(),
                    GroupWorkload {
                        leader: Some(WorkAmount(2 + 0x10)),
                        ..groups[3].clone()
                    },
                ],
            },
        ];
        let to_move = next_rebalance(&mut workloads);
        assert_eq!(
            Some(Rebalance {
                leader: (REALM, groups[2].group),
                from: ids[0],
                to: ids[2]
            }),
            to_move
        );

        apply_rebalance(&mut workloads, to_move);
        let to_move = next_rebalance(&mut workloads);
        assert_eq!(
            Some(Rebalance {
                leader: (REALM, groups[3].group),
                from: ids[2],
                to: ids[1]
            }),
            to_move
        );

        // after applying the change, there shouldn't be anymore things to move
        apply_rebalance(&mut workloads, to_move);
        assert_eq!(None, next_rebalance(&mut workloads));
    }

    #[test]
    fn dont_rebalance_to_out_of_date_members() {
        let ids = vec![HsmId([1; 16]), HsmId([2; 16])];
        let groups = make_test_groups(2, ids.clone());
        let mut workloads = vec![
            HsmWorkload {
                id: ids[0],
                groups: vec![
                    GroupWorkload {
                        leader: Some(WorkAmount(2 + 0x40)),
                        ..groups[0].clone()
                    },
                    GroupWorkload {
                        leader: Some(WorkAmount(2 + 0x80)),
                        last_captured: Some(LogIndex(98_000)),
                        ..groups[1].clone()
                    },
                ],
            },
            HsmWorkload {
                id: ids[1],
                groups: vec![GroupWorkload {
                    last_captured: Some(LogIndex(90_000)),
                    ..groups[1].clone()
                }],
            },
        ];
        assert_eq!(None, next_rebalance(&mut workloads));

        let w = workloads.iter_mut().find(|w| w.id == ids[1]).unwrap();
        w.groups[0].last_captured = Some(LogIndex(97_123));
        assert_eq!(
            Some(Rebalance {
                leader: (REALM, groups[1].group),
                from: ids[0],
                to: ids[1],
            }),
            next_rebalance(&mut workloads)
        );
    }

    // Creates 'num' GroupWorkloads each with the supplied member HsmIds. The
    // first group will only have the first HSM as its members, matching the
    // single node group that is created as part of realm creation.
    fn make_test_groups(num: u8, members: Vec<HsmId>) -> Vec<GroupWorkload> {
        let mut groups = (0..num)
            .map(|i| GroupWorkload {
                witness: WorkAmount(1),
                leader: None,
                members: members.clone(),
                last_captured: Some(LogIndex(i as u64 * 10_000)),
                group: GroupId([i; 16]),
                realm: REALM,
            })
            .collect::<Vec<_>>();
        groups[0].members = vec![members[0]];
        groups
    }

    fn apply_rebalance(workloads: &mut [HsmWorkload], rebalance: Option<Rebalance>) {
        if let Some(rebalance) = rebalance {
            let from = workloads
                .iter_mut()
                .find(|w| w.id == rebalance.from)
                .unwrap();
            let group_idx = from
                .groups
                .iter()
                .position(|w| (w.realm, w.group) == rebalance.leader)
                .unwrap();
            let leader = from.groups[group_idx].leader.take();

            let to = workloads.iter_mut().find(|w| w.id == rebalance.to).unwrap();
            let group_idx = to
                .groups
                .iter()
                .position(|w| (w.realm, w.group) == rebalance.leader)
                .unwrap();
            to.groups[group_idx].leader = leader;
        }
    }
}
