use futures::future::join_all;
use futures::FutureExt;
use std::collections::HashMap;
use std::iter::zip;
use tracing::{info, warn};
use url::Url;

use super::{ManagementGrant, Manager};
use cluster_core::{discover_hsm_ids, get_hsm_statuses};
use hsm_api::{GroupId, HsmId, LogIndex};
use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_networking::rpc::{self, RpcError};
use service_core::rpc::HandlerError;

impl Manager {
    pub(super) async fn handle_leader_stepdown(
        &self,
        req: cluster_api::StepDownRequest,
    ) -> Result<cluster_api::StepDownResponse, HandlerError> {
        type Response = cluster_api::StepDownResponse;

        let addresses: HashMap<HsmId, Url> =
            match discover_hsm_ids(&self.0.store, &self.0.agents).await {
                Ok(it) => it.collect(),
                Err(_) => return Ok(Response::NoStore),
            };

        // Calculate the exact set of step downs needed.
        let stepdowns = match self.resolve_stepdowns(&req, &addresses).await {
            Err(e) => return Ok(e),
            Ok(sd) => sd,
        };
        let mut grants = Vec::with_capacity(stepdowns.len());
        for stepdown in &stepdowns {
            match self.mark_as_busy(stepdown.realm, stepdown.group) {
                None => {
                    return Ok(Response::Busy {
                        realm: stepdown.realm,
                        group: stepdown.group,
                    })
                }
                Some(grant) => grants.push(grant),
            }
        }

        for (stepdown, grant) in zip(stepdowns, grants) {
            info!(
                url=%stepdown.url,
                hsm=?stepdown.hsm,
                group=?stepdown.group,
                realm=?stepdown.realm,
                "Asking agent/HSM to step down as leader",
            );
            match rpc::send(
                &self.0.agents,
                &stepdown.url,
                agent_api::StepDownRequest {
                    realm: stepdown.realm,
                    group: stepdown.group,
                },
            )
            .await
            {
                Err(err) => return Ok(Response::RpcError(err)),
                Ok(agent_api::StepDownResponse::NoHsm) => return Ok(Response::NoHsm),
                Ok(agent_api::StepDownResponse::InvalidGroup) => return Ok(Response::InvalidGroup),
                Ok(agent_api::StepDownResponse::InvalidRealm) => return Ok(Response::InvalidRealm),
                Ok(agent_api::StepDownResponse::NotLeader) => return Ok(Response::NotLeader),
                Ok(agent_api::StepDownResponse::Ok { last }) => {
                    if let Err(err) = self
                        .assign_leader_post_stepdown(&addresses, &grant, stepdown, Some(last))
                        .await
                    {
                        return Ok(Response::RpcError(err));
                    }
                }
            }
        }
        Ok(Response::Ok)
    }

    /// Leader stepdown was completed, assign a new one.
    async fn assign_leader_post_stepdown(
        &self,
        addresses: &HashMap<HsmId, Url>,
        grant: &ManagementGrant<'_>,
        stepdown: Stepdown,
        last: Option<LogIndex>,
    ) -> Result<Option<HsmId>, RpcError> {
        let hsm_status = get_hsm_statuses(
            &self.0.agents,
            stepdown.config.iter().filter_map(|hsm| addresses.get(hsm)),
        )
        .await;

        super::leader::assign_group_a_leader(
            &self.0.agents,
            grant,
            stepdown.config,
            Some(stepdown.hsm),
            &hsm_status,
            last,
        )
        .await
    }

    async fn resolve_stepdowns(
        &self,
        req: &cluster_api::StepDownRequest,
        addresses: &HashMap<HsmId, Url>,
    ) -> Result<Vec<Stepdown>, cluster_api::StepDownResponse> {
        match req {
            cluster_api::StepDownRequest::Hsm(hsm) => match addresses.get(hsm) {
                None => {
                    warn!(?hsm, "failed to find HSM in service discovery");
                    Err(cluster_api::StepDownResponse::InvalidHsm)
                }

                Some(url) => {
                    match rpc::send(&self.0.agents, url, agent_api::StatusRequest {}).await {
                        Err(err) => {
                            warn!(?err, %url, ?hsm, "failed to get status of HSM");
                            Err(cluster_api::StepDownResponse::RpcError(err))
                        }
                        Ok(agent_api::StatusResponse {
                            hsm:
                                Some(hsm_api::StatusResponse {
                                    id,
                                    realm: Some(rs),
                                    ..
                                }),
                            ..
                        }) if id == *hsm => Ok(rs
                            .groups
                            .into_iter()
                            .filter_map(|gs| {
                                gs.leader.map(|_| Stepdown {
                                    hsm: *hsm,
                                    url: url.clone(),
                                    group: gs.id,
                                    realm: rs.id,
                                    config: gs.configuration,
                                })
                            })
                            .collect()),
                        Ok(_s) => {
                            info!(?hsm, %url, "HSM is not a member of a realm");
                            Ok(Vec::new())
                        }
                    }
                }
            },

            cluster_api::StepDownRequest::Group { realm, group } => {
                Ok(join_all(addresses.iter().map(|(_hsm, url)| {
                    rpc::send(&self.0.agents, url, agent_api::StatusRequest {})
                        .map(|r| (r, url.clone()))
                }))
                .await
                .into_iter()
                .filter_map(|(s, url)| {
                    if let Some((hsm_id, realm_status)) = s
                        .ok()
                        .and_then(|s| s.hsm)
                        .and_then(|hsm| hsm.realm.map(|r| (hsm.id, r)))
                    {
                        if realm_status.id == *realm {
                            for g in realm_status.groups {
                                if g.id == *group && g.leader.is_some() {
                                    return Some(Stepdown {
                                        hsm: hsm_id,
                                        url,
                                        group: *group,
                                        realm: *realm,
                                        config: g.configuration,
                                    });
                                }
                            }
                        }
                    }
                    None
                })
                .collect())
            }
        }
    }
}

struct Stepdown {
    hsm: HsmId,
    url: Url,
    group: GroupId,
    realm: RealmId,
    config: Vec<HsmId>,
}
