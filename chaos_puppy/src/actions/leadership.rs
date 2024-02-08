use anyhow::{anyhow, Context};
use async_trait::async_trait;
use rand::seq::{IteratorRandom, SliceRandom};
use rand_core::OsRng;
use thiserror::Error;
use tracing::info;

use super::{cluster_manager, find_groups, Puppy};
use agent_api::BecomeLeaderResponse;
use cluster_api::StepDownResponse;
use cluster_core::discover_hsm_statuses;
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc;
use store::StoreClient;

// This uses the cluster manager to do a coordinated leadership transfer. This
// is what happens when an agent is cleanly shutdown, or during cluster
// rebalancing.
#[derive(Debug)]
pub struct GracefulStepdown;

#[async_trait]
impl Puppy for GracefulStepdown {
    async fn run(&self, store: &StoreClient, client: &Client) -> anyhow::Result<()> {
        let statuses = discover_hsm_statuses(store, client).await?;
        let groups = find_groups(&statuses);

        let Some(target) = groups.choose(&mut OsRng) else {
            return Err(anyhow!("no replication groups found via service discovery"));
        };
        let cluster_manager = cluster_manager(store).await?;

        info!(
            realm=?target.realm,
            group=?target.group,
            manager=%cluster_manager,
            "Asking cluster manager to stepdown group leader"
        );
        let result = rpc::send(
            client,
            &cluster_manager,
            cluster_api::StepDownRequest::Group {
                realm: target.realm,
                group: target.group,
            },
        )
        .await?;
        if !matches!(result, StepDownResponse::Ok) {
            return Err(StepDownError::ClusterManager(result))
                .context("asking cluster manager to perform a leadership step down");
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
enum StepDownError {
    #[error("cluster manager stepdown error: {0:?}")]
    ClusterManager(StepDownResponse),
    #[error("agent stepdown error: {0:?}")]
    Agent(agent_api::StepDownResponse),
}

#[derive(Debug, Error)]
#[error("become leader error: {0:?}")]
struct BecomeLeaderError(agent_api::BecomeLeaderResponse);

// This asks an agent directly to stepdown. The group will have no leader until
// the cluster manager spots it and fixes it. This is more disruptive than the
// above graceful stepdown.
#[derive(Debug)]
pub struct DirectAgentStepDown;

#[async_trait]
impl Puppy for DirectAgentStepDown {
    async fn run(&self, store: &StoreClient, client: &Client) -> anyhow::Result<()> {
        let statuses = discover_hsm_statuses(store, client).await?;
        let groups = find_groups(&statuses);

        let Some(target) = groups.choose(&mut OsRng) else {
            return Err(anyhow!("no replication groups found via service discovery"));
        };

        info!(realm=?target.realm, group=?target.group, agent=%target.agent,
            "asking leader agent to stepdown for group");
        let result = rpc::send(
            client,
            &target.agent,
            agent_api::StepDownRequest {
                realm: target.realm,
                group: target.group,
            },
        )
        .await?;
        if !matches!(result, agent_api::StepDownResponse::Ok { .. }) {
            return Err(StepDownError::Agent(result)).context("asking agent to stepdown");
        }
        Ok(())
    }
}

// This picks a random witness and asks it to become leader, creating a dueling
// leaders situation.
#[derive(Debug)]
pub struct BecomeLeader;

#[async_trait]
impl Puppy for BecomeLeader {
    async fn run(&self, store: &StoreClient, client: &Client) -> anyhow::Result<()> {
        let statuses = discover_hsm_statuses(store, client).await?;
        let Some((realm, group, url)) = statuses
            .values()
            .filter_map(|(s, url)| s.realm.as_ref().map(|r| (r, url)))
            .flat_map(|(r, url)| {
                r.groups
                    .iter()
                    .filter(|gs| gs.leader.is_none())
                    .map(|gs| (r.id, gs.id, url.clone()))
            })
            .choose(&mut OsRng)
        else {
            return Err(anyhow!(
                "No replication group witnesses found via service discovery"
            ));
        };

        info!(?realm, ?group, agent=%url, "asking agent to become leader");
        let result = rpc::send(
            client,
            &url,
            agent_api::BecomeLeaderRequest {
                realm,
                group,
                last: None,
            },
        )
        .await?;
        if !matches!(result, BecomeLeaderResponse::Ok) {
            return Err(BecomeLeaderError(result)).context("asking agent to become leader");
        }
        Ok(())
    }
}
