use futures::future::try_join_all;
use thiserror::Error;
use tracing::{debug, info};
use url::Url;

use agent_api::{
    JoinGroupRequest, JoinGroupResponse, JoinRealmRequest, JoinRealmResponse, NewGroupRequest,
    NewGroupResponse, NewRealmRequest, NewRealmResponse, StatusRequest,
};
use hsm_api::{GroupId, HsmId, HsmRealmStatement, GROUPS_LIMIT};
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc::{self, RpcError};
use juicebox_realm_api::types::RealmId;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum NewRealmError {
    #[error("RPC error: {0}")]
    NetworkError(RpcError),
    #[error("no HSM found")]
    NoHsm,
    #[error("HSM is already in a realm")]
    HaveRealm,
    #[error("error accessing Bigtable")]
    NoStore,
    #[error("could not create log entry in Bigtable: precondition failed")]
    StorePreconditionFailed,
}

pub async fn new_realm(
    agents_client: &Client,
    agent: &Url,
) -> Result<(RealmId, GroupId), NewRealmError> {
    type Error = NewRealmError;

    info!("setting up new realm");
    let hsm = match rpc::send(agents_client, agent, StatusRequest {})
        .await
        .map_err(Error::NetworkError)?
        .hsm
    {
        Some(hsm_status) => Ok(hsm_status.id),
        None => Err(Error::NoHsm),
    }?;

    debug!(?hsm, "requesting new realm");
    let (realm_id, group_id) = match rpc::send(agents_client, agent, NewRealmRequest {})
        .await
        .map_err(Error::NetworkError)?
    {
        NewRealmResponse::Ok { realm, group } => Ok((realm, group)),
        NewRealmResponse::NoHsm => Err(Error::NoHsm),
        NewRealmResponse::HaveRealm => Err(Error::HaveRealm),
        NewRealmResponse::NoStore => Err(Error::NoStore),
        NewRealmResponse::StorePreconditionFailed => Err(Error::StorePreconditionFailed),
    }?;
    debug!(?realm_id, ?group_id, "HSM created new realm");

    super::wait_for_commit(agent, realm_id, group_id, agents_client)
        .await
        .map_err(Error::NetworkError)?;
    info!(?realm_id, ?group_id, "realm initialization complete");
    Ok((realm_id, group_id))
}

#[derive(Debug, Error)]
pub enum JoinRealmError {
    #[error("RPC error: {0}")]
    NetworkError(RpcError),
    #[error("no HSM found at {agent}")]
    NoHsm { agent: Url },
    #[error("HSM at {agent} not in given realm or in different realm")]
    InvalidRealm { agent: Url },
    #[error("HSM at {agent} rejected realm keys statement")]
    InvalidStatement { agent: Url },
}

/// Requests a set of HSMs to join a realm.
///
/// `new` is a list of agent URLs with HSMs that will be joined to the `realm`.
/// It is OK if they are already members of the realm.
///
/// `existing` is an agent URL with an HSM that is already a member of `realm`.
pub async fn join_realm(
    agents_client: &Client,
    realm: RealmId,
    new: &[Url],
    existing: &Url,
) -> Result<(), JoinRealmError> {
    type Error = JoinRealmError;

    // Get HSM ID and HSM-realm statement from an existing agent/HSM.
    let (existing_hsm, statement): (HsmId, HsmRealmStatement) =
        match rpc::send(agents_client, existing, StatusRequest {})
            .await
            .map_err(Error::NetworkError)?
            .hsm
        {
            Some(hsm_status) => match hsm_status.realm {
                Some(realm_status) if realm_status.id == realm => {
                    Ok((hsm_status.id, realm_status.statement))
                }
                _ => Err(Error::InvalidRealm {
                    agent: existing.clone(),
                }),
            },
            None => Err(Error::NoHsm {
                agent: existing.clone(),
            }),
        }?;

    // Ask new agents/HSMs to join the realm.
    try_join_all(new.iter().map(|agent| async {
        let response = rpc::send(
            agents_client,
            agent,
            JoinRealmRequest {
                realm,
                peer: existing_hsm,
                statement: statement.clone(),
            },
        )
        .await
        .map_err(Error::NetworkError)?;

        match response {
            JoinRealmResponse::Ok { .. } => Ok(()),
            JoinRealmResponse::HaveOtherRealm => Err(Error::InvalidRealm {
                agent: agent.clone(),
            }),
            JoinRealmResponse::InvalidStatement => Err(Error::InvalidStatement {
                agent: agent.clone(),
            }),
            JoinRealmResponse::NoHsm => Err(Error::NoHsm {
                agent: agent.clone(),
            }),
        }
    }))
    .await?;

    Ok(())
}

#[derive(Debug, Error)]
pub enum NewGroupError {
    #[error("RPC error: {0}")]
    NetworkError(RpcError),
    #[error("no HSM found at {agent}")]
    NoHsm { agent: Url },
    #[error("HSM at {agent} not in given realm")]
    InvalidRealm { agent: Url },
    #[error("HSM at {agent} rejected realm keys statement")]
    InvalidHsmRealmStatement { agent: Url },
    #[error("invalid configuration")]
    InvalidConfiguration,
    #[error("invalid group statement")]
    InvalidGroupStatement,
    #[error("HSM at {agent} has too many groups")]
    TooManyGroups { agent: Url },
    #[error("error accessing Bigtable")]
    NoStore,
    #[error("could not create log entry in Bigtable: precondition failed")]
    StorePreconditionFailed,
}

/// Creates a new replication group within a realm.
///
/// `group` is a list of agent URLs. Each HSM attached to those agents must
/// already be a member of `realm`.
pub async fn new_group(
    agents_client: &Client,
    realm: RealmId,
    agents: &[Url],
) -> Result<GroupId, NewGroupError> {
    type Error = NewGroupError;
    info!(?realm, "setting up new group");

    // Ensure all HSMs are up, have joined the realm, and have capacity for
    // another group. Get their ID and statements to form the configuration.
    let mut hsms: Vec<(HsmId, HsmRealmStatement)> =
        try_join_all(agents.iter().map(|agent| async {
            let status = rpc::send(agents_client, agent, StatusRequest {})
                .await
                .map_err(Error::NetworkError)?;
            let Some(hsm_status) = status.hsm else {
                return Err(Error::NoHsm {
                    agent: agent.clone(),
                });
            };
            let Some(realm_status) = hsm_status.realm else {
                return Err(Error::InvalidRealm {
                    agent: agent.clone(),
                });
            };
            if realm_status.id != realm {
                return Err(Error::InvalidRealm {
                    agent: agent.clone(),
                });
            }
            if realm_status.groups.len() >= usize::from(GROUPS_LIMIT) {
                return Err(Error::TooManyGroups {
                    agent: agent.clone(),
                });
            }
            Ok((hsm_status.id, realm_status.statement))
        }))
        .await?;

    let first: HsmId = hsms[0].0; // located at agent group[0]
    hsms.sort_unstable_by(|(id1, _), (id2, _)| id1.cmp(id2));
    let configuration: Vec<HsmId> = hsms.iter().map(|(id, _)| *id).collect();

    debug!(
        ?hsms,
        "gathered group configuration and HSM-realm statements"
    );

    // Create a new group on the first agent.
    debug!(hsm = ?first, agent = %agents[0], "requesting new group");
    let (group_id, group_statement) = match rpc::send(
        agents_client,
        &agents[0],
        NewGroupRequest {
            realm,
            members: hsms,
        },
    )
    .await
    .map_err(Error::NetworkError)?
    {
        NewGroupResponse::Ok { group, statement } => Ok((group, statement)),
        NewGroupResponse::NoHsm => Err(Error::NoHsm {
            agent: agents[0].clone(),
        }),
        NewGroupResponse::InvalidRealm => Err(Error::InvalidRealm {
            agent: agents[0].clone(),
        }),
        NewGroupResponse::InvalidConfiguration => Err(Error::InvalidConfiguration),
        NewGroupResponse::InvalidStatement => Err(Error::InvalidHsmRealmStatement {
            agent: agents[0].clone(),
        }),
        NewGroupResponse::TooManyGroups => Err(Error::TooManyGroups {
            agent: agents[0].clone(),
        }),
        NewGroupResponse::NoStore => Err(Error::NoStore),
        NewGroupResponse::StorePreconditionFailed => Err(Error::StorePreconditionFailed),
    }?;
    debug!(?realm, group = ?group_id, "first HSM created new group");

    // Request each of the other agents to join the new group.
    try_join_all(agents[1..].iter().map(|agent| {
        let configuration = configuration.clone();
        let group_statement = group_statement.clone();
        async {
            match rpc::send(
                agents_client,
                agent,
                JoinGroupRequest {
                    realm,
                    group: group_id,
                    configuration,
                    statement: group_statement,
                },
            )
            .await
            .map_err(Error::NetworkError)?
            {
                JoinGroupResponse::Ok => Ok(()),
                JoinGroupResponse::InvalidRealm => Err(Error::InvalidRealm {
                    agent: agent.clone(),
                }),
                JoinGroupResponse::InvalidConfiguration => Err(Error::InvalidConfiguration),
                JoinGroupResponse::InvalidStatement => Err(Error::InvalidGroupStatement),
                JoinGroupResponse::TooManyGroups => Err(Error::TooManyGroups {
                    agent: agent.clone(),
                }),
                JoinGroupResponse::NoHsm => Err(Error::NoHsm {
                    agent: agent.clone(),
                }),
            }
        }
    }))
    .await?;

    // Wait for the new group to commit the first log entry.
    super::wait_for_commit(&agents[0], realm, group_id, agents_client)
        .await
        .map_err(Error::NetworkError)?;
    debug!(?realm, group = ?group_id, "group initialization complete");
    Ok(group_id)
}
