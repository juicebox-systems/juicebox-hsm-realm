use futures::future::try_join_all;
use tracing::{debug, info};
use url::Url;

use super::super::super::http_client::{Client, ClientOptions};
use super::super::agent::types::{
    JoinGroupRequest, JoinGroupResponse, JoinRealmRequest, JoinRealmResponse, NewGroupRequest,
    NewGroupResponse, NewRealmRequest, NewRealmResponse, StatusRequest,
};
use hsm_types::{Configuration, GroupId, HsmId};
use hsmcore::hsm::types as hsm_types;
use loam_sdk_core::types::RealmId;
use loam_sdk_networking::rpc::{self, RpcError};

#[derive(Debug)]
pub enum NewRealmError {
    NetworkError(RpcError),
    NoHsm { agent: Url },
    HaveRealm { agent: Url },
    InvalidConfiguration,
    InvalidGroupStatement,
    NoStore,
    StorePreconditionFailed,
}

pub async fn new_realm(group: &[Url]) -> Result<(RealmId, GroupId), NewRealmError> {
    type Error = NewRealmError;
    info!("setting up new realm");
    let agent_client = Client::new(ClientOptions::default());

    let hsms = try_join_all(
        group
            .iter()
            .map(|agent| rpc::send(&agent_client, agent, StatusRequest {})),
    )
    .await
    .map_err(Error::NetworkError)?
    .iter()
    .zip(group)
    .map(|(resp, agent)| match &resp.hsm {
        Some(hsm_status) => Ok(hsm_status.id),
        None => Err(Error::NoHsm {
            agent: agent.clone(),
        }),
    })
    .collect::<Result<Vec<HsmId>, Error>>()?;
    let first = hsms[0];
    let configuration = {
        let mut sorted = hsms;
        sorted.sort_unstable();
        Configuration(sorted)
    };
    debug!(?configuration, "gathered realm configuration");

    debug!(hsm = ?first, "requesting new realm");
    let (realm_id, group_id, statement) = match rpc::send(
        &agent_client,
        &group[0],
        NewRealmRequest {
            configuration: configuration.clone(),
        },
    )
    .await
    .map_err(Error::NetworkError)?
    {
        NewRealmResponse::Ok {
            realm,
            group,
            statement,
        } => Ok((realm, group, statement)),
        NewRealmResponse::NoHsm => Err(Error::NoHsm {
            agent: group[0].clone(),
        }),
        NewRealmResponse::HaveRealm => Err(Error::HaveRealm {
            agent: group[0].clone(),
        }),
        NewRealmResponse::InvalidConfiguration => Err(Error::InvalidConfiguration),
        NewRealmResponse::NoStore => Err(Error::NoStore),
        NewRealmResponse::StorePreconditionFailed => Err(Error::StorePreconditionFailed),
    }?;
    debug!(?realm_id, ?group_id, "first HSM created new realm");

    debug!(?realm_id, ?group_id, "requesting others join new realm");
    try_join_all(group[1..].iter().map(|agent| {
        let configuration = configuration.clone();
        let statement = statement.clone();
        async {
            match rpc::send(&agent_client, agent, JoinRealmRequest { realm: realm_id })
                .await
                .map_err(Error::NetworkError)?
            {
                JoinRealmResponse::NoHsm => Err(Error::NoHsm {
                    agent: agent.clone(),
                }),
                JoinRealmResponse::HaveOtherRealm => Err(Error::HaveRealm {
                    agent: agent.clone(),
                }),
                JoinRealmResponse::Ok { .. } => Ok(()),
            }?;

            match rpc::send(
                &agent_client,
                agent,
                JoinGroupRequest {
                    realm: realm_id,
                    group: group_id,
                    configuration,
                    statement,
                },
            )
            .await
            .map_err(Error::NetworkError)?
            {
                JoinGroupResponse::Ok => Ok(()),
                JoinGroupResponse::InvalidRealm => Err(Error::HaveRealm {
                    agent: agent.clone(),
                }),
                JoinGroupResponse::InvalidConfiguration => Err(Error::InvalidConfiguration),
                JoinGroupResponse::InvalidStatement => Err(Error::InvalidGroupStatement),
                JoinGroupResponse::NoHsm => Err(Error::NoHsm {
                    agent: agent.clone(),
                }),
            }
        }
    }))
    .await?;

    super::wait_for_commit(&group[0], realm_id, group_id, &agent_client)
        .await
        .map_err(Error::NetworkError)?;
    info!(?realm_id, ?group_id, "realm initialization complete");
    Ok((realm_id, group_id))
}

#[derive(Debug)]
pub enum NewGroupError {
    NetworkError(RpcError),
    NoHsm { agent: Url },
    InvalidRealm { agent: Url },
    InvalidConfiguration,
    InvalidGroupStatement,
    NoStore,
    StorePreconditionFailed,
}

pub async fn new_group(realm: RealmId, group: &[Url]) -> Result<GroupId, NewGroupError> {
    type Error = NewGroupError;
    info!(?realm, "setting up new group");

    let agent_client = Client::new(ClientOptions::default());

    // Ensure all HSMs are up and have joined the realm. Get their IDs to form
    // the configuration.

    let join_realm_requests = group
        .iter()
        .map(|agent| rpc::send(&agent_client, agent, JoinRealmRequest { realm }));
    let join_realm_results = try_join_all(join_realm_requests)
        .await
        .map_err(Error::NetworkError)?;

    let hsms = join_realm_results
        .into_iter()
        .zip(group)
        .map(|(response, agent)| match response {
            JoinRealmResponse::Ok { hsm } => Ok(hsm),
            JoinRealmResponse::HaveOtherRealm => Err(Error::InvalidRealm {
                agent: agent.clone(),
            }),
            JoinRealmResponse::NoHsm => Err(Error::NoHsm {
                agent: agent.clone(),
            }),
        })
        .collect::<Result<Vec<HsmId>, Error>>()?;

    let first = hsms[0];
    let configuration = {
        let mut sorted = hsms;
        sorted.sort_unstable();
        Configuration(sorted)
    };
    debug!(?configuration, "gathered group configuration");

    // Create a new group on the first agent.

    debug!(hsm = ?first, "requesting new group");
    let (group_id, statement) = match rpc::send(
        &agent_client,
        &group[0],
        NewGroupRequest {
            realm,
            configuration: configuration.clone(),
        },
    )
    .await
    .map_err(Error::NetworkError)?
    {
        NewGroupResponse::Ok { group, statement } => Ok((group, statement)),
        NewGroupResponse::NoHsm => Err(Error::NoHsm {
            agent: group[0].clone(),
        }),
        NewGroupResponse::InvalidRealm => Err(Error::InvalidRealm {
            agent: group[0].clone(),
        }),
        NewGroupResponse::InvalidConfiguration => Err(Error::InvalidConfiguration),
        NewGroupResponse::NoStore => Err(Error::NoStore),
        NewGroupResponse::StorePreconditionFailed => Err(Error::StorePreconditionFailed),
    }?;
    debug!(?realm, group = ?group_id, "first HSM created new group");

    // Request each of the other agents to join the new group.

    try_join_all(group[1..].iter().map(|agent| {
        let configuration = configuration.clone();
        let statement = statement.clone();
        async {
            match rpc::send(
                &agent_client,
                agent,
                JoinGroupRequest {
                    realm,
                    group: group_id,
                    configuration,
                    statement,
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
                JoinGroupResponse::NoHsm => Err(Error::NoHsm {
                    agent: agent.clone(),
                }),
            }
        }
    }))
    .await?;

    // Wait for the new group to commit the first log entry.
    super::wait_for_commit(&group[0], realm, group_id, &agent_client)
        .await
        .map_err(Error::NetworkError)?;
    debug!(?realm, group = ?group_id, "group initialization complete");
    Ok(group_id)
}
