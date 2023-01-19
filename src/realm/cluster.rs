use actix::prelude::*;
use futures::future::try_join_all;
use std::time::Duration;
use tracing::info;

use super::agent::types::{
    JoinGroupRequest, JoinGroupResponse, JoinRealmRequest, JoinRealmResponse, NewGroupRequest,
    NewGroupResponse, NewRealmRequest, NewRealmResponse, StatusRequest,
};
use super::agent::Agent;
use super::hsm::types::{
    Configuration, GroupId, GroupStatus, HsmId, LeaderStatus, LogIndex, RealmId,
};

#[derive(Debug)]
pub enum NewRealmError {
    NetworkError(actix::MailboxError),
    NoHsm { agent: Addr<Agent> },
    HaveRealm { agent: Addr<Agent> },
    InvalidConfiguration,
    InvalidGroupStatement,
    NoStore,
    StorePreconditionFailed,
}

pub async fn new_realm(group: &[Addr<Agent>]) -> Result<(RealmId, GroupId), NewRealmError> {
    type Error = NewRealmError;
    info!("setting up new realm");

    let hsms = try_join_all(group.iter().map(|agent| agent.send(StatusRequest {})))
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
    info!(?configuration, "gathered realm configuration");

    info!(hsm = ?first, "requesting new realm");
    let (realm_id, group_id, statement) = match group[0]
        .send(NewRealmRequest {
            configuration: configuration.clone(),
        })
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
    info!(?realm_id, ?group_id, "first HSM created new realm");

    info!(?realm_id, ?group_id, "requesting others join new realm");
    try_join_all(group[1..].iter().map(|agent| {
        let configuration = configuration.clone();
        let statement = statement.clone();
        async {
            match agent
                .send(JoinRealmRequest { realm: realm_id })
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

            match agent
                .send(JoinGroupRequest {
                    realm: realm_id,
                    group: group_id,
                    configuration,
                    statement,
                })
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

    wait_for_commit(&group[0], realm_id, group_id)
        .await
        .map_err(Error::NetworkError)?;
    info!(?realm_id, ?group_id, "realm initialization complete");
    Ok((realm_id, group_id))
}

async fn wait_for_commit(
    leader: &Addr<Agent>,
    realm: RealmId,
    group: GroupId,
) -> Result<(), actix::MailboxError> {
    info!(?realm, ?group, "waiting for first log entry to commit");
    loop {
        let status = leader.send(StatusRequest {}).await?;
        let Some(hsm) = status.hsm else { continue };
        let Some(realm_status) = hsm.realm else { continue };
        if realm_status.id != realm {
            continue;
        }
        let group = realm_status
            .groups
            .iter()
            .find(|group_status| group_status.id == group);
        if let Some(GroupStatus {
            leader:
                Some(LeaderStatus {
                    committed: Some(committed),
                    ..
                }),
            ..
        }) = group
        {
            if *committed >= LogIndex(1) {
                info!(?realm, ?group, ?committed, "first log entry committed");
                return Ok(());
            }
        }

        actix::clock::sleep(Duration::from_millis(1)).await;
    }
}

#[derive(Debug)]
pub enum NewGroupError {
    NetworkError(actix::MailboxError),
    NoHsm { agent: Addr<Agent> },
    InvalidRealm { agent: Addr<Agent> },
    InvalidConfiguration,
    InvalidGroupStatement,
    NoStore,
    StorePreconditionFailed,
}

pub async fn new_group(realm: RealmId, group: &[Addr<Agent>]) -> Result<GroupId, NewGroupError> {
    type Error = NewGroupError;
    info!(?realm, "setting up new group");

    // Ensure all HSMs are up and have joined the realm. Get their IDs to form
    // the configuration.

    let join_realm_requests = group
        .iter()
        .map(|agent| agent.send(JoinRealmRequest { realm }));
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
    info!(?configuration, "gathered group configuration");

    // Create a new group on the first agent.

    info!(hsm = ?first, "requesting new group");
    let (group_id, statement) = match group[0]
        .send(NewGroupRequest {
            realm,
            configuration: configuration.clone(),
        })
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
    info!(?realm, group = ?group_id, "first HSM created new group");

    // Request each of the other agents to join the new group.

    try_join_all(group[1..].iter().map(|agent| {
        let configuration = configuration.clone();
        let statement = statement.clone();
        async {
            match agent
                .send(JoinGroupRequest {
                    realm,
                    group: group_id,
                    configuration,
                    statement,
                })
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
    wait_for_commit(&group[0], realm, group_id)
        .await
        .map_err(Error::NetworkError)?;
    info!(?realm, ?group, "group initialization complete");
    Ok(group_id)
}
