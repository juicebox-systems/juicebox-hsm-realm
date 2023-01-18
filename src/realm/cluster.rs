use actix::prelude::*;
use futures::future::try_join_all;
use std::time::Duration;
use tracing::info;

use super::agent::types::{
    JoinGroupRequest, JoinGroupResponse, JoinRealmRequest, JoinRealmResponse, NewRealmRequest,
    NewRealmResponse, StatusRequest,
};
use super::agent::Agent;
use super::hsm::types::{Configuration, GroupStatus, HsmId, LeaderStatus, LogIndex, RealmId};

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

pub async fn new_realm(group: &[Addr<Agent>]) -> Result<RealmId, NewRealmError> {
    info!("setting up new realm");

    let hsms = try_join_all(group.iter().map(|agent| agent.send(StatusRequest {})))
        .await
        .map_err(NewRealmError::NetworkError)?
        .iter()
        .zip(group)
        .map(|(resp, agent)| match &resp.hsm {
            Some(hsm_status) => Ok(hsm_status.id),
            None => Err(NewRealmError::NoHsm {
                agent: agent.clone(),
            }),
        })
        .collect::<Result<Vec<HsmId>, NewRealmError>>()?;
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
        .map_err(NewRealmError::NetworkError)?
    {
        NewRealmResponse::Ok {
            realm,
            group,
            statement,
        } => Ok((realm, group, statement)),
        NewRealmResponse::NoHsm => Err(NewRealmError::NoHsm {
            agent: group[0].clone(),
        }),
        NewRealmResponse::HaveRealm => Err(NewRealmError::HaveRealm {
            agent: group[0].clone(),
        }),
        NewRealmResponse::InvalidConfiguration => Err(NewRealmError::InvalidConfiguration),
        NewRealmResponse::NoStore => Err(NewRealmError::NoStore),
        NewRealmResponse::StorePreconditionFailed => Err(NewRealmError::StorePreconditionFailed),
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
                .map_err(NewRealmError::NetworkError)?
            {
                JoinRealmResponse::NoHsm => Err(NewRealmError::NoHsm {
                    agent: agent.clone(),
                }),
                JoinRealmResponse::HaveRealm => Err(NewRealmError::HaveRealm {
                    agent: agent.clone(),
                }),
                JoinRealmResponse::Ok => Ok(()),
            }?;

            match agent
                .send(JoinGroupRequest {
                    realm: realm_id,
                    group: group_id,
                    configuration,
                    statement,
                })
                .await
                .map_err(NewRealmError::NetworkError)?
            {
                JoinGroupResponse::Ok => Ok(()),
                JoinGroupResponse::InvalidRealm => Err(NewRealmError::HaveRealm {
                    agent: agent.clone(),
                }),
                JoinGroupResponse::InvalidConfiguration => Err(NewRealmError::InvalidConfiguration),
                JoinGroupResponse::InvalidStatement => Err(NewRealmError::InvalidGroupStatement),
                JoinGroupResponse::NoHsm => Err(NewRealmError::NoHsm {
                    agent: agent.clone(),
                }),
            }
        }
    }))
    .await?;

    info!(
        ?realm_id,
        ?group_id,
        "waiting for first log entry to commit"
    );
    loop {
        let status = group[0]
            .send(StatusRequest {})
            .await
            .map_err(NewRealmError::NetworkError)?;
        let Some(hsm) = status.hsm else { continue };
        let Some(realm) = hsm.realm else { continue };
        if realm.id != realm_id {
            continue;
        }
        let group = realm.groups.iter().find(|group| group.id == group_id);
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
                info!(
                    ?realm_id,
                    ?group_id,
                    ?committed,
                    "realm initialization complete"
                );
                return Ok(realm_id);
            }
        }

        actix::clock::sleep(Duration::from_millis(1)).await;
    }
}
