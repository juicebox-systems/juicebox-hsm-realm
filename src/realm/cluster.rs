use actix::prelude::*;
use futures::future::{join_all, try_join_all};
use std::collections::HashMap;
use std::iter::zip;
use std::time::Duration;
use tracing::{debug, info, trace, warn};

use super::agent::types::{
    CompleteTransferRequest, CompleteTransferResponse, JoinGroupRequest, JoinGroupResponse,
    JoinRealmRequest, JoinRealmResponse, NewGroupRequest, NewGroupResponse, NewRealmRequest,
    NewRealmResponse, StatusRequest, StatusResponse, TransferInRequest, TransferInResponse,
    TransferNonceRequest, TransferNonceResponse, TransferOutRequest, TransferOutResponse,
    TransferStatementRequest, TransferStatementResponse,
};
use super::agent::Agent;
use super::hsm::types as hsm_types;
use super::store::types::{AddressEntry, GetAddressesRequest, GetAddressesResponse};
use super::store::Store;
use hsm_types::{
    Configuration, GroupId, GroupStatus, HsmId, LeaderStatus, LogIndex, OwnedPrefix, RealmId,
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
    debug!(?configuration, "gathered realm configuration");

    debug!(hsm = ?first, "requesting new realm");
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
    debug!(?realm_id, ?group_id, "first HSM created new realm");

    debug!(?realm_id, ?group_id, "requesting others join new realm");
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
    debug!(?realm, ?group, "waiting for first log entry to commit");
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
    debug!(?configuration, "gathered group configuration");

    // Create a new group on the first agent.

    debug!(hsm = ?first, "requesting new group");
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
    debug!(?realm, group = ?group_id, "first HSM created new group");

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
    debug!(?realm, ?group, "group initialization complete");
    Ok(group_id)
}

#[derive(Debug)]
pub enum TransferError {
    NoSourceLeader,
    NoDestinationLeader,
    // TODO: more error cases hidden in todo!()s.
}

pub async fn transfer(
    realm: RealmId,
    source: GroupId,
    destination: GroupId,
    prefix: OwnedPrefix,
    store: &Addr<Store>,
) -> Result<(), TransferError> {
    type Error = TransferError;

    info!(
        ?realm,
        ?source,
        ?destination,
        ?prefix,
        "transferring ownership"
    );

    let leaders = find_leaders(store).await.expect("TODO");

    let Some(source_leader) = leaders.get(&(realm, source)) else {
        return Err(Error::NoSourceLeader);
    };

    let Some(dest_leader) = leaders.get(&(realm, destination)) else {
        return Err(Error::NoDestinationLeader);
    };

    // The current ownership transfer protocol is dangerous in that the moment
    // the source group commits the log entry that the prefix is transferring
    // out, the prefix must then move to the destination group. However, we
    // don't have any guarantee that the destination group will accept the
    // prefix. This is an issue with splitting in half: the only group that can
    // accept a prefix is one that owns no prefix or one that owns the
    // complementary prefix (the one with its least significant bit flipped).

    let transferring_partition = match source_leader
        .send(TransferOutRequest {
            realm,
            source,
            destination,
            prefix: prefix.clone(),
        })
        .await
    {
        Err(e) => todo!("{e:?}"),
        Ok(TransferOutResponse::Ok { transferring }) => transferring,
        Ok(r) => todo!("{r:?}"),
    };

    let nonce = match dest_leader
        .send(TransferNonceRequest { realm, destination })
        .await
    {
        Err(e) => todo!("{e:?}"),
        Ok(TransferNonceResponse::Ok(nonce)) => nonce,
        Ok(r) => todo!("{r:?}"),
    };

    let statement = match source_leader
        .send(TransferStatementRequest {
            realm,
            source,
            destination,
            nonce,
        })
        .await
    {
        Err(e) => todo!("{e:?}"),
        Ok(TransferStatementResponse::Ok(statement)) => statement,
        Ok(r) => todo!("{r:?}"),
    };

    match dest_leader
        .send(TransferInRequest {
            realm,
            source,
            destination,
            transferring: transferring_partition,
            nonce,
            statement,
        })
        .await
    {
        Err(e) => todo!("{e:?}"),
        Ok(TransferInResponse::Ok) => {}
        Ok(r) => todo!("{r:?}"),
    }

    // TODO: This part is dangerous because TransferInRequest returns before
    // the transfer has committed (for now). If that log entry doesn't commit
    // and this calls CompleteTransferRequest, the keyspace will be lost
    // forever.

    match source_leader
        .send(CompleteTransferRequest {
            realm,
            source,
            destination,
            prefix,
        })
        .await
    {
        Err(e) => todo!("{e:?}"),
        Ok(CompleteTransferResponse::Ok) => Ok(()),
        Ok(r) => todo!("{r:?}"),
    }
}

async fn find_leaders(
    store: &Addr<Store>,
) -> Result<HashMap<(RealmId, GroupId), Addr<Agent>>, actix::MailboxError> {
    trace!("refreshing cluster information");
    match store.send(GetAddressesRequest {}).await {
        Err(_) => todo!(),
        Ok(GetAddressesResponse(addresses)) => {
            let responses = join_all(
                addresses
                    .iter()
                    .map(|entry| entry.address.send(StatusRequest {})),
            )
            .await;

            let mut leaders: HashMap<(RealmId, GroupId), Addr<Agent>> = HashMap::new();
            for (AddressEntry { address: agent, .. }, response) in zip(addresses, responses) {
                match response {
                    Ok(StatusResponse {
                        hsm:
                            Some(hsm_types::StatusResponse {
                                realm: Some(status),
                                ..
                            }),
                    }) => {
                        for group in status.groups {
                            if group.leader.is_some() {
                                leaders.insert((status.id, group.id), agent.clone());
                            }
                        }
                    }

                    Ok(_) => {}

                    Err(err) => {
                        warn!(?agent, ?err, "could not get status");
                    }
                }
            }
            trace!("done refreshing cluster information");
            Ok(leaders)
        }
    }
}
