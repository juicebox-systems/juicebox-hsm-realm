use futures::future::{join_all, try_join_all};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::iter::zip;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, trace, warn};
use url::Url;

use super::super::http_client::{Client, ClientOptions};
use super::agent::types::{
    AgentService, BecomeLeaderRequest, BecomeLeaderResponse, CompleteTransferRequest,
    CompleteTransferResponse, JoinGroupRequest, JoinGroupResponse, JoinRealmRequest,
    JoinRealmResponse, NewGroupRequest, NewGroupResponse, NewRealmRequest, NewRealmResponse,
    StatusRequest, StatusResponse, TransferInRequest, TransferInResponse, TransferNonceRequest,
    TransferNonceResponse, TransferOutRequest, TransferOutResponse, TransferStatementRequest,
    TransferStatementResponse,
};
use super::store::bigtable::StoreClient;
use hsm_types::{Configuration, GroupId, GroupStatus, HsmId, LeaderStatus, LogIndex, OwnedRange};
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

    wait_for_commit(&group[0], realm_id, group_id, &agent_client)
        .await
        .map_err(Error::NetworkError)?;
    info!(?realm_id, ?group_id, "realm initialization complete");
    Ok((realm_id, group_id))
}

async fn wait_for_commit(
    leader: &Url,
    realm: RealmId,
    group_id: GroupId,
    agent_client: &Client<AgentService>,
) -> Result<(), RpcError> {
    debug!(?realm, group = ?group_id, "waiting for first log entry to commit");
    loop {
        let status = rpc::send(agent_client, leader, StatusRequest {}).await?;
        let Some(hsm) = status.hsm else { continue };
        let Some(realm_status) = hsm.realm else { continue };
        if realm_status.id != realm {
            continue;
        }
        let group_status = realm_status
            .groups
            .iter()
            .find(|group_status| group_status.id == group_id);
        if let Some(GroupStatus {
            leader:
                Some(LeaderStatus {
                    committed: Some(committed),
                    ..
                }),
            ..
        }) = group_status
        {
            if *committed >= LogIndex::FIRST {
                info!(?realm, group = ?group_id, ?committed, "first log entry committed");
                return Ok(());
            }
        }

        sleep(Duration::from_millis(1)).await;
    }
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
    wait_for_commit(&group[0], realm, group_id, &agent_client)
        .await
        .map_err(Error::NetworkError)?;
    debug!(?realm, group = ?group_id, "group initialization complete");
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
    range: OwnedRange,
    store: &StoreClient,
) -> Result<(), TransferError> {
    type Error = TransferError;

    info!(
        ?realm,
        ?source,
        ?destination,
        ?range,
        "transferring ownership"
    );

    let agent_client = Client::new(ClientOptions::default());

    let leaders = find_leaders(store, &agent_client).await.expect("TODO");

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

    let transferring_partition = match rpc::send(
        &agent_client,
        source_leader,
        TransferOutRequest {
            realm,
            source,
            destination,
            range: range.clone(),
        },
    )
    .await
    {
        Err(e) => todo!("{e:?}"),
        Ok(TransferOutResponse::Ok { transferring }) => transferring,
        Ok(r) => todo!("{r:?}"),
    };

    let nonce = match rpc::send(
        &agent_client,
        dest_leader,
        TransferNonceRequest { realm, destination },
    )
    .await
    {
        Err(e) => todo!("{e:?}"),
        Ok(TransferNonceResponse::Ok(nonce)) => nonce,
        Ok(r) => todo!("{r:?}"),
    };

    let statement = match rpc::send(
        &agent_client,
        source_leader,
        TransferStatementRequest {
            realm,
            source,
            destination,
            nonce,
        },
    )
    .await
    {
        Err(e) => todo!("{e:?}"),
        Ok(TransferStatementResponse::Ok(statement)) => statement,
        Ok(r) => todo!("{r:?}"),
    };

    match rpc::send(
        &agent_client,
        dest_leader,
        TransferInRequest {
            realm,
            source,
            destination,
            transferring: transferring_partition,
            nonce,
            statement,
        },
    )
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

    match rpc::send(
        &agent_client,
        source_leader,
        CompleteTransferRequest {
            realm,
            source,
            destination,
            range,
        },
    )
    .await
    {
        Err(e) => todo!("{e:?}"),
        Ok(CompleteTransferResponse::Ok) => Ok(()),
        Ok(r) => todo!("{r:?}"),
    }
}

async fn find_leaders(
    store: &StoreClient,
    agent_client: &Client<AgentService>,
) -> Result<HashMap<(RealmId, GroupId), Url>, tonic::Status> {
    trace!("refreshing cluster information");
    let addresses = store.get_addresses().await?;

    let responses = join_all(
        addresses
            .iter()
            .map(|(_, address)| rpc::send(agent_client, address, StatusRequest {})),
    )
    .await;

    let mut leaders: HashMap<(RealmId, GroupId), Url> = HashMap::new();
    for ((_, agent), response) in zip(addresses, responses) {
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
                warn!(%agent, ?err, "could not get status");
            }
        }
    }
    trace!("done refreshing cluster information");
    Ok(leaders)
}

pub async fn ensure_groups_have_leader(
    agent_client: &Client<AgentService>,
    store: &StoreClient,
) -> Result<(), tonic::Status> {
    trace!("checking that all groups have a leader");
    let addresses = store.get_addresses().await?;

    let hsm_status: HashMap<HsmId, hsm_types::StatusResponse> = join_all(
        addresses
            .iter()
            .map(|(_, address)| rpc::send(agent_client, address, StatusRequest {})),
    )
    .await
    .into_iter()
    .filter_map(|r| r.ok().and_then(|s| s.hsm).map(|s| (s.id, s)))
    .collect();

    let mut groups: HashMap<GroupId, (Configuration, RealmId, Option<HsmId>)> = HashMap::new();
    for hsm in hsm_status.values() {
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
        // This group doesn't have a leader, we'll pick one and ask it to become leader.
        info!(?group_id, ?realm_id, "Group has no leader");

        // We calculate a score for each group member based on how much work we
        // think its doing. Then use that to control the order in which we try to
        // make a member the leader.
        let mut scored: Vec<_> = config
            .0
            .into_iter()
            .filter_map(|id| hsm_status.get(&id))
            .map(|m| score(&group_id, m))
            .collect();
        scored.sort();

        for hsm_id in scored.into_iter().map(|s| s.id) {
            if let Some((_, url)) = addresses.iter().find(|a| a.0 == hsm_id) {
                info!(?hsm_id, ?realm_id, ?group_id, "Asking hsm to become leader");
                match rpc::send(
                    agent_client,
                    url,
                    BecomeLeaderRequest {
                        realm: realm_id,
                        group: group_id,
                    },
                )
                .await
                {
                    Ok(BecomeLeaderResponse::Ok) => {
                        info!(?hsm_id, ?realm_id, ?group_id, "Now leader");
                        break;
                    }
                    Ok(reply) => {
                        warn!(?reply, "BecomeLeader replied not okay");
                    }
                    Err(e) => {
                        warn!(err=?e, "BecomeLeader error");
                    }
                }
            }
        }
    }
    Ok(())
}

fn score(group: &GroupId, m: &hsm_types::StatusResponse) -> Score {
    let mut work = 0;
    let mut last_captured = None;
    if let Some(r) = &m.realm {
        // group member scores +1, leader scores + 10
        for g in &r.groups {
            work += 1;
            if g.leader.is_some() {
                work += 10;
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
