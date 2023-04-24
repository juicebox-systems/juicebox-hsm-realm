use bytes::Bytes;
use futures::future::{join_all, try_join_all};
use futures::{Future, FutureExt};
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use opentelemetry_http::HeaderExtractor;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::iter::zip;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{debug, info, instrument, trace, warn, Instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use url::Url;

use super::super::http_client::{Client, ClientOptions};
use super::agent::types as agent_types;
use super::agent::types::{
    AgentService, BecomeLeaderRequest, BecomeLeaderResponse, CompleteTransferRequest,
    CompleteTransferResponse, JoinGroupRequest, JoinGroupResponse, JoinRealmRequest,
    JoinRealmResponse, NewGroupRequest, NewGroupResponse, NewRealmRequest, NewRealmResponse,
    StatusRequest, StatusResponse, TransferInRequest, TransferInResponse, TransferNonceRequest,
    TransferNonceResponse, TransferOutRequest, TransferOutResponse, TransferStatementRequest,
    TransferStatementResponse,
};
use super::rpc::{handle_rpc, HandlerError};
use super::store::bigtable::StoreClient;
use hsm_types::{Configuration, GroupId, GroupStatus, HsmId, LeaderStatus, LogIndex, OwnedRange};
use hsmcore::hsm::types as hsm_types;
use loam_sdk_core::types::RealmId;
use loam_sdk_networking::rpc::{self, Rpc, RpcError};

pub mod types;

#[derive(Debug)]
pub enum Error {
    Grpc(tonic::Status),
    Rpc(RpcError),
}
impl From<tonic::Status> for Error {
    fn from(value: tonic::Status) -> Self {
        Self::Grpc(value)
    }
}
impl From<RpcError> for Error {
    fn from(value: RpcError) -> Self {
        Self::Rpc(value)
    }
}

#[derive(Clone)]
pub struct Manager(Arc<ManagerInner>);

struct ManagerInner {
    store: StoreClient,
    agents: Client<AgentService>,
    // Groups that are being actively managed through some transition and other
    // management operations on the group should be skipped.
    busy_groups: Mutex<HashSet<(RealmId, GroupId)>>,
}

/// When drop'd will remove the realm/group from the managers busy_groups set.
struct ManagementGrant<'a> {
    mgr: &'a Manager,
    group: GroupId,
    realm: RealmId,
}

impl<'a> Drop for ManagementGrant<'a> {
    fn drop(&mut self) {
        info!(group=?self.group, realm=?self.realm, "management task completed");
        self.mgr
            .0
            .busy_groups
            .lock()
            .unwrap()
            .remove(&(self.realm, self.group));
    }
}

impl Manager {
    pub fn new(store: StoreClient, update_interval: Duration) -> Self {
        let m = Self(Arc::new(ManagerInner {
            store,
            agents: Client::new(ClientOptions::default()),
            busy_groups: Mutex::new(HashSet::new()),
        }));
        let manager = m.clone();
        tokio::spawn(async move {
            loop {
                sleep(update_interval).await;
                manager.run().await;
            }
        });
        m
    }

    pub async fn listen(
        self,
        address: SocketAddr,
    ) -> Result<(Url, JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(address).await?;
        let url = Url::parse(&format!("https://{address}")).unwrap();

        Ok((
            url,
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Err(e) => warn!("error accepting connection: {e:?}"),
                        Ok((stream, _)) => {
                            let manager = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(stream, manager)
                                    .await
                                {
                                    warn!("error serving connection: {e:?}");
                                }
                            });
                        }
                    }
                }
            }),
        ))
    }
}

impl Service<Request<IncomingBody>> for Manager {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[instrument(level = "trace", skip(self, request))]
    fn call(&mut self, request: Request<IncomingBody>) -> Self::Future {
        let parent_context = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(request.headers()))
        });
        Span::current().set_parent(parent_context);

        let manager = self.clone();
        Box::pin(
            async move {
                let Some(path) = request.uri().path().strip_prefix('/') else {
                    return Ok(Response::builder()
                        .status(http::StatusCode::NOT_FOUND)
                        .body(Full::from(Bytes::new()))
                        .unwrap());
                };
                match path {
                    types::StepdownAsLeaderRequest::PATH => {
                        handle_rpc(&manager, request, Self::handle_leader_stepdown).await
                    }
                    _ => Ok(Response::builder()
                        .status(http::StatusCode::NOT_FOUND)
                        .body(Full::from(Bytes::new()))
                        .unwrap()),
                }
            }
            // This doesn't look like it should do anything, but it seems to be
            // critical to connecting these spans to the parent.
            .instrument(Span::current()),
        )
    }
}

impl Manager {
    /// Perform one pass of the management tasks.
    async fn run(&self) {
        if let Err(err) = self.ensure_groups_have_leader().await {
            warn!(?err, "Error while checking/updating cluster state")
        }
    }

    // Track that the group is going through some management operation that
    // should block other management operations. Returns None if the group is
    // already busy by some other task. When the returned ManagementGrant is
    // dropped, the group will be removed from the busy set.
    fn mark_as_busy(&self, realm: RealmId, group: GroupId) -> Option<ManagementGrant> {
        let mut locked = self.0.busy_groups.lock().unwrap();
        if locked.insert((realm, group)) {
            info!(?group, ?realm, "marking group as under active management");
            Some(ManagementGrant {
                mgr: self,
                realm,
                group,
            })
        } else {
            None
        }
    }

    async fn handle_leader_stepdown(
        &self,
        req: types::StepdownAsLeaderRequest,
    ) -> Result<types::StepdownAsLeaderResponse, HandlerError> {
        type Response = types::StepdownAsLeaderResponse;

        let addresses: HashMap<HsmId, Url> = match self.0.store.get_addresses().await {
            Ok(a) => a.into_iter().collect(),
            Err(_err) => return Ok(Response::NoStore),
        };

        // calculate the exact set of step downs needed.
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
            info!(url=%stepdown.url, hsm=?stepdown.hsm, group=?stepdown.group, realm=?stepdown.realm, "Asking Agent/HSM to step down as leader");
            match rpc::send(
                &self.0.agents,
                &stepdown.url,
                agent_types::StepdownAsLeaderRequest {
                    realm: stepdown.realm,
                    group: stepdown.group,
                },
            )
            .await
            {
                Err(err) => return Ok(Response::RpcError(err)),
                Ok(agent_types::StepdownAsLeaderResponse::NoHsm) => return Ok(Response::NoHsm),
                Ok(agent_types::StepdownAsLeaderResponse::InvalidGroup) => {
                    return Ok(Response::InvalidGroup)
                }
                Ok(agent_types::StepdownAsLeaderResponse::InvalidRealm) => {
                    return Ok(Response::InvalidRealm)
                }
                Ok(agent_types::StepdownAsLeaderResponse::NotLeader) => {
                    return Ok(Response::NotLeader)
                }
                Ok(agent_types::StepdownAsLeaderResponse::Ok { last }) => {
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
            stepdown
                .config
                .0
                .iter()
                .filter_map(|hsm| addresses.get(hsm)),
        )
        .await;

        assign_group_a_leader(
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
        req: &types::StepdownAsLeaderRequest,
        addresses: &HashMap<HsmId, Url>,
    ) -> Result<Vec<Stepdown>, types::StepdownAsLeaderResponse> {
        match req {
            types::StepdownAsLeaderRequest::Hsm(hsm) => match addresses.get(hsm) {
                None => {
                    warn!(?hsm, "failed to find hsm in service discovery");
                    Err(types::StepdownAsLeaderResponse::InvalidHsm)
                }
                Some(url) => match rpc::send(&self.0.agents, url, StatusRequest {}).await {
                    Err(err) => {
                        warn!(?err, url=%url, hsm=?hsm, "failed to get status of HSM");
                        Err(types::StepdownAsLeaderResponse::RpcError(err))
                    }
                    Ok(StatusResponse {
                        hsm:
                            Some(hsm_types::StatusResponse {
                                id,
                                realm: Some(rs),
                                ..
                            }),
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
                        info!(?hsm,url=%url, "hsm is not a member of a realm");
                        Ok(Vec::new())
                    }
                },
            },
            types::StepdownAsLeaderRequest::Group { realm, group } => {
                Ok(join_all(addresses.iter().map(|(_hsm, url)| {
                    rpc::send(&self.0.agents, url, StatusRequest {}).map(|r| (r, url.clone()))
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

    pub async fn ensure_groups_have_leader(&self) -> Result<(), Error> {
        trace!("checking that all groups have a leader");
        let addresses = self.0.store.get_addresses().await?;
        let hsm_status =
            get_hsm_statuses(&self.0.agents, addresses.iter().map(|(_, url)| url)).await;

        let mut groups: HashMap<GroupId, (Configuration, RealmId, Option<HsmId>)> = HashMap::new();
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

struct Stepdown {
    hsm: HsmId,
    url: Url,
    group: GroupId,
    realm: RealmId,
    config: Configuration,
}

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

    let Some((_, source_leader)) = leaders.get(&(realm, source)) else {
        return Err(Error::NoSourceLeader);
    };

    let Some((_, dest_leader)) = leaders.get(&(realm, destination)) else {
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

    let dest_index = match rpc::send(
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
        Ok(TransferInResponse::Ok(index)) => index,
        Ok(r) => todo!("{r:?}"),
    };

    // TODO: This part is dangerous because TransferInRequest returns before
    // the transfer has committed (for now). If that log entry doesn't commit
    // and this calls CompleteTransferRequest, the keyspace will be lost
    // forever.

    let src_index = match rpc::send(
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
        Ok(CompleteTransferResponse::Ok(index)) => index,
        Ok(r) => todo!("{r:?}"),
    };
    // At this point the agents have queued the log entry that contained
    // the completed transfer but may or may not have actually written
    // it to the store yet. So we need to wait for that to happen.
    // TODO: this should really wait for commit, and handled in the agent
    // to be resolved with the overall transfer review/update.
    let wait_for_entry = |group, index| async move {
        loop {
            if let Some(e) = store
                .read_last_log_entry(&realm, &group)
                .await
                .expect("TODO")
            {
                if e.index >= index {
                    return;
                }
                sleep(Duration::from_millis(1)).await;
            }
        }
    };
    wait_for_entry(source, src_index).await;
    wait_for_entry(destination, dest_index).await;

    Ok(())
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

async fn get_hsm_statuses(
    agents: &Client<AgentService>,
    agent_urls: impl Iterator<Item = &Url>,
) -> HashMap<HsmId, (hsm_types::StatusResponse, Url)> {
    join_all(
        agent_urls.map(|url| rpc::send(agents, url, StatusRequest {}).map(|r| (r, url.clone()))),
    )
    .await
    .into_iter()
    .filter_map(|(r, url)| r.ok().and_then(|s| s.hsm).map(|s| (s.id, (s, url))))
    .collect()
}

/// Assigns a new leader for the group, using our workload scoring. The caller
/// is responsible for deciding that the group needs a leader.
async fn assign_group_a_leader(
    agent_client: &Client<AgentService>,
    grant: &ManagementGrant<'_>,
    config: Configuration,
    skipping: Option<HsmId>,
    hsm_status: &HashMap<HsmId, (hsm_types::StatusResponse, Url)>,
    last: Option<LogIndex>,
) -> Result<Option<HsmId>, RpcError> {
    // We calculate a score for each group member based on how much work we
    // think its doing. Then use that to control the order in which we try to
    // make a member the leader.
    let mut scored: Vec<_> = config
        .0
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
