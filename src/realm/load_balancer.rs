use actix::prelude::*;
use futures::future::join_all;
use std::collections::HashMap;
use std::iter::zip;
use tracing::{trace, warn};

pub mod types;

use super::agent::types::{AppRequest, AppResponse, StatusRequest, StatusResponse};
use super::agent::Agent;
use super::hsm::types as hsm_types;
use super::store::types::{AddressEntry, GetAddressesRequest, GetAddressesResponse};
use super::store::Store;
use hsm_types::{GroupId, OwnedPrefix, RealmId};
use types::{ClientRequest, ClientResponse};

pub struct LoadBalancer {
    name: String,
    store: Addr<Store>,
}

impl LoadBalancer {
    pub fn new(name: String, store: Addr<Store>) -> Self {
        Self { name, store }
    }
}

#[derive(Debug)]
struct Partition {
    group: GroupId,
    owned_prefix: OwnedPrefix,
    leader: Addr<Agent>,
}

async fn refresh(name: &str, store: Addr<Store>) -> HashMap<RealmId, Vec<Partition>> {
    trace!(load_balancer = name, "refreshing cluster information");
    match store.send(GetAddressesRequest {}).await {
        Err(_) => todo!(),
        Ok(GetAddressesResponse(addresses)) => {
            let responses = join_all(
                addresses
                    .iter()
                    .map(|entry| entry.address.send(StatusRequest {})),
            )
            .await;

            let mut realms: HashMap<RealmId, Vec<Partition>> = HashMap::new();
            for (AddressEntry { address: agent, .. }, response) in zip(addresses, responses) {
                match response {
                    Ok(StatusResponse {
                        hsm:
                            Some(hsm_types::StatusResponse {
                                realm: Some(status),
                                ..
                            }),
                    }) => {
                        let realm = realms.entry(status.id).or_default();
                        for group in status.groups {
                            if let Some(leader) = group.leader {
                                if let Some(owned_prefix) = leader.owned_prefix {
                                    realm.push(Partition {
                                        group: group.id,
                                        owned_prefix,
                                        leader: agent.clone(),
                                    });
                                }
                            }
                        }
                    }

                    Ok(_) => {}

                    Err(err) => {
                        warn!(load_balancer = name, ?agent, ?err, "could not get status");
                    }
                }
            }
            trace!(load_balancer = name, "done refreshing cluster information");
            realms
        }
    }
}

impl Actor for LoadBalancer {
    type Context = Context<Self>;
}

impl Handler<ClientRequest> for LoadBalancer {
    type Result = ResponseFuture<ClientResponse>;

    fn handle(&mut self, request: ClientRequest, _ctx: &mut Context<Self>) -> Self::Result {
        let name = self.name.clone();
        trace!(load_balancer = name, ?request);
        let store = self.store.clone();

        Box::pin(async move {
            let realms = refresh(&name, store).await;
            let response = handle_client_request(request, &name, &realms).await;
            trace!(load_balancer = name, ?response);
            response
        })
    }
}

async fn handle_client_request(
    request: ClientRequest,
    name: &str,
    realms: &HashMap<RealmId, Vec<Partition>>,
) -> ClientResponse {
    type Response = ClientResponse;

    let Some(partitions) = realms.get(&request.realm) else {
        return Response::Unavailable;
    };

    for partition in partitions {
        if !partition.owned_prefix.contains(&request.uid) {
            continue;
        }

        let result = partition
            .leader
            .send(AppRequest {
                realm: request.realm,
                group: partition.group,
                uid: request.uid.clone(),
                request: request.request.clone(),
            })
            .await;

        match result {
            Err(_) => {
                warn!(
                    load_balancer = name,
                    agent = ?partition.leader,
                    realm = ?request.realm,
                    group = ?partition.group,
                    "connection error",
                );
            }

            Ok(
                r @ AppResponse::InvalidRealm
                | r @ AppResponse::InvalidGroup
                | r @ AppResponse::NoHsm
                | r @ AppResponse::NoStore
                | r @ AppResponse::NotLeader,
            ) => {
                warn!(
                    load_balancer = name,
                    agent = ?partition.leader,
                    realm = ?request.realm,
                    group = ?partition.group,
                    response = ?r,
                    "AppRequest not ok",
                );
            }

            Ok(AppResponse::Ok(response)) => return Response::Ok(response),
        }
    }

    Response::Unavailable
}
