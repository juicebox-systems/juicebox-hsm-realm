use bitvec::prelude::Msb0;
use bitvec::vec::BitVec;
use bytes::Bytes;
use futures::future::join_all;
use futures::Future;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use reqwest::Url;
use std::collections::HashMap;
use std::iter::zip;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{trace, warn};

pub mod types;

use super::super::http_client::Client;
use super::agent::types::{
    AgentService, AppRequest, AppResponse, StatusRequest, StatusResponse, TenantId, UserId,
};
use super::store::bigtable::StoreClient;
use hsm_types::{GroupId, OwnedRange, RealmId};
use hsmcore::hsm::types as hsm_types;
use types::{ClientRequest, ClientResponse};

#[derive(Clone)]
pub struct LoadBalancer(Arc<State>);

struct State {
    name: String,
    store: StoreClient,
    agent_client: Client<AgentService>,
}

impl LoadBalancer {
    pub fn new(name: String, store: StoreClient) -> Self {
        Self(Arc::new(State {
            name,
            store,
            agent_client: Client::new(),
        }))
    }

    pub async fn listen(
        self,
        address: SocketAddr,
    ) -> Result<(Url, JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(address).await?;
        let url = Url::parse(&format!("http://{address}")).unwrap();
        Ok((
            url,
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Err(e) => warn!("error accepting connection: {e:?}"),
                        Ok((stream, _)) => {
                            let lb = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    http1::Builder::new().serve_connection(stream, lb).await
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

#[derive(Debug)]
struct Partition {
    group: GroupId,
    owned_range: OwnedRange,
    leader: Url,
}

async fn refresh(
    name: &str,
    store: &StoreClient,
    agent_client: &Client<AgentService>,
) -> HashMap<RealmId, Vec<Partition>> {
    trace!(load_balancer = name, "refreshing cluster information");
    match store.get_addresses().await {
        Err(_) => todo!(),
        Ok(addresses) => {
            let responses = join_all(
                addresses
                    .iter()
                    .map(|(_, address)| agent_client.send(address, StatusRequest {})),
            )
            .await;

            let mut realms: HashMap<RealmId, Vec<Partition>> = HashMap::new();
            for ((_, agent), response) in zip(addresses, responses) {
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
                                if let Some(owned_range) = leader.owned_range {
                                    realm.push(Partition {
                                        group: group.id,
                                        owned_range,
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

impl Service<Request<IncomingBody>> for LoadBalancer {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&mut self, request: Request<IncomingBody>) -> Self::Future {
        let name = self.0.name.clone();
        trace!(load_balancer = name, ?request);
        let store = self.0.store.clone();
        let agent_client = self.0.agent_client.clone();

        Box::pin(async move {
            let realms = refresh(&name, &store, &agent_client).await;
            let request =
                rmp_serde::from_slice(request.collect().await?.to_bytes().as_ref()).expect("TODO");
            let response = handle_client_request(request, &name, &realms, &agent_client).await;
            trace!(load_balancer = name, ?response);
            Ok(Response::builder()
                .body(Full::new(Bytes::from(
                    rmp_serde::to_vec(&response).expect("TODO"),
                )))
                .expect("TODO"))
        })
    }
}

async fn handle_client_request(
    request: ClientRequest,
    name: &str,
    realms: &HashMap<RealmId, Vec<Partition>>,
    agent_client: &Client<AgentService>,
) -> ClientResponse {
    type Response = ClientResponse;

    let Some(partitions) = realms.get(&request.realm) else {
        return Response::Unavailable;
    };

    // TODO: this is a dumb hack and obviously not what we want.
    let token = request.request.auth_token();
    let mut tenant = BitVec::new();
    tenant.extend(&BitVec::<u8, Msb0>::from_slice(token.signature.as_bytes()));
    let mut user = BitVec::new();
    user.extend(&BitVec::<u8, Msb0>::from_slice(token.user.as_bytes()));
    let record_id = super::agent::types::make_record_id(&TenantId(tenant), &UserId(user));

    for partition in partitions {
        if !partition.owned_range.contains(&record_id) {
            continue;
        }

        match agent_client
            .send(
                &partition.leader,
                AppRequest {
                    realm: request.realm,
                    group: partition.group,
                    rid: record_id.clone(),
                    request: request.request.clone(),
                },
            )
            .await
        {
            Err(_) => {
                warn!(
                    load_balancer = name,
                    agent = ?partition.leader,
                    realm = ?request.realm,
                    group = ?partition.group,
                    "http error",
                );
            }

            Ok(
                r @ AppResponse::InvalidRealm
                | r @ AppResponse::InvalidGroup
                | r @ AppResponse::NoHsm
                | r @ AppResponse::NoStore
                | r @ AppResponse::NotLeader
                | r @ AppResponse::InvalidProof,
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
