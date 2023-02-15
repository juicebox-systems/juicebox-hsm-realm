use bytes::Bytes;
use futures::lock::Mutex;
use futures::Future;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use reqwest::Url;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{trace, warn};

mod kv;
pub mod types;

use self::types::{
    GetRecordProofRequest, GetRecordProofResponse, GetTreeEdgeProofRequest,
    GetTreeEdgeProofResponse,
};
use super::hsm::types::{GroupId, HsmId, LogEntry, LogIndex, RealmId};
use super::merkle::agent::TreeStoreError;
use super::rpc::{handle_rpc, HandlerError, Rpc};
use kv::MemStore;
use types::{
    AddressEntry, AppendRequest, AppendResponse, GetAddressesRequest, GetAddressesResponse,
    ReadEntryRequest, ReadEntryResponse, ReadLatestRequest, ReadLatestResponse, SetAddressRequest,
    SetAddressResponse,
};

#[derive(Clone)]
pub struct Store(Arc<InnerStore>);

struct InnerStore {
    state: Mutex<State>,
}
struct State {
    groups: HashMap<(RealmId, GroupId), GroupState>,
    addresses: HashMap<HsmId, Url>,
    kv: MemStore,
}

struct GroupState {
    log: Vec<LogEntry>, // never empty
}

impl Store {
    pub fn new() -> Self {
        Self(Arc::new(InnerStore {
            state: Mutex::new(State {
                groups: HashMap::new(),
                addresses: HashMap::new(),
                kv: MemStore::new(),
            }),
        }))
    }
}

impl Service<Request<IncomingBody>> for Store {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&mut self, request: Request<IncomingBody>) -> Self::Future {
        let store = self.clone();
        Box::pin(async move {
            let Some(path) = request.uri().path().strip_prefix('/') else {
                return Ok(Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(Full::from(Bytes::new()))
                    .unwrap());
            };
            match path {
                AppendRequest::PATH => handle_rpc(&store, request, Self::handle_append).await,
                ReadEntryRequest::PATH => {
                    handle_rpc(&store, request, Self::handle_read_entry).await
                }
                ReadLatestRequest::PATH => {
                    handle_rpc(&store, request, Self::handle_read_latest).await
                }
                GetRecordProofRequest::PATH => {
                    handle_rpc(&store, request, Self::handle_record_proof).await
                }
                GetTreeEdgeProofRequest::PATH => {
                    handle_rpc(&store, request, Self::handle_tree_proof).await
                }
                SetAddressRequest::PATH => {
                    handle_rpc(&store, request, Self::handle_set_address).await
                }
                GetAddressesRequest::PATH => {
                    handle_rpc(&store, request, Self::handle_get_address).await
                }
                _ => Ok(Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(Full::from(Bytes::new()))
                    .unwrap()),
            }
        })
    }
}

impl Store {
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
                            let store = self.clone();
                            tokio::spawn(async move {
                                if let Err(e) = http1::Builder::new()
                                    .serve_connection(stream, store.clone())
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

    async fn handle_append(&self, request: AppendRequest) -> Result<AppendResponse, HandlerError> {
        trace!(?request);
        let mut store_state_lock = self.0.state.lock().await;
        let store_state: &mut State = &mut store_state_lock;

        let response = match store_state.groups.entry((request.realm, request.group)) {
            Occupied(mut bucket) => {
                let state = bucket.get_mut();
                let last = state.log.last().unwrap();
                if request.entry.index == last.index.next() {
                    state.log.push(request.entry);
                    if let Some(delta) = request.delta {
                        store_state.kv.apply_store_delta(&request.realm, delta);
                    }
                    AppendResponse::Ok
                } else {
                    AppendResponse::PreconditionFailed
                }
            }

            Vacant(bucket) => {
                if request.entry.index == LogIndex(1) {
                    if let Some(delta) = request.delta {
                        assert!(request.entry.partition.is_some());
                        store_state.kv.apply_store_delta(&request.realm, delta);
                    }
                    let state = GroupState {
                        log: vec![request.entry],
                    };
                    bucket.insert(state);
                    AppendResponse::Ok
                } else {
                    AppendResponse::PreconditionFailed
                }
            }
        };
        trace!(?response);
        Ok(response)
    }

    async fn handle_read_entry(
        &self,
        request: ReadEntryRequest,
    ) -> Result<ReadEntryResponse, HandlerError> {
        type Response = ReadEntryResponse;
        trace!(?request);

        let store_state = self.0.state.lock().await;
        let response = match store_state.groups.get(&(request.realm, request.group)) {
            None => Response::Discarded { start: LogIndex(1) },

            Some(state) => {
                let first = state.log.first().unwrap();
                let last = state.log.last().unwrap();
                if request.index < first.index {
                    Response::Discarded { start: first.index }
                } else if request.index > last.index {
                    Response::DoesNotExist { last: last.index }
                } else {
                    let offset = usize::try_from(request.index.0 - first.index.0).unwrap();
                    Response::Ok(state.log.get(offset).unwrap().clone())
                }
            }
        };
        trace!(?response);
        Ok(response)
    }

    async fn handle_read_latest(
        &self,
        request: ReadLatestRequest,
    ) -> Result<ReadLatestResponse, HandlerError> {
        trace!(?request);
        let store_state = self.0.state.lock().await;
        let response = match store_state.groups.get(&(request.realm, request.group)) {
            None => ReadLatestResponse::None,

            Some(state) => {
                let last = state.log.last().unwrap();
                ReadLatestResponse::Ok {
                    entry: last.clone(),
                }
            }
        };
        trace!(?response);
        Ok(response)
    }

    async fn handle_record_proof(
        &self,
        request: GetRecordProofRequest,
    ) -> Result<GetRecordProofResponse, HandlerError> {
        trace!(?request);
        let store_state = self.0.state.lock().await;
        let response = match store_state.groups.get(&(request.realm, request.group)) {
            None => GetRecordProofResponse::UnknownGroup,

            Some(state) => {
                let last = state.log.last().unwrap();
                match &last.partition {
                    None => GetRecordProofResponse::NotOwner,
                    Some(partition) => {
                        if !partition.range.contains(&request.record) {
                            GetRecordProofResponse::NotOwner
                        } else {
                            match super::merkle::agent::read(
                                &store_state.kv.reader(&request.realm),
                                &partition.range,
                                &partition.root_hash,
                                &request.record,
                            )
                            .await
                            {
                                Ok(proof) => GetRecordProofResponse::Ok {
                                    proof,
                                    index: last.index,
                                },
                                Err(TreeStoreError::MissingNode) => {
                                    GetRecordProofResponse::StoreMissingNode
                                }
                            }
                        }
                    }
                }
            }
        };
        trace!(?response);
        Ok(response)
    }

    async fn handle_tree_proof(
        &self,
        request: GetTreeEdgeProofRequest,
    ) -> Result<GetTreeEdgeProofResponse, HandlerError> {
        trace!(?request);
        let store_state = self.0.state.lock().await;
        let response = match store_state.groups.get(&(request.realm, request.group)) {
            None => GetTreeEdgeProofResponse::UnknownGroup,

            Some(_) => {
                match super::merkle::agent::read_tree_side(
                    &store_state.kv.reader(&request.realm),
                    &request.partition.range,
                    &request.partition.root_hash,
                    request.dir,
                ) {
                    Ok(proof) => GetTreeEdgeProofResponse::Ok { proof },
                    Err(TreeStoreError::MissingNode) => GetTreeEdgeProofResponse::StoreMissingNode,
                }
            }
        };
        trace!(?response);
        Ok(response)
    }

    async fn handle_set_address(
        &self,
        request: SetAddressRequest,
    ) -> Result<SetAddressResponse, HandlerError> {
        trace!(?request);
        let mut store_state = self.0.state.lock().await;
        store_state.addresses.insert(request.hsm, request.address);
        let response = SetAddressResponse::Ok;
        trace!(?response);
        Ok(response)
    }

    async fn handle_get_address(
        &self,
        request: GetAddressesRequest,
    ) -> Result<GetAddressesResponse, HandlerError> {
        trace!(?request);
        let store_state = self.0.state.lock().await;
        let response = GetAddressesResponse(
            store_state
                .addresses
                .iter()
                .map(|(hsm, address)| AddressEntry {
                    hsm: *hsm,
                    address: address.clone(),
                })
                .collect(),
        );
        trace!(?response);
        Ok(response)
    }
}
