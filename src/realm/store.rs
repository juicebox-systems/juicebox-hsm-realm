use actix::prelude::*;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use tracing::trace;

mod kv;
pub mod types;

use self::types::{GetRecordProofRequest, GetRecordProofResponse};

use super::agent::Agent;
use super::hsm::types::{GroupId, HsmId, LogEntry, LogIndex, RealmId};
use super::merkle::agent::TreeStoreError;
use kv::MemStore;
use types::{
    AddressEntry, AppendRequest, AppendResponse, GetAddressesRequest, GetAddressesResponse,
    ReadEntryRequest, ReadEntryResponse, ReadLatestRequest, ReadLatestResponse, SetAddressRequest,
    SetAddressResponse,
};

pub struct Store {
    groups: HashMap<(RealmId, GroupId), GroupState>,
    addresses: HashMap<HsmId, Addr<Agent>>,
    kv: MemStore,
}

struct GroupState {
    log: Vec<LogEntry>, // never empty
}

impl Store {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            addresses: HashMap::new(),
            kv: MemStore::new(),
        }
    }
}

impl Actor for Store {
    type Context = Context<Self>;
}

impl Handler<AppendRequest> for Store {
    type Result = AppendResponse;

    fn handle(&mut self, request: AppendRequest, _ctx: &mut Context<Self>) -> Self::Result {
        trace!(?request);

        let response = match self.groups.entry((request.realm, request.group)) {
            Occupied(mut bucket) => {
                let state = bucket.get_mut();
                let last = state.log.last().unwrap();
                if request.entry.index == last.index.next() {
                    state.log.push(request.entry);
                    if let Some(delta) = request.delta {
                        self.kv.apply_store_delta(delta);
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
                        self.kv.apply_store_delta(delta);
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
        response
    }
}

impl Handler<ReadEntryRequest> for Store {
    type Result = ReadEntryResponse;

    fn handle(&mut self, request: ReadEntryRequest, _ctx: &mut Context<Self>) -> Self::Result {
        type Response = ReadEntryResponse;
        trace!(?request);
        let response = match self.groups.get(&(request.realm, request.group)) {
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
        response
    }
}

impl Handler<ReadLatestRequest> for Store {
    type Result = ReadLatestResponse;

    fn handle(&mut self, request: ReadLatestRequest, _ctx: &mut Context<Self>) -> Self::Result {
        trace!(?request);
        let response = match self.groups.get(&(request.realm, request.group)) {
            None => ReadLatestResponse::None,

            Some(state) => {
                let last = state.log.last().unwrap();
                ReadLatestResponse::Ok {
                    entry: last.clone(),
                }
            }
        };
        trace!(?response);
        response
    }
}

impl Handler<GetRecordProofRequest> for Store {
    type Result = GetRecordProofResponse;

    fn handle(&mut self, request: GetRecordProofRequest, _ctx: &mut Context<Self>) -> Self::Result {
        trace!(?request);
        let response = match self.groups.get(&(request.realm, request.group)) {
            None => GetRecordProofResponse::UnknownGroup,

            Some(state) => {
                let last = state.log.last().unwrap();
                match &last.partition {
                    None => GetRecordProofResponse::NotOwner,
                    Some(partition) => {
                        if !partition.prefix.contains(&request.record) {
                            GetRecordProofResponse::NotOwner
                        } else {
                            match super::merkle::agent::read(
                                &self.kv,
                                &partition.root_hash,
                                &request.record.0,
                                partition.prefix.0.len(),
                            ) {
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
        response
    }
}

impl Handler<SetAddressRequest> for Store {
    type Result = SetAddressResponse;

    fn handle(&mut self, request: SetAddressRequest, _ctx: &mut Context<Self>) -> Self::Result {
        trace!(?request);
        self.addresses.insert(request.hsm, request.address);
        let response = SetAddressResponse::Ok;
        trace!(?response);
        response
    }
}

impl Handler<GetAddressesRequest> for Store {
    type Result = GetAddressesResponse;

    fn handle(&mut self, request: GetAddressesRequest, _ctx: &mut Context<Self>) -> Self::Result {
        trace!(?request);
        let response = GetAddressesResponse(
            self.addresses
                .iter()
                .map(|(hsm, address)| AddressEntry {
                    hsm: *hsm,
                    address: address.clone(),
                })
                .collect(),
        );
        trace!(?response);
        response
    }
}
