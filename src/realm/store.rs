use actix::prelude::*;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use tracing::trace;

mod kv;
pub mod types;

use self::types::{GetRecordProofRequest, GetRecordProofResponse};

use super::agent::Agent;
use super::hsm::types::{DataHash, GroupId, HsmId, LogEntry, LogIndex, RealmId};
use super::merkle::agent::{StoreDelta, TreeStoreError};
use kv::MemStore;
use types::{
    AddressEntry, AppendRequest, AppendResponse, DataChange, GetAddressesRequest,
    GetAddressesResponse, ReadEntryRequest, ReadEntryResponse, ReadLatestRequest,
    ReadLatestResponse, SetAddressRequest, SetAddressResponse,
};

pub struct Store {
    groups: HashMap<(RealmId, GroupId), GroupState>,
    addresses: HashMap<HsmId, Addr<Agent>>,
    kv: MemStore,
}

struct GroupState {
    log: Vec<LogEntry>, // never empty
    transferring_out: Option<StoreDelta<DataHash>>,
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
                    match request.data {
                        DataChange::Delta(delta) => {
                            self.kv.apply_store_delta(delta);
                        }
                        DataChange::Delete => {
                            panic!("not allowed to delete a group's data (because that spreads Option everywhere for not much benefit)");
                        }
                        DataChange::None => {}
                    }
                    match request.transferring_out {
                        DataChange::Delta(data) => {
                            state.transferring_out = Some(data);
                        }
                        DataChange::Delete => {
                            state.transferring_out = None;
                        }
                        DataChange::None => {}
                    }
                    AppendResponse::Ok
                } else {
                    AppendResponse::PreconditionFailed
                }
            }

            Vacant(bucket) => {
                if request.entry.index == LogIndex(1) {
                    if !matches!(request.transferring_out, DataChange::None) {
                        panic!("must initialize a group without transferring_out state");
                    };
                    match request.data {
                        DataChange::Delta(delta) => {
                            assert!(request.entry.partition.is_some());
                            self.kv.apply_store_delta(delta);
                        }
                        DataChange::Delete => panic!("not allowed to delete a group's data (because that spreads Option everywhere for not much benefit)"),
                        DataChange::None => {}
                    }
                    let state = GroupState {
                        log: vec![request.entry],
                        transferring_out: None,
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
                    transferring_out: state.transferring_out.clone(),
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
