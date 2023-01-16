use actix::prelude::*;
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use tracing::trace;

pub mod types;

use super::agent::Agent;
use super::hsm::types::{GroupId, HsmId, LogEntry, LogIndex, RealmId};
use types::{
    AddressEntry, AppendRequest, AppendResponse, GetAddressesRequest, GetAddressesResponse,
    ReadRequest, ReadResponse, SetAddressRequest, SetAddressResponse,
};

pub struct Store {
    groups: HashMap<(RealmId, GroupId), GroupState>,
    addresses: HashMap<HsmId, Addr<Agent>>,
}

struct GroupState {
    log: Vec<LogEntry>, // never empty
    data: Vec<u8>,
}

impl Store {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            addresses: HashMap::new(),
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
                if request.entry.index == LogIndex(last.index.0 + 1) {
                    state.log.push(request.entry);
                    state.data = request.data;
                    AppendResponse::Ok
                } else {
                    AppendResponse::PreconditionFailed
                }
            }

            Vacant(bucket) => {
                if request.entry.index == LogIndex(1) {
                    bucket.insert(GroupState {
                        log: vec![request.entry],
                        data: request.data,
                    });
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

impl Handler<ReadRequest> for Store {
    type Result = ReadResponse;

    fn handle(&mut self, request: ReadRequest, _ctx: &mut Context<Self>) -> Self::Result {
        trace!(?request);
        let response = match self.groups.get(&(request.realm, request.group)) {
            None => ReadResponse::Discarded { start: LogIndex(1) },

            Some(state) => {
                let first = state.log.first().unwrap();
                let last = state.log.last().unwrap();
                if request.index < first.index {
                    ReadResponse::Discarded { start: first.index }
                } else if request.index > last.index {
                    ReadResponse::DoesNotExist { last: last.index }
                } else {
                    let offset = usize::try_from(request.index.0 - first.index.0).unwrap();
                    ReadResponse::Ok(state.log.get(offset).unwrap().clone())
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
