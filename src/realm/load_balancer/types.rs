use actix::prelude::*;

use super::super::hsm::types::{RealmId, SecretsRequest, SecretsResponse, UserId};

#[derive(Clone, Debug, Message)]
#[rtype(result = "ClientResponse")]
pub struct ClientRequest {
    pub realm: RealmId,
    pub uid: UserId,
    pub request: SecretsRequest,
}

#[derive(Debug, MessageResponse)]
pub enum ClientResponse {
    Ok(SecretsResponse),
    Unavailable,
}
