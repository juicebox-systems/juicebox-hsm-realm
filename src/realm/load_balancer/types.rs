use actix::prelude::*;

use super::super::hsm::types::{RealmId, RecordId, SecretsRequest, SecretsResponse};

#[derive(Clone, Debug, Message)]
#[rtype(result = "ClientResponse")]
pub struct ClientRequest {
    pub realm: RealmId,
    pub rid: RecordId,
    pub request: SecretsRequest,
}

#[derive(Debug, MessageResponse)]
pub enum ClientResponse {
    Ok(SecretsResponse),
    Unavailable,
}
