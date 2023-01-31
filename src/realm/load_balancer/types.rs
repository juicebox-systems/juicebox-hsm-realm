use actix::prelude::*;

use super::super::hsm::types::{RealmId, SecretsRequest, SecretsResponse};

#[derive(Clone, Debug, Message)]
#[rtype(result = "ClientResponse")]
pub struct ClientRequest {
    pub realm: RealmId,
    pub request: SecretsRequest,
}

#[derive(Debug, MessageResponse)]
#[allow(clippy::large_enum_variant)]
pub enum ClientResponse {
    Ok(SecretsResponse),
    Unavailable,
}
