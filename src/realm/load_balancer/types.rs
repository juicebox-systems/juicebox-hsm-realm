use serde::{Deserialize, Serialize};

use crate::realm::rpc::Service;

use super::super::rpc::Rpc;
use hsmcore::hsm::types::{RealmId, SecretsRequest, SecretsResponse};
use hsmcore::types::AuthToken;

#[derive(Clone, Debug)]
pub struct LoadBalancerService();
impl Service for LoadBalancerService {}

impl Rpc<LoadBalancerService> for ClientRequest {
    const PATH: &'static str = "req";
    type Response = ClientResponse;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientRequest {
    pub realm: RealmId,
    pub auth_token: AuthToken,
    pub request: SecretsRequest,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ClientResponse {
    Ok(SecretsResponse),
    Unavailable,
    InvalidAuth,
}
