use serde::{Deserialize, Serialize};

use crate::realm::rpc::Service;

use super::super::hsm::types::{RealmId, SecretsRequest, SecretsResponse};
use super::super::rpc::Rpc;

#[derive(Clone, Debug)]
pub struct LoadBalancerRpc();
impl Service for LoadBalancerRpc {}

impl Rpc for ClientRequest {
    const PATH: &'static str = "req";
    type Response = ClientResponse;
    type Family = LoadBalancerRpc;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientRequest {
    pub realm: RealmId,
    pub request: SecretsRequest,
}

#[derive(Debug, Deserialize, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ClientResponse {
    Ok(SecretsResponse),
    Unavailable,
}
