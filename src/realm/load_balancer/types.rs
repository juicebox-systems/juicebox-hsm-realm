use serde::{Deserialize, Serialize};

use super::super::hsm::types::{RealmId, SecretsRequest, SecretsResponse};

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
