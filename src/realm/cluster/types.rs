use serde::{Deserialize, Serialize};

use hsmcore::hsm::types::{GroupId, HsmId};
use loam_sdk::RealmId;
use loam_sdk_networking::rpc::{Rpc, RpcError, Service};

#[derive(Clone, Debug)]
pub struct ClusterService();
impl Service for ClusterService {}

impl Rpc<ClusterService> for StepdownAsLeaderRequest {
    const PATH: &'static str = "leader_stepdown";
    type Response = StepdownAsLeaderResponse;
}

/// Request that a leader stepdown, and a new group member takeover leadership.
#[derive(Debug, Deserialize, Serialize)]
pub enum StepdownAsLeaderRequest {
    /// Have this specific HSM stepdown for all groups it's leading.
    Hsm(HsmId),
    /// Have the current leader for this group step down.
    Group { realm: RealmId, group: GroupId },
}

#[derive(Debug, Deserialize, Serialize)]
pub enum StepdownAsLeaderResponse {
    Ok,
    NoHsm,
    NoStore,
    InvalidRealm,
    InvalidGroup,
    InvalidHsm,
    RpcError(RpcError),
}
