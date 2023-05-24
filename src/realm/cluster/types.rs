use serde::{Deserialize, Serialize};

use hsmcore::hsm::types::{GroupId, HsmId};
use juicebox_sdk::RealmId;
use juicebox_sdk_networking::rpc::{Rpc, RpcError, Service};

#[derive(Clone, Debug)]
pub struct ClusterService();
impl Service for ClusterService {}

impl Rpc<ClusterService> for StepDownRequest {
    const PATH: &'static str = "leader_stepdown";
    type Response = StepDownResponse;
}

/// Request that a leader stepdown, and a new group member takeover leadership.
#[derive(Debug, Deserialize, Serialize)]
pub enum StepDownRequest {
    /// Have this specific HSM stepdown for all groups it's leading.
    Hsm(HsmId),
    /// Have the current leader for this group step down.
    Group { realm: RealmId, group: GroupId },
}

#[derive(Debug, Deserialize, Serialize)]
pub enum StepDownResponse {
    Ok,
    NoHsm,
    NoStore,
    NotLeader,
    InvalidRealm,
    InvalidGroup,
    InvalidHsm,
    // This group is busy with some other cluster management transition.
    Busy { realm: RealmId, group: GroupId },
    RpcError(RpcError),
}
