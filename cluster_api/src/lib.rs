use serde::{Deserialize, Serialize};
use thiserror::Error;

use hsm_api::{GroupId, HsmId, OwnedRange};
use juicebox_networking::rpc::{Rpc, RpcError, Service};
use juicebox_sdk::RealmId;

#[derive(Clone, Debug)]
pub struct ClusterService;

impl Service for ClusterService {}

impl Rpc<ClusterService> for StepDownRequest {
    const PATH: &'static str = "leader_stepdown";
    type Response = StepDownResponse;
}

/// Request that a leader stepdown, and a new group member takeover leadership.
#[derive(Clone, Debug, Deserialize, Serialize)]
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

impl Rpc<ClusterService> for RebalanceRequest {
    const PATH: &'static str = "rebalance";
    type Response = Result<RebalanceSuccess, RebalanceError>;
}

/// RebalanceRequest moves zero or one group leadership roles between HSMs in
/// order to make the workload between the HSMs more even. Multiple
/// RebalanceRequest's may be needed to fully balance out the workloads.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebalanceRequest {}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RebalanceSuccess {
    /// The workloads are already as balanced as we can make them.
    AlreadyBalanced,
    /// Leadership of a group was transferred to make the cluster more balanced.
    /// There may or may not be additional changes to do.
    Rebalanced(RebalancedLeader),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebalancedLeader {
    pub realm: RealmId,
    pub group: GroupId,
    pub from: HsmId,
    pub to: HsmId,
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
pub enum RebalanceError {
    /// An attempt to move leadership was made, but the stepdown request to the
    /// current leader failed.
    #[error("Leadership stepdown failed")]
    StepDownFailed,

    /// An attempt to move leadership was made, but the planned destination
    /// failed to become leader and leadership was moved back to the original
    /// HSM.
    #[error("Failed to move leadership, it was rolled back")]
    LeadershipTransferRolledBack,

    /// An attempt to move leadership was made, but the planned destination
    /// failed to become leader, and we were also unable to get the original
    /// leader to become leader again.
    #[error("Failed to move leadership")]
    LeadershipTransferFailed,

    /// We'd like to move this group, but the group is busy with some other
    /// cluster management transition.
    #[error("The group {group:?} is busy with some other management task")]
    Busy { realm: RealmId, group: GroupId },

    #[error("Error accessing the datastore")]
    NoStore,

    #[error("An RPC Error occurred between the cluster manager and the cluster: {0:?}")]
    Rpc(#[from] RpcError),
}

impl Rpc<ClusterService> for TransferRequest {
    const PATH: &'static str = "transfer";
    type Response = Result<TransferSuccess, TransferError>;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransferRequest {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    pub range: OwnedRange,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransferSuccess {}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
pub enum TransferError {
    #[error("could not find source group leader")]
    NoSourceLeader,
    #[error("could not find destination group leader")]
    NoDestinationLeader,
    #[error("cluster manager failed to obtain management lease")]
    ManagerBusy,
    // more error cases hidden in todo!()s.
}
