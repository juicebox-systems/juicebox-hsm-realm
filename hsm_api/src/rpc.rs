extern crate alloc;

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt::Debug;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::{
    AppRequest, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse, CaptureNextRequest,
    CaptureNextResponse, CommitRequest, CommitResponse, CompleteTransferRequest,
    CompleteTransferResponse, HandshakeRequest, HandshakeResponse, JoinGroupRequest,
    JoinGroupResponse, JoinRealmRequest, JoinRealmResponse, NewGroupRequest, NewGroupResponse,
    NewRealmRequest, NewRealmResponse, PersistStateRequest, PersistStateResponse, StatusRequest,
    StatusResponse, StepDownRequest, StepDownResponse, TransferInRequest, TransferInResponse,
    TransferNonceRequest, TransferNonceResponse, TransferOutRequest, TransferOutResponse,
    TransferStatementRequest, TransferStatementResponse,
};

// Nanoseconds upto ~4.29 seconds.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialOrd, PartialEq, Serialize)]
pub struct Nanos(pub u32);

impl Nanos {
    pub const ZERO: Nanos = Nanos(0);
    pub const ONE_SECOND: Nanos = Nanos(1_000_000_000);
    pub const MAX: Nanos = Nanos(u32::MAX);
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MetricsAction {
    // Don't record any metrics.
    Skip,
    // Record metrics for the request.
    Record,
}

#[derive(Deserialize, Serialize)]
pub struct HsmRequestContainer {
    pub req: HsmRequest,
    pub metrics: MetricsAction,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HsmResponseContainer<'a, T> {
    pub res: T,
    // Empty unless Record was specified as the metrics action in the request.
    pub metrics: Vec<(Cow<'a, str>, Nanos)>,
}

pub trait HsmRpc: DeserializeOwned + Serialize + Debug {
    type Response: DeserializeOwned + Serialize + Debug;
    fn to_req(self) -> HsmRequest;
}

// HsmRequest is what is sent over the "wire" to the HSM itself.
#[derive(Serialize, Deserialize)]
pub enum HsmRequest {
    Status(StatusRequest),
    NewRealm(NewRealmRequest),
    JoinRealm(JoinRealmRequest),
    NewGroup(NewGroupRequest),
    JoinGroup(JoinGroupRequest),
    BecomeLeader(BecomeLeaderRequest),
    StepDown(StepDownRequest),
    CaptureNext(CaptureNextRequest),
    PersistState(PersistStateRequest),
    Commit(CommitRequest),
    TransferOut(TransferOutRequest),
    TransferNonce(TransferNonceRequest),
    TransferStatement(TransferStatementRequest),
    TransferIn(TransferInRequest),
    CompleteTransfer(CompleteTransferRequest),
    HandshakeRequest(HandshakeRequest),
    AppRequest(AppRequest),
}

impl HsmRequest {
    pub fn name(&self) -> &'static str {
        match self {
            HsmRequest::Status(_) => "Status",
            HsmRequest::NewRealm(_) => "NewRealm",
            HsmRequest::JoinRealm(_) => "JoinRealm",
            HsmRequest::NewGroup(_) => "NewGroup",
            HsmRequest::JoinGroup(_) => "JoinGroup",
            HsmRequest::BecomeLeader(_) => "BecomeLeader",
            HsmRequest::StepDown(_) => "StepDown",
            HsmRequest::CaptureNext(_) => "CaptureNext",
            HsmRequest::PersistState(_) => "PersistState",
            HsmRequest::Commit(_) => "Commit",
            HsmRequest::TransferOut(_) => "TransferOut",
            HsmRequest::TransferNonce(_) => "TransferNonce",
            HsmRequest::TransferStatement(_) => "TransferStatement",
            HsmRequest::TransferIn(_) => "TransferIn",
            HsmRequest::CompleteTransfer(_) => "CompleteTransfer",
            HsmRequest::HandshakeRequest(_) => "HandshakeRequest",
            HsmRequest::AppRequest(_) => "AppRequest",
        }
    }
}

impl HsmRpc for StatusRequest {
    type Response = StatusResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::Status(self)
    }
}
impl HsmRpc for NewRealmRequest {
    type Response = NewRealmResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::NewRealm(self)
    }
}
impl HsmRpc for JoinRealmRequest {
    type Response = JoinRealmResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::JoinRealm(self)
    }
}
impl HsmRpc for NewGroupRequest {
    type Response = NewGroupResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::NewGroup(self)
    }
}
impl HsmRpc for JoinGroupRequest {
    type Response = JoinGroupResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::JoinGroup(self)
    }
}
impl HsmRpc for CaptureNextRequest {
    type Response = CaptureNextResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::CaptureNext(self)
    }
}

impl HsmRpc for PersistStateRequest {
    type Response = PersistStateResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::PersistState(self)
    }
}

impl HsmRpc for BecomeLeaderRequest {
    type Response = BecomeLeaderResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::BecomeLeader(self)
    }
}

impl HsmRpc for StepDownRequest {
    type Response = StepDownResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::StepDown(self)
    }
}

impl HsmRpc for CommitRequest {
    type Response = CommitResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::Commit(self)
    }
}
impl HsmRpc for TransferOutRequest {
    type Response = TransferOutResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::TransferOut(self)
    }
}
impl HsmRpc for TransferNonceRequest {
    type Response = TransferNonceResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::TransferNonce(self)
    }
}
impl HsmRpc for TransferStatementRequest {
    type Response = TransferStatementResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::TransferStatement(self)
    }
}
impl HsmRpc for TransferInRequest {
    type Response = TransferInResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::TransferIn(self)
    }
}
impl HsmRpc for CompleteTransferRequest {
    type Response = CompleteTransferResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::CompleteTransfer(self)
    }
}
impl HsmRpc for HandshakeRequest {
    type Response = HandshakeResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::HandshakeRequest(self)
    }
}
impl HsmRpc for AppRequest {
    type Response = AppResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::AppRequest(self)
    }
}
