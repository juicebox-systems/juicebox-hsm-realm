extern crate alloc;

use alloc::{borrow::Cow, string::String, vec::Vec};
use core::fmt::Debug;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::super::hal::Nanos;
use super::types::{
    AppRequest, AppResponse, BecomeLeaderRequest, BecomeLeaderResponse, CaptureNextRequest,
    CaptureNextResponse, CommitRequest, CommitResponse, CompleteTransferRequest,
    CompleteTransferResponse, JoinGroupRequest, JoinGroupResponse, JoinRealmRequest,
    JoinRealmResponse, NewGroupRequest, NewGroupResponse, NewRealmRequest, NewRealmResponse,
    ReadCapturedRequest, ReadCapturedResponse, StatusRequest, StatusResponse, TransferInRequest,
    TransferInResponse, TransferNonceRequest, TransferNonceResponse, TransferOutRequest,
    TransferOutResponse, TransferStatementRequest, TransferStatementResponse,
};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub enum MetricsAction {
    // Record metrics.
    Record,
    // Records and then reports metrics back to the client and resets the HSM in memory metrics.
    ReportAndReset,
}

#[derive(Deserialize, Serialize)]
pub struct HsmRequestContainer {
    pub req: HsmRequest,
    pub metrics: Option<MetricsAction>,
}

#[derive(Deserialize, Serialize)]
pub struct HsmResponseContainer<'a, T> {
    pub res: T,
    // None unless ReportAndReset was specified as the metrics action.
    pub metrics: Option<HsmMetrics<'a>>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct HsmMetrics<'a> {
    // Uses Cow so that serialize can be on references, and deserialize
    // can create new ones.
    pub metrics: Vec<Cow<'a, HsmMetric>>,
    pub hsm_name: Cow<'a, String>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct HsmMetric {
    pub name: String,
    pub units: String,
    pub points: Vec<Nanos>,
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
    CaptureNext(CaptureNextRequest),
    ReadCaptured(ReadCapturedRequest),
    Commit(CommitRequest),
    TransferOut(TransferOutRequest),
    TransferNonce(TransferNonceRequest),
    TransferStatement(TransferStatementRequest),
    TransferIn(TransferInRequest),
    CompleteTransfer(CompleteTransferRequest),
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
            HsmRequest::CaptureNext(_) => "CaptureNext",
            HsmRequest::ReadCaptured(_) => "ReadCaptured",
            HsmRequest::Commit(_) => "Commit",
            HsmRequest::TransferOut(_) => "TransferOut",
            HsmRequest::TransferNonce(_) => "TransferNonce",
            HsmRequest::TransferStatement(_) => "TransferStatement",
            HsmRequest::TransferIn(_) => "TransferIn",
            HsmRequest::CompleteTransfer(_) => "CompleteTransfer",
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
impl HsmRpc for ReadCapturedRequest {
    type Response = ReadCapturedResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::ReadCaptured(self)
    }
}
impl HsmRpc for BecomeLeaderRequest {
    type Response = BecomeLeaderResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::BecomeLeader(self)
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
impl HsmRpc for AppRequest {
    type Response = AppResponse;
    fn to_req(self) -> HsmRequest {
        HsmRequest::AppRequest(self)
    }
}
