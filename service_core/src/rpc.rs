use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming as IncomingBody, Request, Response};
use std::future::Future;
use tracing::warn;

use juicebox_marshalling as marshalling;
use juicebox_networking::rpc::{Rpc, Service};

#[derive(Debug)]
pub enum HandlerError {
    // We'd use this if we wanted to return non-200 HTTP statuses or drop the
    // connection. For now, there's nothing here.
}

pub async fn handle_rpc<'a, S, H, R: Rpc<SVC>, SVC: Service, O>(
    service: &'a S,
    incoming_request: Request<IncomingBody>,
    handler: H,
) -> Result<Response<Full<Bytes>>, hyper::Error>
where
    H: Fn(&'a S, R) -> O,
    O: Future<Output = Result<R::Response, HandlerError>>,
{
    let request_bytes = incoming_request.collect().await?.to_bytes();
    let request: R = match marshalling::from_slice(request_bytes.as_ref()) {
        Ok(request) => request,
        Err(e) => {
            warn!(error = ?e, "deserialization error");
            return Ok(Response::builder()
                .status(hyper::StatusCode::BAD_REQUEST)
                .body(Full::from(Bytes::new()))
                .unwrap());
        }
    };

    let response = handler(service, request).await;
    match response {
        Err(e) => match e { /* no possible errors */ },
        Ok(response) => {
            let response_bytes = match marshalling::to_vec(&response) {
                Ok(response_bytes) => response_bytes,
                Err(e) => {
                    warn!(error = ?e, ?response, "serialization error");
                    return Ok(Response::builder()
                        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::from(Bytes::new()))
                        .unwrap());
                }
            };
            Ok(Response::builder()
                .body(Full::new(Bytes::from(response_bytes)))
                .unwrap())
        }
    }
}
