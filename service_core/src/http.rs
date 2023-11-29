use ::reqwest::Error;
use async_trait::async_trait;
use std::time::Instant;

use juicebox_networking::http as jb_http;
use juicebox_networking::reqwest;
use observability::metrics::{self, Tag};
use observability::metrics_tag as tag;

#[derive(Clone, Debug)]
pub struct ReqwestClientMetrics {
    pub client: reqwest::Client,
    metrics: metrics::Client,
}

impl ReqwestClientMetrics {
    pub fn new(metrics: metrics::Client, options: reqwest::ClientOptions) -> Self {
        Self {
            client: reqwest::Client::new(options),
            metrics,
        }
    }
}

#[async_trait]
impl jb_http::Client for ReqwestClientMetrics {
    async fn send(&self, request: jb_http::Request) -> Option<jb_http::Response> {
        let start = Instant::now();
        let url = request.url.clone();
        let method = request.method;

        let req_builder = self.client.to_reqwest(request);
        let resp = req_builder.send().await;
        let mapper = self.client.to_response(resp);
        let result = mapper.await;

        let elapsed = start.elapsed();
        let mut tags = Vec::with_capacity(4);
        tags.push(tag!(?method));
        tags.push(tag!(?url));
        match &result {
            Err(err) => {
                tags.push(error_tag(err));
                if let Some(status_code) = err.status() {
                    tags.push(tag!(?status_code))
                }
            }
            Ok(r) => {
                let status_code = r.status_code;
                tags.push(tag!(status_code));
            }
        };
        self.metrics.timing("reqwest.client.time", elapsed, tags);
        result.ok()
    }
}

fn error_tag(e: &Error) -> Tag {
    if e.is_body() {
        tag!("err": "body")
    } else if e.is_builder() {
        tag!("err": "builder")
    } else if e.is_connect() {
        tag!("err": "connect")
    } else if e.is_decode() {
        tag!("err": "decode")
    } else if e.is_redirect() {
        tag!("err": "redirect")
    } else if e.is_request() {
        tag!("err": "request")
    } else if e.is_status() {
        tag!("err": "status")
    } else if e.is_timeout() {
        tag!("err": "timeout")
    } else {
        tag!("err": "unknown")
    }
}
