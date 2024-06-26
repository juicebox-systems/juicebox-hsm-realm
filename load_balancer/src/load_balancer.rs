use anyhow::{anyhow, Context};
use blake2::Blake2sMac256;
use bytes::Bytes;
use digest::{FixedOutput, KeyInit};
use futures::future::join_all;
use futures::{select_biased, FutureExt};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming as IncomingBody;
use hyper::http::HeaderValue;
use hyper::server::conn::{http1, http2};
use hyper::service::Service;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::server::ResolvesServerCert;
use semver::Version;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::iter::zip;
use std::net::SocketAddr;
use std::pin::{pin, Pin};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_rustls::{rustls, TlsAcceptor};
use tracing::{span, trace, warn, Instrument, Level, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use super::server::{HealthCheckStatus, ManagerOptions, ServiceManager};
use agent_api::{AppRequest, AppResponse, HashedUserId, StatusRequest, StatusResponse};
use hsm_api::{GroupId, OwnedRange, RecordId};
use jburl::Url;
use juicebox_marshalling as marshalling;
use juicebox_networking::reqwest::ClientOptions;
use juicebox_networking::rpc::{self, SendOptions};
use juicebox_realm_api::requests::{ClientRequest, ClientResponse, BODY_SIZE_LIMIT};
use juicebox_realm_api::types::{RealmId, SecretBytesArray, JUICEBOX_VERSION_HEADER};
use juicebox_realm_auth::validation::{Require, Validator as AuthTokenValidator};
use juicebox_realm_auth::Scope;
use observability::logging::TracingSource;
use observability::metrics::{self, Tag};
use observability::metrics_tag as tag;
use observability::tracing::TracingMiddleware;
use secret_manager::{
    record_id_randomization_key_name, tenant_secret_name, Secret, SecretAlgorithm, SecretManager,
};
use service_core::http::ReqwestClientMetrics;
use store::{ServiceKind, StoreClient};

#[derive(Clone)]
pub struct LoadBalancer(Arc<State>);

struct State {
    name: String,
    store: StoreClient,
    secret_manager: Box<dyn SecretManager>,
    agent_client: ReqwestClientMetrics,
    realms: Mutex<Arc<HashMap<RealmId, Vec<Partition>>>>,
    metrics: metrics::Client,
    semver: Version,
    svc_mgr: ServiceManager,
    record_id_randomization_key: RecordIdRandomizationKey,
}

impl LoadBalancer {
    pub async fn new(
        name: String,
        store: StoreClient,
        secret_manager: Box<dyn SecretManager>,
        metrics: metrics::Client,
        svc_cfg: ManagerOptions,
    ) -> Result<Self, anyhow::Error> {
        let (_version, secret) = secret_manager
            .get_latest_secret_version(&record_id_randomization_key_name())
            .await?
            .ok_or_else(|| anyhow!("missing secret: {}", record_id_randomization_key_name().0))?;

        Ok(Self(Arc::new(State {
            name,
            store,
            secret_manager,
            record_id_randomization_key: secret.try_into().context(format!(
                "failed to convert secret to key: {}",
                record_id_randomization_key_name().0
            ))?,
            agent_client: ReqwestClientMetrics::new(metrics.clone(), ClientOptions::default()),
            realms: Mutex::new(Arc::new(HashMap::new())),
            metrics: metrics.clone(),
            semver: Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            svc_mgr: ServiceManager::new(svc_cfg, metrics),
        })))
    }

    pub async fn listen(
        self,
        address: SocketAddr,
        cert_resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<(Url, JoinHandle<()>), anyhow::Error> {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("failed to bind to {address}"))?;
        let url = Url::parse(&format!("https://{address}")).unwrap();
        self.start_refresher().await;

        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(cert_resolver);
        assert!(config.alpn_protocols.is_empty());
        config
            .alpn_protocols
            .extend([b"h2".to_vec(), b"http/1.1".to_vec()]);

        let acceptor = TlsAcceptor::from(Arc::new(config));

        Ok((
            url,
            tokio::spawn(async move {
                let mgr = self.0.svc_mgr.clone();
                let mut start_drain_rx = mgr.subscribe_start_draining();
                let mut start_drain = pin!(start_drain_rx.wait_for(|start| *start).fuse());
                loop {
                    let accept_result = select_biased! {
                        _ = start_drain => return,
                        r = listener.accept().fuse() => r
                    };
                    match accept_result {
                        Err(error) => {
                            warn!(%error, "error accepting connection")
                        }
                        Ok((stream, _)) => {
                            let acceptor = acceptor.clone();
                            let lb = TracingMiddleware::new(self.clone());
                            let metrics = self.0.metrics.clone();
                            let mgr = mgr.clone();
                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Err(error) => {
                                        warn!(%error, "error terminating TLS connection");
                                    }
                                    Ok(stream) => {
                                        let (_, connection) = stream.get_ref();
                                        let protocol = match connection.alpn_protocol() {
                                            Some(b"h2") => "h2",
                                            _ => "http/1.1",
                                        };
                                        metrics.incr(
                                            "load_balancer.connections.count",
                                            [tag!(protocol)],
                                        );
                                        let io = TokioIo::new(stream);
                                        let result = match protocol {
                                            "h2" => {
                                                let c = http2::Builder::new(TokioExecutor)
                                                    .max_header_list_size(4096)
                                                    .serve_connection(io, lb);
                                                let c = mgr.manage(c).await;
                                                c.await
                                            }
                                            "http/1.1" => {
                                                let c =
                                                    http1::Builder::new().serve_connection(io, lb);
                                                let c = mgr.manage(c).await;
                                                c.await
                                            }
                                            _ => unreachable!(),
                                        };
                                        if let Err(error) = result {
                                            metrics.incr(
                                                "load_balancer.connections.errors",
                                                [tag!(protocol)],
                                            );
                                            warn!(%error, protocol, "error serving connection");
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
            }),
        ))
    }

    pub async fn shut_down(&self) {
        self.0.svc_mgr.shut_down().await;
    }

    async fn start_refresher(&self) {
        let state = self.0.clone();
        tokio::spawn(async move {
            let cx = opentelemetry::Context::new().with_value(TracingSource::BackgroundJob);

            loop {
                let span = span!(Level::TRACE, "refresher_loop");
                span.set_parent(cx.clone());

                let updated = refresh(&state.name, &state.store, &state.agent_client)
                    .instrument(span)
                    .await;
                *state.realms.lock().unwrap() = Arc::new(updated);
                time::sleep(Duration::from_millis(100)).await;
            }
        });
    }
}

#[derive(Debug)]
struct Partition {
    group: GroupId,
    owned_range: OwnedRange,
    leader: Url,
}

#[tracing::instrument(level = "trace", skip(store, agent_client))]
async fn refresh(
    name: &str,
    store: &StoreClient,
    agent_client: &ReqwestClientMetrics,
) -> HashMap<RealmId, Vec<Partition>> {
    match store.get_addresses(Some(ServiceKind::Agent)).await {
        Err(err) => todo!("{err:?}"),
        Ok(addresses) => {
            let responses = join_all(addresses.iter().map(|(address, _)| {
                rpc::send_with_options(
                    agent_client,
                    address,
                    StatusRequest {},
                    SendOptions::default().with_timeout(Duration::from_secs(5)),
                )
            }))
            .await;

            let mut realms: HashMap<RealmId, Vec<Partition>> = HashMap::new();
            for ((agent, _), response) in zip(addresses, responses) {
                match response {
                    Ok(StatusResponse {
                        hsm:
                            Some(hsm_api::StatusResponse {
                                realm: Some(status),
                                ..
                            }),
                        ..
                    }) => {
                        let realm = realms.entry(status.id).or_default();
                        for group in status.groups {
                            if let Some(leader) = group.leader {
                                if let Some(owned_range) = leader.owned_range {
                                    realm.push(Partition {
                                        group: group.id,
                                        owned_range,
                                        leader: agent.clone(),
                                    });
                                }
                            }
                        }
                    }

                    Ok(_) => {}

                    Err(err) => {
                        warn!(load_balancer = name, %agent, %err, "could not get status");
                    }
                }
            }
            realms
        }
    }
}

impl Service<Request<IncomingBody>> for LoadBalancer {
    type Response = Response<Full<Bytes>>;
    type Error = Box<dyn Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, request: Request<IncomingBody>) -> Self::Future {
        let state = self.clone();

        Box::pin(
            async move {
                let start = Instant::now();
                let mut result = match (request.uri().path(), request.method()) {
                    ("/req", &Method::POST) => state.handle_req(request).await,
                    ("/livez", &Method::GET) => state.handle_livez(request).await,
                    ("/rttest", &Method::POST) => state.handle_rttest(request).await,

                    ("/req", &Method::OPTIONS) => Ok(Response::builder()
                        .header("Access-Control-Allow-Origin", "*")
                        .header("Access-Control-Allow-Headers", "*")
                        .header("Access-Control-Allow-Methods", "POST")
                        .status(StatusCode::OK)
                        .body(Full::from(Bytes::from("No Content")))
                        .unwrap()),
                    ("/livez" | "/req", _) => Ok(Response::builder()
                        .status(StatusCode::METHOD_NOT_ALLOWED)
                        .body(Full::from(Bytes::from("Not Allowed")))
                        .unwrap()),
                    _ => Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Full::from(Bytes::from("Not Found")))
                        .unwrap()),
                };
                let e = start.elapsed();
                if let Ok(ref mut r) = result {
                    r.headers_mut().insert(
                        "x-exec-time",
                        HeaderValue::from_str(&e.as_nanos().to_string()).unwrap(),
                    );
                }
                result
            }
            // This doesn't look like it should do anything, but it seems to be
            // critical to connecting these spans to the parent.
            .instrument(Span::current()),
        )
    }
}

impl LoadBalancer {
    // This is a test endpoint with a fixed response. It expects a POST request
    // and returns a 167 byte response after 100ms. This roughly approximates
    // the request shape/timing that the /req endpoint exposes.
    async fn handle_rttest(
        &self,
        request: Request<IncomingBody>,
    ) -> Result<Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
        let _b = Limited::new(request, BODY_SIZE_LIMIT)
            .collect()
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
        let body = vec![65u8; 167];
        Ok(Response::builder()
            .status(200)
            .body(Full::from(body))
            .unwrap())
    }

    async fn handle_livez(
        &self,
        _request: Request<IncomingBody>,
    ) -> Result<Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
        let body = match self.0.svc_mgr.health_check().await {
            HealthCheckStatus::Ok => Bytes::from(format!(
                "Juicebox load balancer: {version}
name: {name}
{build}",
                version = self.0.semver,
                name = self.0.name,
                build = build_info::get!().livez()
            )),
            HealthCheckStatus::ShuttingDown => Bytes::from("Shutting down"),
        };
        Ok(Response::builder()
            .status(200)
            .body(Full::from(body))
            .unwrap())
    }

    async fn handle_req(
        &self,
        request: Request<IncomingBody>,
    ) -> Result<Response<Full<Bytes>>, Box<dyn Error + Send + Sync>> {
        let has_valid_version = request
            .headers()
            .get(JUICEBOX_VERSION_HEADER)
            .and_then(|version| version.to_str().ok())
            .and_then(|str| Version::parse(str).ok())
            .is_some_and(|semver| {
                // verify that major.minor is >= to our major.minor
                // patch and bugfix versions can be out-of-sync
                // to allow the SDK and realm software to make
                // changes that don't break protocol compatibility
                semver.major > self.0.semver.major
                    || (semver.major == self.0.semver.major && semver.minor >= self.0.semver.minor)
            });

        if !has_valid_version {
            return Ok(Response::builder()
                .header("Access-Control-Allow-Origin", "*")
                .status(StatusCode::UPGRADE_REQUIRED)
                .body(Full::from(Bytes::from(format!(
                    "SDK upgrade required to version >={}.{}",
                    self.0.semver.major, self.0.semver.minor
                ))))
                .unwrap());
        }

        let response = match Limited::new(request, BODY_SIZE_LIMIT).collect().await {
            Err(err) if err.downcast_ref::<LengthLimitError>().is_some() => {
                ClientResponse::PayloadTooLarge
            }
            Err(err) => return Err(err),
            Ok(collected_bytes) => {
                let request_bytes = collected_bytes.to_bytes();
                match marshalling::from_slice(request_bytes.as_ref()) {
                    Err(_) => ClientResponse::DecodingError,
                    Ok(request) => {
                        let realms = self.0.realms.lock().unwrap().clone();
                        match handle_client_request(
                            &request,
                            &self.0.name,
                            &realms,
                            self.0.secret_manager.as_ref(),
                            &self.0.record_id_randomization_key,
                            &self.0.agent_client,
                            &self.0.metrics,
                        )
                        .await
                        {
                            ClientResponse::Unavailable => {
                                // retry with refreshed info about realm endpoints
                                let refreshed_realms = Arc::new(
                                    refresh(&self.0.name, &self.0.store, &self.0.agent_client)
                                        .await,
                                );
                                *self.0.realms.lock().unwrap() = refreshed_realms.clone();

                                handle_client_request(
                                    &request,
                                    &self.0.name,
                                    &refreshed_realms,
                                    self.0.secret_manager.as_ref(),
                                    &self.0.record_id_randomization_key,
                                    &self.0.agent_client,
                                    &self.0.metrics,
                                )
                                .await
                            }
                            response => response,
                        }
                    }
                }
            }
        };

        trace!(load_balancer = self.0.name, ?response);
        Ok(Response::builder()
            .header("Access-Control-Allow-Origin", "*")
            .status(match response {
                ClientResponse::Ok(_) => StatusCode::OK,
                ClientResponse::DecodingError
                | ClientResponse::MissingSession
                | ClientResponse::SessionError => StatusCode::BAD_REQUEST,
                ClientResponse::InvalidAuth => StatusCode::UNAUTHORIZED,
                ClientResponse::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
                ClientResponse::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                ClientResponse::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            })
            .body(Full::new(Bytes::from(
                marshalling::to_vec(&response).expect("TODO"),
            )))
            .expect("TODO"))
    }
}

#[tracing::instrument(
    level = "trace",
    skip(
        request,
        realms,
        secret_manager,
        record_id_randomization_key,
        agent_client,
        metrics
    )
)]
async fn handle_client_request(
    request: &ClientRequest,
    name: &str,
    realms: &HashMap<RealmId, Vec<Partition>>,
    secret_manager: &dyn SecretManager,
    record_id_randomization_key: &RecordIdRandomizationKey,
    agent_client: &ReqwestClientMetrics,
    metrics: &metrics::Client,
) -> ClientResponse {
    let mut tags = Vec::with_capacity(5);
    let start = Instant::now();
    let result = handle_client_request_inner(
        request,
        name,
        realms,
        secret_manager,
        record_id_randomization_key,
        agent_client,
        &mut tags,
    )
    .await;

    add_client_response(&mut tags, &result);
    tags.push(tag!("realm": ?request.realm));

    metrics.timing("load_balancer.request.time", start.elapsed(), tags);
    result
}

fn add_client_response(tags: &mut Vec<Tag>, response: &ClientResponse) {
    let (result, success) = match response {
        ClientResponse::Ok(_) => ("Ok", true),
        ClientResponse::Unavailable => ("Unavailable", false),
        ClientResponse::InvalidAuth => ("InvalidAuth", false),
        ClientResponse::MissingSession => ("MissingSession", false),
        ClientResponse::SessionError => ("SessionError", false),
        ClientResponse::DecodingError => ("DecodingError", false),
        ClientResponse::PayloadTooLarge => ("PayloadTooLarge", false),
        ClientResponse::RateLimitExceeded => ("RateLimitExceeded", false),
    };
    tags.push(tag!(result));
    tags.push(tag!(success));
}

async fn handle_client_request_inner(
    request: &ClientRequest,
    name: &str,
    realms: &HashMap<RealmId, Vec<Partition>>,
    secret_manager: &dyn SecretManager,
    record_id_randomization_key: &RecordIdRandomizationKey,
    agent_client: &ReqwestClientMetrics,
    request_tags: &mut Vec<Tag>,
) -> ClientResponse {
    type Response = ClientResponse;

    let Some(partitions) = realms.get(&request.realm) else {
        return Response::Unavailable;
    };

    let validator = AuthTokenValidator::new(request.realm, Require::ScopeOrMissing(Scope::User));
    let Ok((tenant, version)) = validator.parse_key_id(&request.auth_token) else {
        return Response::InvalidAuth;
    };
    let claims = match secret_manager
        .get_secret_version(&tenant_secret_name(&tenant), version.into())
        .await
    {
        Ok(Some(secret)) => match secret.try_into() {
            Ok(key) => match validator.validate(&request.auth_token, &key) {
                Ok(claims) => claims,
                Err(_) => return Response::InvalidAuth,
            },
            Err(err) => {
                warn!(?tenant, ?version, ?err, "invalid secret data");
                return Response::InvalidAuth;
            }
        },
        Ok(None) => return Response::InvalidAuth,
        Err(err) => {
            warn!(?tenant, ?version, ?err, "failed to get tenant key secret");
            return Response::Unavailable;
        }
    };
    let record_id = RecordIdBuilder {
        tenant: &claims.issuer,
        user: &claims.subject,
    }
    .build(record_id_randomization_key);
    request_tags.push(tag!("missing_scope": claims.scope.is_none()));
    request_tags.push(tag!("tenant": claims.issuer));

    for partition in partitions {
        if !partition.owned_range.contains(&record_id) {
            continue;
        }
        request_tags.push(tag!("group": partition.group));

        match rpc::send(
            agent_client,
            &partition.leader,
            AppRequest {
                realm: request.realm,
                group: partition.group,
                record_id: record_id.clone(),
                session_id: request.session_id,
                kind: request.kind,
                encrypted: request.encrypted.clone(),
                tenant: claims.issuer.clone(),
                user: HashedUserId::new(&claims.issuer, &claims.subject),
            },
        )
        .await
        {
            Err(err) => {
                warn!(
                    load_balancer = name,
                    agent = %partition.leader,
                    realm = ?request.realm,
                    group = ?partition.group,
                    %err,
                    "http error",
                );
            }

            Ok(
                r @ AppResponse::InvalidRealm
                | r @ AppResponse::InvalidGroup
                | r @ AppResponse::NoHsm
                | r @ AppResponse::NoStore
                | r @ AppResponse::NoPubSub
                | r @ AppResponse::NotLeader
                | r @ AppResponse::InvalidProof,
            ) => {
                warn!(
                    load_balancer = name,
                    agent = %partition.leader,
                    realm = ?request.realm,
                    group = ?partition.group,
                    response = ?r,
                    "AppRequest not ok",
                );
            }

            Ok(AppResponse::Ok(response)) => return Response::Ok(response),
            Ok(AppResponse::MissingSession) => return Response::MissingSession,
            Ok(AppResponse::SessionError) => return Response::SessionError,
            Ok(AppResponse::DecodingError) => return Response::DecodingError,
            Ok(AppResponse::RateLimitExceeded) => return Response::RateLimitExceeded,
        };
    }

    Response::Unavailable
}

#[derive(Debug)]
pub struct RecordIdRandomizationKey(SecretBytesArray<32>);

impl RecordIdRandomizationKey {
    pub fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl TryFrom<Secret> for RecordIdRandomizationKey {
    type Error = anyhow::Error;
    fn try_from(value: Secret) -> Result<Self, Self::Error> {
        match value.algorithm {
            SecretAlgorithm::Blake2sMac256 => Ok(RecordIdRandomizationKey(
                SecretBytesArray::try_from(value.data.expose_secret())
                    .map_err(|_| anyhow!("invalid secret length: need 32 bytes"))?,
            )),
            _ => Err(anyhow!("invalid secret algorithm: need Blake2sMac256")),
        }
    }
}

#[derive(Serialize)]
struct RecordIdBuilder<'a> {
    tenant: &'a str,
    user: &'a str,
}

// This uses a MAC with a per-realm key so that tenants/users can't cause
// unbalanced Merkle trees (the same way hash tables are randomized).
//
// TODO: we may need a way to enumerate all the users for a given tenant if
// that tenant wanted to delete all their data.
impl<'a> RecordIdBuilder<'a> {
    fn build(&self, randomization_key: &RecordIdRandomizationKey) -> RecordId {
        let mut h = Blake2sMac256::new(randomization_key.expose_secret().into());
        ciborium::ser::into_writer(self, DigestWriter(&mut h))
            .expect("failed to serialize RecordIdBuilder");
        RecordId(h.finalize_fixed().into())
    }
}

struct DigestWriter<'a, D>(&'a mut D);
impl<'a, D: digest::Update> ciborium_io::Write for DigestWriter<'a, D> {
    type Error = ();

    fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.0.update(data);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Adapter to use tokio to spawn HTTP2 tasks.
///
/// Copied from example on
/// <https://docs.rs/hyper/1.0.0-rc.4/hyper/rt/trait.Executor.html>.
#[derive(Clone)]
struct TokioExecutor;

impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        tokio::spawn(future);
    }
}
