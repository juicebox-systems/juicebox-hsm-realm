use anyhow::Context;
use bytes::Bytes;
use futures::future::join_all;
use futures::Future;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{body::Incoming as IncomingBody, Request, Response};
use loam_mvp::metrics::{self, Tag};
use loam_mvp::metrics_tag as tag;
use loam_sdk_core::marshalling;
use loam_sdk_networking::rpc;
use opentelemetry_http::HeaderExtractor;
use rustls::server::ResolvesServerCert;
use std::collections::HashMap;
use std::iter::zip;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;
use tracing::{instrument, trace, warn, Instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use url::Url;

use hsm_types::{GroupId, OwnedRange};
use hsmcore::hsm::types as hsm_types;
use loam_mvp::client_auth::{
    tenant_secret_name, validation::Validator as AuthTokenValidator, AuthKey,
};
use loam_mvp::http_client::{Client, ClientOptions};
use loam_mvp::logging::Spew;
use loam_mvp::realm::agent::types::{
    make_record_id, AgentService, AppRequest, AppResponse, StatusRequest, StatusResponse,
};
use loam_mvp::realm::store::bigtable::StoreClient;
use loam_mvp::secret_manager::SecretManager;
use loam_sdk_core::requests::{ClientRequest, ClientResponse, BODY_SIZE_LIMIT};
use loam_sdk_core::types::RealmId;

#[derive(Clone)]
pub struct LoadBalancer(Arc<State>);

struct State {
    name: String,
    store: StoreClient,
    secret_manager: Box<dyn SecretManager>,
    agent_client: Client<AgentService>,
    realms: Mutex<Arc<HashMap<RealmId, Vec<Partition>>>>,
    metrics: metrics::Client,
}

impl LoadBalancer {
    pub fn new(
        name: String,
        store: StoreClient,
        secret_manager: Box<dyn SecretManager>,
        metrics: metrics::Client,
    ) -> Self {
        Self(Arc::new(State {
            name,
            store,
            secret_manager,
            agent_client: Client::new(ClientOptions::default()),
            realms: Mutex::new(Arc::new(HashMap::new())),
            metrics,
        }))
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

        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(cert_resolver);
        let acceptor = TlsAcceptor::from(Arc::new(config));

        Ok((
            url,
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Err(e) => warn!("error accepting connection: {e:?}"),
                        Ok((stream, _)) => {
                            let acceptor = acceptor.clone();
                            let lb = self.clone();
                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Err(e) => {
                                        warn!("error terminating TLS connection: {e:?}");
                                    }
                                    Ok(stream) => {
                                        if let Err(e) =
                                            http1::Builder::new().serve_connection(stream, lb).await
                                        {
                                            warn!("error serving connection: {e:?}");
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

    async fn start_refresher(&self) {
        let state = self.0.clone();
        tokio::spawn(async move {
            loop {
                let updated = refresh(&state.name, &state.store, &state.agent_client).await;
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

static REFRESH_SPEW: Spew = Spew::new();

#[tracing::instrument(level = "trace")]
async fn refresh(
    name: &str,
    store: &StoreClient,
    agent_client: &Client<AgentService>,
) -> HashMap<RealmId, Vec<Partition>> {
    trace!(load_balancer = name, "refreshing cluster information");
    match store.get_addresses().await {
        Err(_) => todo!(),
        Ok(addresses) => {
            let responses = join_all(
                addresses
                    .iter()
                    .map(|(_, address)| rpc::send(agent_client, address, StatusRequest {})),
            )
            .await;

            let mut realms: HashMap<RealmId, Vec<Partition>> = HashMap::new();
            for ((_, agent), response) in zip(addresses, responses) {
                match response {
                    Ok(StatusResponse {
                        hsm:
                            Some(hsm_types::StatusResponse {
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
                        if let Some(suppressed) = REFRESH_SPEW.ok() {
                            warn!(load_balancer = name, %agent, %err, suppressed, "could not get status");
                        }
                    }
                }
            }
            trace!(
                ?realms,
                load_balancer = name,
                "done refreshing cluster information"
            );
            realms
        }
    }
}

impl Service<Request<IncomingBody>> for LoadBalancer {
    type Response = Response<Full<Bytes>>;
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    #[instrument(level = "trace", name = "Service::call", skip(self, request))]
    fn call(&mut self, request: Request<IncomingBody>) -> Self::Future {
        trace!(load_balancer = self.0.name, ?request);
        let state = self.0.clone();

        let parent_context = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(request.headers()))
        });
        Span::current().set_parent(parent_context);

        Box::pin(
            async move {
                let request_bytes = request.collect().await?.to_bytes();

                // todo: figure out a way to reject without reading all bytes into memory first
                let response = if request_bytes.len() >= BODY_SIZE_LIMIT {
                    ClientResponse::PayloadTooLarge
                } else {
                    match marshalling::from_slice(request_bytes.as_ref()) {
                        Err(_) => ClientResponse::DecodingError,
                        Ok(request) => {
                            let realms = state.realms.lock().unwrap().clone();
                            match handle_client_request(
                                &request,
                                &state.name,
                                &realms,
                                state.secret_manager.as_ref(),
                                &state.agent_client,
                                &state.metrics,
                            )
                            .await
                            {
                                ClientResponse::Unavailable => {
                                    // retry with refreshed info about realm endpoints
                                    let refreshed_realms = Arc::new(
                                        refresh(&state.name, &state.store, &state.agent_client)
                                            .await,
                                    );
                                    *state.realms.lock().unwrap() = refreshed_realms.clone();

                                    handle_client_request(
                                        &request,
                                        &state.name,
                                        &refreshed_realms,
                                        state.secret_manager.as_ref(),
                                        &state.agent_client,
                                        &state.metrics,
                                    )
                                    .await
                                }
                                response => response,
                            }
                        }
                    }
                };
                trace!(load_balancer = state.name, ?response);
                Ok(Response::builder()
                    .header("Access-Control-Allow-Origin", "*")
                    .status(match response {
                        ClientResponse::Ok(_) => 200,
                        ClientResponse::DecodingError
                        | ClientResponse::MissingSession
                        | ClientResponse::SessionError => 400,
                        ClientResponse::InvalidAuth => 401,
                        ClientResponse::PayloadTooLarge => 413,
                        ClientResponse::Unavailable => 503,
                    })
                    .body(Full::new(Bytes::from(
                        marshalling::to_vec(&response).expect("TODO"),
                    )))
                    .expect("TODO"))
            }
            // This doesn't look like it should do anything, but it seems to be
            // critical to connecting these spans to the parent.
            .instrument(Span::current()),
        )
    }
}

#[tracing::instrument(level = "trace", skip(request, realms, agent_client))]
async fn handle_client_request(
    request: &ClientRequest,
    name: &str,
    realms: &HashMap<RealmId, Vec<Partition>>,
    secret_manager: &dyn SecretManager,
    agent_client: &Client<AgentService>,
    metrics: &metrics::Client,
) -> ClientResponse {
    let mut tags = Vec::with_capacity(5);
    let start = Instant::now();
    let result = handle_client_request_inner(
        request,
        name,
        realms,
        secret_manager,
        agent_client,
        &mut tags,
    )
    .await;

    add_client_response(&mut tags, &result);
    tags.push(tag!(realm: "{:?}", request.realm));

    metrics.timing("load-balancer.request.time", start.elapsed(), tags);
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
    };
    tags.push(tag!(result));
    tags.push(tag!(success));
}

#[tracing::instrument(level = "trace", skip(request, realms, agent_client, request_tags))]
async fn handle_client_request_inner(
    request: &ClientRequest,
    name: &str,
    realms: &HashMap<RealmId, Vec<Partition>>,
    secret_manager: &dyn SecretManager,
    agent_client: &Client<AgentService>,
    request_tags: &mut Vec<Tag>,
) -> ClientResponse {
    type Response = ClientResponse;

    let Some(partitions) = realms.get(&request.realm) else {
        return Response::Unavailable;
    };

    let validator = AuthTokenValidator::new(request.realm);
    let Ok((tenant, version)) = validator.parse_key_id(&request.auth_token) else {
        return Response::InvalidAuth;
    };
    let claims = match secret_manager
        .get_secret_version(&tenant_secret_name(&tenant), version)
        .await
    {
        Ok(Some(key)) => match validator.validate(&request.auth_token, &AuthKey::from(key)) {
            Ok(claims) => claims,
            Err(_) => return Response::InvalidAuth,
        },
        Ok(None) => return Response::InvalidAuth,
        Err(err) => {
            warn!(?tenant, ?version, ?err, "failed to get tenant key secret");
            return Response::Unavailable;
        }
    };
    let record_id = make_record_id(&claims.issuer, &claims.subject);
    request_tags.push(tag!(tenant: "{}", claims.issuer));

    for partition in partitions {
        if !partition.owned_range.contains(&record_id) {
            continue;
        }
        request_tags.push(tag!(group: "{:?}", partition.group));

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
        };
    }

    Response::Unavailable
}
