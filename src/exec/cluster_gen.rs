use futures::future::join_all;
use reqwest::{Certificate, Url};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info};

use hsmcore::hsm::types::GroupId;
use loam_sdk::{Client, Configuration, PinHashingMode, Realm, RealmId, TokioSleeper};
use loam_sdk_networking::rpc::{self, LoadBalancerService};

use super::bigtable::BigTableRunner;
use super::certs::{create_localhost_key_and_cert, Certificates};
use super::hsm_gen::{Entrust, HsmGenerator, MetricsParticipants};
use super::PortIssuer;
use crate::client_auth::creation::create_token;
use crate::client_auth::{new_google_secret_manager, tenant_secret_name, AuthKey, Claims};
use crate::google_auth;
use crate::http_client::{self, ClientOptions};
use crate::metrics;
use crate::process_group::ProcessGroup;
use crate::realm::agent::types::{AgentService, StatusRequest};
use crate::realm::cluster::{self, NewRealmError};
use crate::realm::store::bigtable::{BigTableArgs, StoreClient};
use crate::secret_manager::{BulkLoad, SecretManager, SecretVersion, SecretsFile};

#[derive(Debug)]
pub struct ClusterConfig {
    pub load_balancers: u8,
    pub realms: Vec<RealmConfig>,
    pub bigtable: BigTableArgs,
    pub secrets_file: Option<PathBuf>,
    pub entrust: Entrust,
}

#[derive(Debug)]
pub struct RealmConfig {
    pub hsms: u8,
    pub groups: u8,
    pub metrics: MetricsParticipants,
    pub state_dir: Option<PathBuf>,
}

pub struct ClusterResult {
    pub load_balancers: Vec<Url>,
    pub certs: Certificates,
    pub realms: Vec<RealmResult>,

    pub auth_key_version: SecretVersion,
    pub auth_key: AuthKey,

    pub store: StoreClient,
    pub cluster_manager: Url,
}

impl ClusterResult {
    pub fn lb_cert(&self) -> Certificate {
        Certificate::from_pem(
            &fs::read(&self.certs.cert_file_pem).expect("failed to read certificate file"),
        )
        .expect("failed to decode certificate file")
    }

    pub fn client_for_user(
        &self,
        user_id: String,
    ) -> Client<TokioSleeper, http_client::Client<LoadBalancerService>> {
        Client::with_tokio(
            Configuration {
                realms: self
                    .realms
                    .iter()
                    .map(|r| Realm {
                        address: self.load_balancers[0].clone(),
                        public_key: Some(r.communication_public_key.clone()),
                        id: r.realm,
                    })
                    .collect(),
                register_threshold: self.realms.len().try_into().unwrap(),
                recover_threshold: self.realms.len().try_into().unwrap(),
                pin_hashing_mode: PinHashingMode::FastInsecure,
            },
            Vec::new(),
            create_token(
                &Claims {
                    issuer: "test".to_string(),
                    subject: user_id,
                },
                &self.auth_key,
                self.auth_key_version,
            ),
            http_client::Client::<LoadBalancerService>::new(http_client::ClientOptions {
                additional_root_certs: vec![self.lb_cert()],
            }),
        )
    }
}

pub struct RealmResult {
    pub agents: Vec<Url>,
    pub groups: Vec<GroupId>,
    pub realm: RealmId,
    pub communication_public_key: Vec<u8>,
}

pub async fn create_cluster(
    args: ClusterConfig,
    process_group: &mut ProcessGroup,
    ports: impl Into<PortIssuer>,
) -> Result<ClusterResult, String> {
    debug!(config=?args, "creating cluster");
    let ports = ports.into();
    let auth_manager = if args.bigtable.needs_auth() || args.secrets_file.is_none() {
        Some(
            google_auth::from_adc()
                .await
                .expect("failed to initialize Google Cloud auth"),
        )
    } else {
        None
    };

    if args.bigtable.url.is_some() {
        BigTableRunner::run(process_group, &args.bigtable).await;
    }
    let store_admin = args
        .bigtable
        .connect_admin(auth_manager.clone())
        .await
        .expect("failed to connect to bigtable admin service");

    info!("initializing service discovery table");
    store_admin
        .initialize_discovery()
        .await
        .expect("unable to initialize Bigtable service discovery");

    let store = args
        .bigtable
        .connect_data(auth_manager.clone(), metrics::Client::NONE)
        .await
        .expect("failed to connect to bigtable data service");

    let secret_manager: Box<dyn SecretManager> = match &args.secrets_file {
        Some(secrets_file) => {
            info!(path = ?secrets_file, "loading secrets from JSON file");
            Box::new(
                SecretsFile::new(secrets_file.clone())
                    .load_all()
                    .await
                    .expect("failed to load secrets from JSON file"),
            )
        }

        None => {
            info!("connecting to Google Cloud Secret Manager");
            Box::new(
                new_google_secret_manager(
                    &args.bigtable.project,
                    auth_manager.unwrap(),
                    Duration::MAX,
                )
                .await
                .expect("failed to load secrets from Google Secret Manager"),
            )
        }
    };

    let tenant = "test";
    let (auth_key_version, auth_key) = secret_manager
        .get_secrets(&tenant_secret_name(tenant))
        .await
        .expect("failed to get test tenant auth key")
        .into_iter()
        .map(|(version, key)| (version, AuthKey::from(key)))
        .next()
        .expect("test tenant has no secrets");

    let (lb_urls, certificates) = create_load_balancers(&args, process_group, &ports);
    let cluster_manager = start_cluster_manager(&args.bigtable, process_group, &ports);

    let mut realms = Vec::with_capacity(args.realms.len());
    let mut hsm_gen = HsmGenerator::new(args.entrust, ports);
    for realm in &args.realms {
        let res = create_realm(&mut hsm_gen, process_group, realm, &args.bigtable).await;
        realms.push(res);
    }

    Ok(ClusterResult {
        load_balancers: lb_urls,
        certs: certificates,
        realms,
        auth_key_version,
        auth_key,
        store,
        cluster_manager,
    })
}

fn create_load_balancers(
    args: &ClusterConfig,
    process_group: &mut ProcessGroup,
    port: &PortIssuer,
) -> (Vec<Url>, Certificates) {
    let certificates = create_localhost_key_and_cert("target".into())
        .expect("Failed to create TLS key/cert for load balancer");

    info!("creating load balancer(s)");
    let urls: Vec<Url> = (0..args.load_balancers)
        .map(|_| {
            let p = port.next();
            let address = SocketAddr::from(([127, 0, 0, 1], p));
            let mut cmd = Command::new(format!(
                "target/{}/load_balancer",
                if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                }
            ));
            cmd.arg("--tls-cert")
                .arg(certificates.cert_file_pem.clone())
                .arg("--tls-key")
                .arg(certificates.key_file_pem.clone())
                .arg("--listen")
                .arg(address.to_string());
            if let Some(secrets_file) = &args.secrets_file {
                cmd.arg("--secrets-file").arg(secrets_file);
            }
            args.bigtable.add_to_cmd(&mut cmd);
            process_group.spawn(&mut cmd);
            Url::parse(&format!("https://localhost:{p}/")).unwrap()
        })
        .collect();

    (urls, certificates)
}

fn start_cluster_manager(
    args: &BigTableArgs,
    process_group: &mut ProcessGroup,
    ports: &PortIssuer,
) -> Url {
    let port = ports.next();
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut cmd = Command::new(format!(
        "target/{}/cluster_manager",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    ));
    cmd.arg("--listen").arg(address.to_string());
    args.add_to_cmd(&mut cmd);
    process_group.spawn(&mut cmd);
    Url::parse(&format!("http://localhost:{port}/")).unwrap()
}

async fn create_realm(
    hsm_gen: &mut HsmGenerator,
    process_group: &mut ProcessGroup,
    r: &RealmConfig,
    bigtable: &BigTableArgs,
) -> RealmResult {
    let (agents, key) = hsm_gen
        .create_hsms(
            r.hsms.into(),
            r.metrics,
            process_group,
            bigtable,
            r.state_dir.clone(),
        )
        .await;

    match cluster::new_realm(&agents).await {
        Ok((realm, group_id)) => {
            let mut res = RealmResult {
                agents,
                groups: vec![group_id],
                realm,
                communication_public_key: key,
            };
            for _ in 1..r.groups {
                let group_id = cluster::new_group(realm, &res.agents).await.unwrap();
                res.groups.push(group_id);
                // TODO, transfer some partition to the new group
            }
            res
        }

        // If we're restarting a realm from its persisted state, it might already have a realm/groups.
        Err(NewRealmError::HaveRealm { agent }) => {
            let c = http_client::Client::<AgentService>::new(ClientOptions::default());
            let sr = rpc::send(&c, &agent, StatusRequest {}).await.unwrap();
            match sr.hsm.and_then(|hsm| hsm.realm) {
                None => panic!("it said it had a realm)"),
                Some(r) => {
                    // we need to wait til it has a leader before returning from new_realm.
                    while !join_all(
                        agents
                            .iter()
                            .map(|url| rpc::send(&c, url, StatusRequest {})),
                    )
                    .await
                    .into_iter()
                    .flat_map(|r| r.ok().and_then(|r| r.hsm))
                    .flat_map(|r| r.realm)
                    .flat_map(|r| r.groups.into_iter())
                    .any(|g| g.leader.is_some())
                    {
                        sleep(Duration::from_millis(20)).await;
                    }

                    RealmResult {
                        agents,
                        groups: r.groups.iter().map(|g| g.id).collect::<Vec<GroupId>>(),
                        realm: r.id,
                        communication_public_key: key,
                    }
                }
            }
        }

        Err(e) => panic!("failed to create new realm {e:?}"),
    }
}
