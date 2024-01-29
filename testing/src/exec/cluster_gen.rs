use ::reqwest::{Certificate, Url};
use futures::future::join_all;
use http::Uri;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use std::{env, fs, iter};
use tokio::time::sleep;
use tracing::{debug, info};

use super::bigtable::BigtableRunner;
use super::certs::{create_localhost_key_and_cert, Certificates};
use super::hsm_gen::{Entrust, HsmGenerator};
use super::{pubsub, PortIssuer};
use agent_api::StatusRequest;
use cluster_core::{self, NewRealmError, TransferRequest};
use google::{auth, GrpcConnectionOptions};
use hsm_api::{GroupId, OwnedRange, PublicKey};
use juicebox_networking::reqwest;
use juicebox_networking::rpc;
use juicebox_process_group::ProcessGroup;
use juicebox_realm_auth::creation::create_token;
use juicebox_realm_auth::{AuthKey, AuthKeyVersion, Claims, Scope};
use juicebox_sdk::{
    AuthToken, Client, ClientBuilder, Configuration, PinHashingMode, Realm, RealmId, TokioSleeper,
};
use observability::metrics;
use secret_manager::{
    new_google_secret_manager, tenant_secret_name, BulkLoad, SecretManager, SecretsFile,
};
use store::{self, StoreClient};

#[derive(Debug)]
pub struct ClusterConfig {
    pub load_balancers: u8,
    pub cluster_managers: u8,
    pub realms: Vec<RealmConfig>,
    pub bigtable: store::BigtableArgs,
    pub local_pubsub: bool,
    pub secrets_file: Option<PathBuf>,
    pub entrust: Entrust,
    /// Path to the top-level juicebox-hsm-realm directory containing the
    /// target directory.
    ///
    /// An absolute path is recommended for clearer log and error messages, and
    /// for passing to other programs that may have a different working
    /// directory.
    pub path_to_target: PathBuf,
}

#[derive(Debug)]
pub struct RealmConfig {
    pub hsms: u8,
    pub groups: u8,
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug)]
pub struct ClusterResult {
    pub load_balancers: Vec<Url>,
    pub certs: Certificates,
    pub realms: Vec<RealmResult>,

    pub tenant: String,
    pub auth_key_version: AuthKeyVersion,
    pub auth_key: AuthKey,

    pub store: StoreClient,
    pub cluster_managers: Vec<Url>,
    pub pubsub: Option<Uri>,
}

impl ClusterResult {
    pub fn lb_cert(&self) -> Certificate {
        Certificate::from_pem(
            &fs::read(&self.certs.cert_file_pem).expect("failed to read certificate file"),
        )
        .expect("failed to decode certificate file")
    }

    pub fn configuration(&self) -> Configuration {
        Configuration {
            realms: self
                .realms
                .iter()
                .map(|r| Realm {
                    address: self.load_balancers[0].clone(),
                    public_key: Some(r.communication_public_key.0.clone()),
                    id: r.realm,
                })
                .collect(),
            register_threshold: self.realms.len().try_into().unwrap(),
            recover_threshold: self.realms.len().try_into().unwrap(),
            pin_hashing_mode: PinHashingMode::FastInsecure,
        }
    }

    pub fn auth_tokens(&self, user_id: &str) -> HashMap<RealmId, AuthToken> {
        self.realms
            .iter()
            .map(|realm| {
                (
                    realm.realm,
                    create_token(
                        &Claims {
                            issuer: self.tenant.clone(),
                            subject: user_id.to_owned(),
                            audience: realm.realm,
                            scope: Some(Scope::User),
                        },
                        &self.auth_key,
                        self.auth_key_version,
                    ),
                )
            })
            .collect()
    }

    pub fn client_for_user(
        &self,
        user_id: &str,
    ) -> Client<TokioSleeper, reqwest::Client, HashMap<RealmId, AuthToken>> {
        ClientBuilder::new()
            .configuration(self.configuration())
            .auth_token_manager(self.auth_tokens(user_id))
            .tokio_sleeper()
            .reqwest_with_options(reqwest::ClientOptions {
                additional_root_certs: vec![self.lb_cert()],
                ..reqwest::ClientOptions::default()
            })
            .build()
    }
}

#[derive(Debug)]
pub struct RealmResult {
    pub agents: Vec<Url>,
    pub groups: Vec<GroupId>,
    pub realm: RealmId,
    pub communication_public_key: PublicKey,
}

pub async fn create_cluster(
    args: ClusterConfig,
    process_group: &mut ProcessGroup,
    ports: impl Into<PortIssuer>,
) -> Result<ClusterResult, String> {
    debug!(config=?args, "creating cluster");
    let ports = ports.into();
    let auth_manager =
        if args.bigtable.needs_auth() || args.secrets_file.is_none() || !args.local_pubsub {
            Some(
                auth::from_adc()
                    .await
                    .expect("failed to initialize Google Cloud auth"),
            )
        } else {
            None
        };

    let pubsub_url = if args.local_pubsub {
        Some(pubsub::run(process_group, ports.next(), args.bigtable.project.clone()).await)
    } else {
        None
    };

    if args.bigtable.url.is_some() {
        BigtableRunner::run(process_group, &args.bigtable).await;
    }
    let store_admin = args
        .bigtable
        .connect_admin(auth_manager.clone(), metrics::Client::NONE)
        .await
        .expect("failed to connect to bigtable admin service");

    info!("initializing service discovery table");
    store_admin
        .initialize_discovery()
        .await
        .expect("unable to initialize Bigtable service discovery");

    let store = args
        .bigtable
        .connect_data(auth_manager.clone(), store::Options::default())
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
                    GrpcConnectionOptions::default(),
                    metrics::Client::NONE,
                )
                .await
                .expect("failed to load secrets from Google Secret Manager"),
            )
        }
    };

    let tenant = "test-acme";
    let (auth_key_version, auth_key) = secret_manager
        .get_latest_secret_version(&tenant_secret_name(tenant))
        .await
        .unwrap_or_else(|e| panic!("failed to get tenant {tenant:?} auth key: {e}"))
        .map(|(version, key)| (version.into(), key.try_into().expect("invalid AuthKey")))
        .unwrap_or_else(|| panic!("tenant {tenant:?} has no secrets"));

    let (lb_urls, certificates) = create_load_balancers(&args, process_group, &ports);
    let cluster_managers: Vec<Url> = iter::repeat_with(|| {
        start_cluster_manager(
            &args.bigtable,
            args.path_to_target.clone(),
            process_group,
            &ports,
        )
    })
    .take(args.cluster_managers as usize)
    .collect();

    let mut realms = Vec::with_capacity(args.realms.len());
    let mut hsm_gen = HsmGenerator::new(args.entrust, ports);
    for realm in &args.realms {
        let res = create_realm(
            &mut hsm_gen,
            process_group,
            realm,
            &args.bigtable,
            pubsub_url.clone(),
            args.path_to_target.clone(),
            &cluster_managers,
        )
        .await;
        realms.push(res);
    }

    Ok(ClusterResult {
        load_balancers: lb_urls,
        certs: certificates,
        realms,
        tenant: tenant.to_owned(),
        auth_key_version,
        auth_key,
        store,
        cluster_managers,
        pubsub: pubsub_url,
    })
}

fn create_load_balancers(
    args: &ClusterConfig,
    process_group: &mut ProcessGroup,
    port: &PortIssuer,
) -> (Vec<Url>, Certificates) {
    println!("{:?}", env::current_dir());
    let certificates = create_localhost_key_and_cert(args.path_to_target.join("target"), false)
        .expect("Failed to create TLS key/cert for load balancer");

    info!("creating load balancer(s)");
    let urls: Vec<Url> = (0..args.load_balancers)
        .map(|_| {
            let p = port.next();
            let address = SocketAddr::from(([127, 0, 0, 1], p));
            let mut cmd = Command::new(
                args.path_to_target
                    .join("target")
                    .join(if cfg!(debug_assertions) {
                        "debug"
                    } else {
                        "release"
                    })
                    .join("load_balancer"),
            );
            cmd.arg("--tls-cert")
                .arg(certificates.cert_file_pem.clone())
                .arg("--tls-key")
                .arg(certificates.key_file_pem.clone())
                .arg("--listen")
                .arg(address.to_string())
                .arg("--shutdown-timeout") // no point sitting around for graceful shutdowns in tests
                .arg("10ms");
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
    args: &store::BigtableArgs,
    path_to_target: PathBuf,
    process_group: &mut ProcessGroup,
    ports: &PortIssuer,
) -> Url {
    let port = ports.next();
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut cmd = Command::new(
        path_to_target
            .join("target")
            .join(if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            })
            .join("cluster_manager"),
    );
    cmd.arg("--listen").arg(address.to_string());
    args.add_to_cmd(&mut cmd);
    process_group.spawn(&mut cmd);
    Url::parse(&format!("http://localhost:{port}/")).unwrap()
}

async fn create_realm(
    hsm_gen: &mut HsmGenerator,
    process_group: &mut ProcessGroup,
    r: &RealmConfig,
    bigtable: &store::BigtableArgs,
    pubsub_url: Option<Uri>,
    path_to_target: PathBuf,
    cluster_managers: &[Url],
) -> RealmResult {
    assert_ne!(r.hsms, 0);

    let (agents, key) = hsm_gen
        .create_hsms(
            r.hsms.into(),
            process_group,
            path_to_target,
            bigtable,
            &pubsub_url,
            r.state_dir.clone(),
        )
        .await;

    let agents_client = reqwest::Client::new(reqwest::ClientOptions::default());

    match cluster_core::new_realm(&agents_client, &agents[0]).await {
        Ok((realm, group_id)) => {
            cluster_core::join_realm(&agents_client, realm, &agents[1..], &agents[0])
                .await
                .unwrap();

            let mut res = RealmResult {
                agents,
                groups: vec![group_id],
                realm,
                communication_public_key: key,
            };

            // Create additional groups.
            for _ in 0..r.groups {
                let group_id = cluster_core::new_group(&agents_client, realm, &res.agents)
                    .await
                    .unwrap();
                res.groups.push(group_id);
            }

            if r.groups > 0 {
                // Transfer everything from the original group to the next one,
                // because the original group isn't fault-tolerant.
                rpc::send(
                    &agents_client,
                    &cluster_managers[0],
                    TransferRequest {
                        realm: res.realm,
                        source: res.groups[0],
                        destination: res.groups[1],
                        range: OwnedRange::full(),
                    },
                )
                .await
                .unwrap()
                .unwrap();

                // TODO, transfer ranges to the other new groups
            }

            res
        }

        // If we're restarting a realm from its persisted state, it might already have a realm/groups.
        Err(NewRealmError::HaveRealm) => {
            let sr = rpc::send(&agents_client, &agents[0], StatusRequest {})
                .await
                .unwrap();
            match sr.hsm.and_then(|hsm| hsm.realm) {
                None => panic!("it said it had a realm)"),
                Some(r) => {
                    // we need to wait til it has a leader before returning from new_realm.
                    while !join_all(
                        agents
                            .iter()
                            .map(|url| rpc::send(&agents_client, url, StatusRequest {})),
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
