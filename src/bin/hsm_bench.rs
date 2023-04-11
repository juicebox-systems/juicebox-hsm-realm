use clap::Parser;
use futures::future::try_join_all;
use futures::StreamExt;
use reqwest::{Certificate, Url};
use secrecy::SecretString;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, info};

use hsmcore::hsm::types::GroupId;
use loam_mvp::client_auth::{creation::create_token, AuthKey, Claims};
use loam_mvp::google_auth;
use loam_mvp::http_client::{self, ClientOptions};
use loam_mvp::logging;
use loam_mvp::process_group::ProcessGroup;
use loam_mvp::realm::agent::types::{AgentService, StatusRequest, StatusResponse};
use loam_mvp::realm::cluster::{self, NewRealmError};
use loam_mvp::realm::store::bigtable::BigTableArgs;
use loam_sdk::{Client, Configuration, Pin, Realm, RealmId, UserSecret};
use loam_sdk_core::types::Policy;
use loam_sdk_networking::rpc::{self, LoadBalancerService};

mod common;
use common::certs::create_localhost_key_and_cert;
use common::hsm_gen::{Entrust, HsmGenerator, MetricsParticipants};

#[derive(Debug, Parser)]
#[command(about = "An end-to-end benchmark to stress an HSM")]
struct Args {
    #[command(flatten)]
    bigtable: BigTableArgs,

    /// Number of secret registrations to do at a time.
    #[arg(long, value_name = "N", default_value_t = 3)]
    concurrency: usize,

    /// Total number of secret registrations.
    #[arg(long, value_name = "N", default_value_t = 100)]
    count: usize,

    /// Use an entrust HSM/Agent for one of the HSMs and make it the leader.
    #[arg(long, default_value_t = false)]
    entrust: bool,

    /// Report metrics from HSMs. Options are Leader, All, None.
    #[arg(long, value_parser=MetricsParticipants::parse, default_value_t=MetricsParticipants::None)]
    metrics: MetricsParticipants,

    /// A directory to read/write HSM state to. This allows for testing with a
    /// realm that was created by a previous run. You need to keep the bigtable
    /// state between runs for this to be useful.
    #[arg(long)]
    state: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    logging::configure("loam-hsm-bench");

    let mut process_group = ProcessGroup::new();

    ctrlc::set_handler(move || {
        info!(pid = std::process::id(), "received termination signal");
        logging::flush();
        info!(pid = std::process::id(), "exiting");
        std::process::exit(0);
    })
    .expect("error setting signal handler");

    let args = Args::parse();
    info!(?args, "Parsed command-line args");

    let auth_manager = if args.bigtable.needs_auth() {
        Some(
            google_auth::from_adc()
                .await
                .expect("failed to initialize Google Cloud auth"),
        )
    } else {
        None
    };

    let store_admin = args
        .bigtable
        .connect_admin(auth_manager.clone())
        .await
        .expect("Unable to connect to Bigtable admin");
    info!("initializing service discovery table");
    store_admin
        .initialize_discovery()
        .await
        .expect("unable to initialize Bigtable service discovery");

    let store = args
        .bigtable
        .connect_data(auth_manager)
        .await
        .expect("Unable to connect to Bigtable data");

    let certificates = create_localhost_key_and_cert("target".into())
        .expect("Failed to create TLS key/cert for load balancer");

    let lb_cert = Certificate::from_pem(
        &fs::read(&certificates.cert_file_pem).expect("failed to read certificate file"),
    )
    .expect("failed to decode certificate file");

    info!("creating load balancer");
    let load_balancer: Url = {
        let address = SocketAddr::from(([127, 0, 0, 1], 3000));
        let mut cmd = Command::new(format!(
            "target/{}/load_balancer",
            if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
        ));
        cmd.arg("--tls-cert")
            .arg(certificates.cert_file_pem)
            .arg("--tls-key")
            .arg(certificates.key_file_pem)
            .arg("--listen")
            .arg(address.to_string());
        args.bigtable.add_to_cmd(&mut cmd);
        process_group.spawn(&mut cmd);
        Url::parse("https://localhost:3000/").unwrap()
    };

    let mut hsm_generator = HsmGenerator::new(Entrust(args.entrust), 4000);

    let num_hsms = 5;
    info!(count = num_hsms, "creating HSMs and agents");
    let (group, realm_public_key) = hsm_generator
        .create_hsms(
            num_hsms,
            args.metrics,
            &mut process_group,
            &args.bigtable,
            args.state.clone(),
        )
        .await;

    let (realm_id, _group_id) = match group_has_realm(&group).await.unwrap() {
        Some((realm_id, group_id)) => {
            info!(?realm_id, ?group_id, "using existing realm/group");
            let agents = http_client::Client::<AgentService>::new(ClientOptions::default());
            let _ = cluster::ensure_groups_have_leader(&agents, &store).await;
            (realm_id, group_id)
        }
        None => {
            let (realm_id, group_id) = cluster::new_realm(&group).await.unwrap();
            info!(?realm_id, ?group_id, "initialized cluster");
            (realm_id, group_id)
        }
    };

    info!(clients = args.concurrency, "creating clients");
    let clients: Vec<Arc<Mutex<Client<http_client::Client<LoadBalancerService>>>>> = (0..args
        .concurrency)
        .map(|i| {
            Arc::new(Mutex::new(Client::new(
                Configuration {
                    realms: vec![Realm {
                        address: load_balancer.clone(),
                        public_key: realm_public_key.clone(),
                        id: realm_id,
                    }],
                    register_threshold: 1,
                    recover_threshold: 1,
                },
                create_token(
                    &Claims {
                        issuer: String::from("test"),
                        subject: format!("mario{i}"),
                    },
                    &AuthKey::from(SecretString::from(String::from("it's-a-them!"))),
                ),
                http_client::Client::new(http_client::ClientOptions {
                    additional_root_certs: vec![lb_cert.clone()],
                }),
            )))
        })
        .collect::<Vec<_>>();

    info!("main: Running test register");
    clients[0]
        .lock()
        .await
        .register(
            &Pin(b"pin-test".to_vec()),
            &UserSecret(b"secret-test".to_vec()),
            Policy { num_guesses: 2 },
        )
        .await
        .unwrap();

    info!(
        concurrency = args.concurrency,
        count = args.count,
        "main: Running concurrent registers"
    );
    let start = Instant::now();

    let mut stream = futures::stream::iter((0..args.count).map(|i| {
        let client = clients[i % args.concurrency].clone();
        async move {
            client
                .lock()
                .await
                .register(
                    &Pin(format!("pin{i}").into_bytes()),
                    &UserSecret(format!("secret{i}").into_bytes()),
                    Policy { num_guesses: 2 },
                )
                .await
        }
    }))
    .buffer_unordered(args.concurrency);

    let mut completed = 0;
    while let Some(result) = stream.next().await {
        result.unwrap();
        completed += 1;
        debug!(completed, "ok");
    }

    let elapsed = start.elapsed().as_secs_f64();
    info!(
        recoveries = args.count,
        seconds = elapsed,
        recoveries_per_s = (args.count as f64) / elapsed,
        concurrency = args.concurrency,
        "completed benchmark"
    );

    info!("main: done");
    if args.state.is_some() {
        info!("letting agents drain their delete queue");
        sleep(Duration::from_secs(6)).await;
    }
    process_group.kill();
    logging::flush();
    info!("main: exiting");
}

// If all members of the group are part of the same realm and have a single group, returns the realmId, groupId.
async fn group_has_realm(group: &[Url]) -> Result<Option<(RealmId, GroupId)>, NewRealmError> {
    let agent_client = http_client::Client::<AgentService>::new(ClientOptions::default());

    let hsms = try_join_all(
        group
            .iter()
            .map(|agent| rpc::send(&agent_client, agent, StatusRequest {})),
    )
    .await
    .map_err(NewRealmError::NetworkError)?;

    fn realm_group(sr: &StatusResponse) -> Option<(RealmId, GroupId)> {
        if let Some(s) = &sr.hsm {
            if let Some(r) = &s.realm {
                if r.groups.len() == 1 {
                    return Some((r.id, r.groups[0].id));
                }
            }
        }
        None
    }

    let first = realm_group(&hsms[0]);
    for other in &hsms[1..] {
        if realm_group(other) != first {
            return Ok(None);
        }
    }
    Ok(first)
}
