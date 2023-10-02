use clap::Parser;
use futures::future::{join_all, try_join_all};
use google::GrpcConnectionOptions;
use http::Uri;
use reqwest::Url;
use std::collections::HashMap;
use std::env::current_dir;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::thread::sleep;
use std::time::Duration;
use testing::exec::pubsub;
use tracing::{info, warn};

use hsm_api::{OwnedRange, RecordId};
use juicebox_networking::reqwest::{Client, ClientOptions};
use juicebox_process_group::ProcessGroup;
use juicebox_realm_auth::{creation::create_token, Claims};
use juicebox_sdk::{AuthToken, Configuration, PinHashingMode, Realm, RealmId};
use observability::{logging, metrics};
use secret_manager::{tenant_secret_name, BulkLoad, SecretManager, SecretsFile};
use service_core::term::install_termination_handler;
use testing::exec::bigtable::BigtableRunner;
use testing::exec::certs::create_localhost_key_and_cert;
use testing::exec::hsm_gen::{Entrust, HsmGenerator};

#[derive(Parser)]
#[command(
    about = "A tool to launch all the juicebox services and execute a demo binary configured to access them"
)]
struct Args {
    /// Path to the demo binary to execute
    #[arg(long)]
    demo: Option<PathBuf>,

    /// Keep the demo stack alive until Ctrl-C is input
    #[arg(short, long, default_value = "false")]
    keep_alive: bool,

    /// Name of JSON file containing per-tenant keys for authentication.
    #[arg(long, default_value = "secrets-demo.json")]
    secrets_file: PathBuf,
}

#[tokio::main]
async fn main() {
    logging::configure("juicebox-demo-runner");

    let args = Args::parse();
    let metrics = metrics::Client::new("demo_runner");

    let mut process_group = ProcessGroup::new();
    install_termination_handler(Duration::from_secs(1));

    let d = GrpcConnectionOptions::default();
    let bt_args = store::BigtableArgs {
        instance: String::from("inst"),
        project: String::from("prj"),
        url: Some(Uri::from_static("http://localhost:9000")),
        timeout: d.timeout,
        connect_timeout: d.connect_timeout,
        http2_keepalive_interval: d.http2_keepalive_interval,
        http2_keepalive_timeout: d.http2_keepalive_timeout,
        http2_keepalive_while_idle: d.http2_keepalive_while_idle,
    };

    info!(path = ?args.secrets_file, "loading secrets from JSON file");
    let secret_manager = Box::new(
        SecretsFile::new(args.secrets_file.clone())
            .load_all()
            .await
            .expect("failed to load secrets from JSON file"),
    );

    BigtableRunner::run(&mut process_group, &bt_args).await;
    let pubsub_url = pubsub::run(&mut process_group, 9091, bt_args.project.clone()).await;

    let store_admin = bt_args
        .connect_admin(None)
        .await
        .expect("failed to connect to bigtable admin service");

    info!("initializing service discovery table");
    store_admin.initialize_discovery().await.expect("TODO");

    let store = bt_args
        .connect_data(
            None,
            store::Options {
                metrics,
                ..store::Options::default()
            },
        )
        .await
        .expect("failed to connect to bigtable data service");

    let certificates = create_localhost_key_and_cert(current_dir().unwrap().join("target"))
        .expect("Failed to create TLS key/cert for load balancer");

    let num_load_balancers = 2;
    info!(count = num_load_balancers, "creating load balancers");
    let load_balancers: Vec<Url> = (1..=num_load_balancers)
        .map(|i| {
            let address = SocketAddr::from(([127, 0, 0, 1], 3000 + i));
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
                .arg(address.to_string())
                .arg("--secrets-file")
                .arg(&args.secrets_file);
            bt_args.add_to_cmd(&mut cmd);
            process_group.spawn(&mut cmd);
            Url::parse(&format!("https://localhost:{}", address.port())).unwrap()
        })
        .collect();

    let mut hsm_generator = HsmGenerator::new(Entrust(false), 4000);
    let agents_client = Client::new(ClientOptions::default());

    info!("creating initial HSM and agents");
    let (group1, realm1_public_key) = hsm_generator
        .create_hsms(
            1,
            &mut process_group,
            PathBuf::new(),
            &bt_args,
            &Some(pubsub_url.clone()),
            None,
        )
        .await;
    let (realm_id, group_id1) = cluster_core::new_realm(&agents_client, &group1[0])
        .await
        .unwrap();
    info!(?realm_id, group_id = ?group_id1, "initialized cluster");

    info!("creating additional groups");
    let (group2, _) = hsm_generator
        .create_hsms(
            5,
            &mut process_group,
            PathBuf::new(),
            &bt_args,
            &Some(pubsub_url.clone()),
            None,
        )
        .await;
    let (group3, _) = hsm_generator
        .create_hsms(
            4,
            &mut process_group,
            PathBuf::new(),
            &bt_args,
            &Some(pubsub_url.clone()),
            None,
        )
        .await;

    cluster_core::join_realm(
        &agents_client,
        realm_id,
        group1
            .iter()
            .skip(1)
            .chain(group2.iter())
            .chain(group3.iter())
            .cloned()
            .collect::<Vec<Url>>()
            .as_slice(),
        &group1[0],
    )
    .await
    .unwrap();

    let mut groups = try_join_all([
        cluster_core::new_group(&agents_client, realm_id, &group2),
        cluster_core::new_group(&agents_client, realm_id, &group3),
        cluster_core::new_group(&agents_client, realm_id, &group1),
    ])
    .await
    .unwrap();
    info!(?realm_id, new_groups = ?groups, "created groups");

    groups.insert(0, group_id1);
    info!(
        source = ?groups[0],
        destination = ?groups[1],
        "transferring ownership of entire uid-space"
    );
    cluster_core::transfer(realm_id, groups[0], groups[1], OwnedRange::full(), &store)
        .await
        .unwrap();

    info!("growing the cluster to 4 partitions");
    cluster_core::transfer(
        realm_id,
        groups[1],
        groups[2],
        OwnedRange {
            start: RecordId::min_id(),
            end: RecordId([0x80; RecordId::NUM_BYTES]),
        },
        &store,
    )
    .await
    .unwrap();

    cluster_core::transfer(
        realm_id,
        groups[1],
        groups[0],
        OwnedRange {
            start: RecordId([0x80; RecordId::NUM_BYTES]).next().unwrap(),
            end: RecordId([0xA0; RecordId::NUM_BYTES]),
        },
        &store,
    )
    .await
    .unwrap();

    cluster_core::transfer(
        realm_id,
        groups[2],
        groups[3],
        OwnedRange {
            start: RecordId([0x40; RecordId::NUM_BYTES]),
            end: RecordId([0x80; RecordId::NUM_BYTES]),
        },
        &store,
    )
    .await
    .unwrap();

    // moving part of a partition to another group.
    cluster_core::transfer(
        realm_id,
        groups[2],
        groups[3],
        OwnedRange {
            start: RecordId([0x30; RecordId::NUM_BYTES]),
            end: RecordId([0x40; RecordId::NUM_BYTES]).prev().unwrap(),
        },
        &store,
    )
    .await
    .unwrap();

    info!("creating additional realms");
    let mut realms = join_all([5100, 6000, 7100].map(|start_port| {
        let mut hsm_generator = HsmGenerator::new(Entrust(false), start_port);
        let mut process_group = process_group.clone();
        let agents_client = agents_client.clone();
        let bigtable = bt_args.clone();
        let pubsub_url = pubsub_url.clone();
        async move {
            let (agents, public_key) = hsm_generator
                .create_hsms(
                    1,
                    &mut process_group,
                    PathBuf::new(),
                    &bigtable,
                    &Some(pubsub_url),
                    None,
                )
                .await;
            let realm_id = cluster_core::new_realm(&agents_client, &agents[0])
                .await
                .unwrap()
                .0;
            (realm_id, public_key)
        }
    }))
    .await;
    realms.push((realm_id, realm1_public_key));

    let mut lb = load_balancers.iter().cycle();
    let configuration = Configuration {
        realms: realms
            .into_iter()
            .map(|(id, public_key)| Realm {
                id,
                address: lb.next().unwrap().clone(),
                public_key: Some(public_key.0),
            })
            .collect(),
        register_threshold: 3,
        recover_threshold: 3,
        pin_hashing_mode: PinHashingMode::FastInsecure,
    };

    let tenant = "test-acme";
    let (auth_key_version, auth_key) = secret_manager
        .get_secrets(&tenant_secret_name(tenant))
        .await
        .unwrap_or_else(|e| panic!("failed to get tenant {tenant:?} auth key: {e}"))
        .into_iter()
        .map(|(version, key)| (version.into(), key.into()))
        .next()
        .unwrap_or_else(|| panic!("tenant {tenant:?} has no secrets"));

    let auth_tokens: HashMap<RealmId, AuthToken> = configuration
        .realms
        .iter()
        .map(|realm| {
            (
                realm.id,
                create_token(
                    &Claims {
                        issuer: tenant.to_owned(),
                        subject: String::from("mario"),
                        audience: realm.id,
                    },
                    &auth_key,
                    auth_key_version,
                ),
            )
        })
        .collect();

    let jsonable_auth_tokens: HashMap<String, String> = auth_tokens
        .iter()
        .map(|(id, token)| (hex::encode(id.0), token.expose_secret().to_string()))
        .collect();

    let mut demo_status: Option<ExitStatus> = None;

    if let Some(demo) = args.demo {
        info!(pid = std::process::id(), "runner: executing demo");
        demo_status = Some(
            Command::new(demo)
                .arg("--tls-certificate")
                .arg(certificates.cert_file_der.clone())
                .arg("--configuration")
                .arg(configuration.to_json())
                .arg("--auth-tokens")
                .arg(serde_json::to_string(&jsonable_auth_tokens).unwrap())
                .status()
                .expect("Couldn't run demo executable"),
        );
    }

    if args.keep_alive {
        warn!(
            configuration = configuration.to_json(),
            auth_tokens = serde_json::to_string(&jsonable_auth_tokens).unwrap(),
            tls_certificate = ?certificates.cert_file_der,
            "runner: stack is active, press ctrl-c to shutdown"
        );

        sleep(Duration::MAX);
    }

    info!(pid = std::process::id(), "runner: done");
    process_group.kill();
    logging::flush();
    info!(pid = std::process::id(), "runner: exiting");

    if let Some(demo_status) = demo_status {
        assert!(demo_status.success());
    }
}
