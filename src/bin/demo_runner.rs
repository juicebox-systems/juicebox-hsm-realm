use clap::Parser;
use futures::future::{join_all, try_join_all};
use http::Uri;
use reqwest::Url;
use secrecy::ExposeSecret;
use std::env::current_dir;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::thread::sleep;
use std::time::Duration;
use tracing::{info, warn};

use hsmcore::hsm::types::{OwnedRange, RecordId};
use loam_mvp::client_auth::{creation::create_token, tenant_secret_name, AuthKey, Claims};
use loam_mvp::exec::bigtable::BigTableRunner;
use loam_mvp::exec::certs::create_localhost_key_and_cert;
use loam_mvp::exec::hsm_gen::{Entrust, HsmGenerator, MetricsParticipants};
use loam_mvp::logging;
use loam_mvp::process_group::ProcessGroup;
use loam_mvp::realm::cluster;
use loam_mvp::realm::store::bigtable::BigTableArgs;
use loam_mvp::secret_manager::{BulkLoad, SecretManager, SecretsFile};
use loam_sdk::{Configuration, Realm};

#[derive(Parser)]
#[command(
    about = "A tool to launch all the loam services and execute a demo binary configured to access them"
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
    logging::configure("loam-demo-runner");

    let args = Args::parse();

    let mut process_group = ProcessGroup::new();

    ctrlc::set_handler(move || {
        info!(pid = std::process::id(), "received termination signal");
        logging::flush();
        info!(pid = std::process::id(), "exiting");
        std::process::exit(0);
    })
    .expect("error setting signal handler");

    let bt_args = BigTableArgs {
        instance: String::from("inst"),
        project: String::from("prj"),
        url: Some(Uri::from_static("http://localhost:9000")),
    };

    info!(path = ?args.secrets_file, "loading secrets from JSON file");
    let secret_manager = Box::new(
        SecretsFile::new(args.secrets_file.clone())
            .load_all()
            .await
            .expect("failed to load secrets from JSON file"),
    );

    BigTableRunner::run(&mut process_group, &bt_args).await;
    let store_admin = bt_args
        .connect_admin(None)
        .await
        .expect("failed to connect to bigtable admin service");

    info!("initializing service discovery table");
    store_admin.initialize_discovery().await.expect("TODO");

    let store = bt_args
        .connect_data(None)
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

    let num_hsms = 5;
    info!(count = num_hsms, "creating initial HSMs and agents");
    let (group1, realm1_public_key) = hsm_generator
        .create_hsms(
            num_hsms,
            MetricsParticipants::None,
            &mut process_group,
            &bt_args,
            None,
        )
        .await;
    let (realm_id, group_id1) = cluster::new_realm(&group1).await.unwrap();
    info!(?realm_id, group_id = ?group_id1, "initialized cluster");

    info!("creating additional groups");
    let (group2, _) = hsm_generator
        .create_hsms(
            5,
            MetricsParticipants::None,
            &mut process_group,
            &bt_args,
            None,
        )
        .await;
    let (group3, _) = hsm_generator
        .create_hsms(
            4,
            MetricsParticipants::None,
            &mut process_group,
            &bt_args,
            None,
        )
        .await;

    let mut groups = try_join_all([
        cluster::new_group(realm_id, &group2),
        cluster::new_group(realm_id, &group3),
        cluster::new_group(realm_id, &group1),
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
    cluster::transfer(realm_id, groups[0], groups[1], OwnedRange::full(), &store)
        .await
        .unwrap();

    info!("growing the cluster to 4 partitions");
    cluster::transfer(
        realm_id,
        groups[1],
        groups[2],
        OwnedRange {
            start: RecordId::min_id(),
            end: RecordId([0x80; 32]),
        },
        &store,
    )
    .await
    .unwrap();

    cluster::transfer(
        realm_id,
        groups[1],
        groups[0],
        OwnedRange {
            start: RecordId([0x80; 32]).next().unwrap(),
            end: RecordId([0xA0; 32]),
        },
        &store,
    )
    .await
    .unwrap();

    cluster::transfer(
        realm_id,
        groups[2],
        groups[3],
        OwnedRange {
            start: RecordId([0x40; 32]),
            end: RecordId([0x80; 32]),
        },
        &store,
    )
    .await
    .unwrap();

    // moving part of a partition to another group.
    cluster::transfer(
        realm_id,
        groups[2],
        groups[3],
        OwnedRange {
            start: RecordId([0x30; 32]),
            end: RecordId([0x40; 32]).prev().unwrap(),
        },
        &store,
    )
    .await
    .unwrap();

    info!("creating additional realms");
    let mut realms = join_all([5000, 6000, 7000].map(|start_port| {
        let mut hsm_generator = HsmGenerator::new(Entrust(false), start_port);
        let mut process_group = process_group.clone();
        let bigtable = bt_args.clone();
        async move {
            let (agents, public_key) = hsm_generator
                .create_hsms(
                    num_hsms,
                    MetricsParticipants::None,
                    &mut process_group,
                    &bigtable,
                    None,
                )
                .await;
            let realm_id = cluster::new_realm(&agents).await.unwrap().0;
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
                address: lb.next().unwrap().clone(),
                id,
                public_key,
            })
            .collect(),
        register_threshold: 3,
        recover_threshold: 3,
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

    let auth_token = create_token(
        &Claims {
            issuer: tenant.to_owned(),
            subject: String::from("mario"),
        },
        &auth_key,
        auth_key_version,
    );

    let mut demo_status: Option<ExitStatus> = None;

    if let Some(demo) = args.demo {
        info!(pid = std::process::id(), "runner: executing demo");
        demo_status = Some(
            Command::new(demo)
                .arg("--tls-certificate")
                .arg(certificates.cert_file_der.clone())
                .arg("--configuration")
                .arg(serde_json::to_string(&configuration).unwrap())
                .arg("--auth-token")
                .arg(auth_token.0.expose_secret())
                .status()
                .expect("Couldn't run demo executable"),
        );
    }

    if args.keep_alive {
        warn!(
            configuration = serde_json::to_string(&configuration).unwrap(),
            auth_token = auth_token.0.expose_secret(),
            tls_certificate = ?certificates.cert_file_der.clone(),
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
