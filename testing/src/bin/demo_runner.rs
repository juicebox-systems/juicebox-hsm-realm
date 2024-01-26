use clap::Parser;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::env::current_dir;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::thread::sleep;
use std::time::Duration;
use tracing::{info, warn};

use juicebox_process_group::ProcessGroup;
use observability::logging;
use service_core::term::install_termination_handler;
use testing::exec::bigtable::emulator;
use testing::exec::cluster_gen::{create_cluster, ClusterConfig, RealmConfig};
use testing::exec::hsm_gen::Entrust;
use testing::exec::PortIssuer;

static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8444));

/// A tool to launch all the Juicebox HSM realm services and execute a demo
/// binary configured to access them.
#[derive(Parser)]
#[command(version = build_info::clap!())]
struct Args {
    /// Path to the demo binary to execute
    #[arg(long)]
    demo: Option<PathBuf>,

    /// Keep the demo stack alive until Ctrl-C is input
    #[arg(short, long, default_value = "false")]
    keep_alive: bool,

    /// Run a smaller demo stack to use fewer resources.
    #[arg(long, default_value_t = false)]
    minimal: bool,

    /// Name of JSON file containing per-tenant keys for authentication.
    #[arg(long, default_value = "secrets-demo.json")]
    secrets_file: PathBuf,
}

#[tokio::main]
async fn main() {
    logging::configure("juicebox-demo-runner");

    let args = Args::parse();

    let mut process_group = ProcessGroup::new();
    install_termination_handler(Duration::from_secs(1));

    let cluster_args = ClusterConfig {
        load_balancers: 1,
        cluster_managers: 1,
        realms: if args.minimal {
            vec![RealmConfig {
                hsms: 1,
                groups: 1,
                state_dir: None,
            }]
        } else {
            vec![
                RealmConfig {
                    hsms: 5,
                    groups: 2,
                    state_dir: None,
                },
                RealmConfig {
                    hsms: 3,
                    groups: 2,
                    state_dir: None,
                },
            ]
        },
        bigtable: emulator(PORT.next()),
        local_pubsub: true,
        secrets_file: Some(args.secrets_file),
        entrust: Entrust(false),
        path_to_target: current_dir().unwrap(),
    };

    let cluster = create_cluster(cluster_args, &mut process_group, PORT.clone())
        .await
        .unwrap();

    let configuration = cluster.configuration();

    let jsonable_auth_tokens: HashMap<String, String> = cluster
        .auth_tokens("mario")
        .into_iter()
        .map(|(id, token)| (hex::encode(id.0), token.expose_secret().to_string()))
        .collect();

    let mut demo_status: Option<ExitStatus> = None;

    if let Some(demo) = args.demo {
        info!(
            pid = std::process::id(),
            program = ?demo,
            tls_certificate = ?cluster.certs.cert_file_der,
            "runner: executing demo"
        );
        let mut child = Command::new(demo)
            .arg("--tls-certificate")
            .arg(cluster.certs.cert_file_der.clone())
            .arg("--configuration")
            .arg(configuration.to_json())
            .arg("--auth-tokens")
            .arg(serde_json::to_string(&jsonable_auth_tokens).unwrap())
            .spawn()
            .expect("couldn't run demo executable");
        info!(
            pid = std::process::id(),
            child = child.id(),
            "runner: started demo process"
        );
        demo_status = Some(child.wait().expect("couldn't wait on demo process"));
    }

    if args.keep_alive {
        warn!(
            configuration = configuration.to_json(),
            auth_tokens = serde_json::to_string(&jsonable_auth_tokens).unwrap(),
            tls_certificate = ?cluster.certs.cert_file_der,
            "runner: stack is active, press ctrl-c to shutdown"
        );

        sleep(Duration::MAX);
    }

    info!(pid = std::process::id(), "runner: done");
    process_group.kill();
    logging::flush();
    info!(pid = std::process::id(), "runner: exiting");

    if let Some(demo_status) = demo_status {
        if !demo_status.success() {
            panic!("demo process failed: {demo_status}");
        }
    }
}
