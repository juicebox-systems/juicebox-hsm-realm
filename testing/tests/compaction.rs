use once_cell::sync::Lazy;
use reqwest::Url;
use std::fmt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use testing::background::BackgroundClientRequests;
use tokio::time::sleep;
use tracing::info;

use juicebox_process_group::ProcessGroup;
use testing::exec::bigtable::emulator;
use testing::exec::cluster_gen::{create_cluster, ClusterConfig, RealmConfig};
use testing::exec::hsm_gen::Entrust;
use testing::exec::PortIssuer;

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8333));

#[tokio::test(flavor = "multi_thread")]
async fn compaction() {
    // This panics if called from more than one test, but it can be helpful.
    // observability::logging::configure("compaction test");

    let bt_args = emulator(PORT.next());
    let mut processes = ProcessGroup::new();

    let cluster_args = ClusterConfig {
        load_balancers: 1,
        cluster_managers: 1,
        realms: vec![RealmConfig {
            hsms: 3,
            groups: 1,
            state_dir: None,
        }],
        bigtable: bt_args,
        local_pubsub: true,
        secrets_file: Some(PathBuf::from("../secrets-demo.json")),
        entrust: Entrust(false),
        path_to_target: PathBuf::from(".."),
    };

    let cluster = create_cluster(cluster_args, &mut processes, 3000)
        .await
        .unwrap();

    let client = cluster.client_for_user(String::from("teyla"));
    let mut background_work = BackgroundClientRequests::spawn(client).await;
    let agents = &cluster.realms[0].agents;

    // Wait til our background register/recover workers have made some requests.
    background_work
        .wait_for_progress(3, Duration::from_secs(5))
        .await;

    // Note: This test doesn't stop the leader because the background_work
    // times out slowly and panics on any errors.

    signal_agent(&agents[1], Signal::Stop);

    info!("sleeping");
    sleep(Duration::from_secs(10)).await;
    background_work
        .wait_for_progress(3, Duration::from_secs(5))
        .await;

    signal_agent(&agents[1], Signal::Cont);
    signal_agent(&agents[2], Signal::Stop);
    // Now agents[1] will need to participate, since agents[2] is offline.

    info!("sleeping");
    sleep(Duration::from_secs(10)).await;
    background_work
        .wait_for_progress(3, Duration::from_secs(5))
        .await;

    signal_agent(&agents[2], Signal::Cont);

    info!("sleeping");
    sleep(Duration::from_secs(10)).await;
    background_work
        .wait_for_progress(3, Duration::from_secs(5))
        .await;
}

#[derive(Clone, Copy, Debug)]
enum Signal {
    Cont, // resume the process (it becomes eligible to run again)
    Stop, // pause the process (it gets no more CPU time)
}

impl Signal {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Cont => "CONT",
            Self::Stop => "STOP",
        }
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

fn signal_agent(agent: &Url, kind: Signal) {
    info!(signal = %kind, %agent, "signaling agent");
    let host = agent.host().expect("need agent host");
    let port = agent.port().expect("need agent port");
    let status = Command::new("pkill")
        .arg("--full")
        .arg("--newest")
        .arg("--signal")
        .arg(kind.as_str())
        .arg(format!(
            "./target/.*/software_agent .* --listen {host}:{port} "
        ))
        .status()
        .unwrap_or_else(|err| panic!("failed to send signal {kind} to agent {agent}: {err}"));
    if !status.success() {
        panic!("failed to send signal {kind} to agent {agent}: {status}")
    }
}
