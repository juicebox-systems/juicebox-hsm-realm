use once_cell::sync::Lazy;
use std::path::PathBuf;
use std::process::Command;

use juicebox_process_group::ProcessGroup;
use testing::exec::bigtable::emulator;
use testing::exec::cluster_gen::{create_cluster, ClusterConfig, ClusterResult, RealmConfig};
use testing::exec::hsm_gen::Entrust;
use testing::exec::PortIssuer;

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8444));

#[tokio::test]
async fn cluster_bench() {
    let bt_args = emulator(PORT.next());
    let mut processes = ProcessGroup::new();

    let cluster_args = ClusterConfig {
        load_balancers: 1,
        realms: vec![RealmConfig {
            hsms: 3,
            groups: 1,
            state_dir: None,
        }],
        bigtable: bt_args,
        secrets_file: Some(PathBuf::from("../secrets-demo.json")),
        entrust: Entrust(false),
        path_to_target: PathBuf::from(".."),
    };

    let cluster = create_cluster(cluster_args, &mut processes, PORT.clone())
        .await
        .unwrap();

    run_cluster_bench(&cluster, &[]);
    run_cluster_bench(&cluster, &["--conn-pool"]);
}

fn run_cluster_bench(cluster: &ClusterResult, extra_args: &[&str]) {
    let mut cb = Command::new(
        PathBuf::from("..")
            .join("target")
            .join(if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            })
            .join("cluster_bench"),
    );
    cb.arg("--configuration")
        .arg(cluster.configuration().to_json())
        .arg("--count")
        .arg("25")
        .arg("--tenant")
        .arg("test-acme")
        .arg("--secrets-file")
        .arg("../secrets-demo.json")
        .arg("--tls-certificate")
        .arg(cluster.certs.cert_file_der.clone());
    cb.args(extra_args);
    assert!(cb.status().unwrap().success());
}
