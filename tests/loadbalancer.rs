use http::StatusCode;
use juicebox_sdk_core::requests::{SecretsRequest, BODY_SIZE_LIMIT};
use once_cell::sync::Lazy;
use std::path::PathBuf;
use std::time::Duration;

use juicebox_hsm::exec::cluster_gen::{create_cluster, ClusterConfig, RealmConfig};
use juicebox_hsm::exec::hsm_gen::{Entrust, MetricsParticipants};
use juicebox_hsm::exec::PortIssuer;
use juicebox_sdk_networking::rpc::Rpc;
use juicebox_sdk_process_group::ProcessGroup;

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8444));

fn emulator() -> store::Args {
    let u = format!("http://localhost:{}", PORT.next()).parse().unwrap();
    store::Args {
        project: String::from("prj"),
        instance: String::from("inst"),
        url: Some(u),
    }
}

#[tokio::test]
async fn request_bodysize_check() {
    let bt_args = emulator();
    let mut processes = ProcessGroup::new();

    let cluster_args = ClusterConfig {
        load_balancers: 1,
        realms: vec![RealmConfig {
            hsms: 1,
            groups: 1,
            metrics: MetricsParticipants::None,
            state_dir: None,
        }],
        bigtable: bt_args,
        secrets_file: Some(PathBuf::from("secrets-demo.json")),
        entrust: Entrust(false),
    };

    let cluster = create_cluster(cluster_args, &mut processes, PORT.clone())
        .await
        .unwrap();

    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .use_rustls_tls();
    b = b.add_root_certificate(cluster.lb_cert());

    let http = b.build().unwrap();
    let req = vec![1; BODY_SIZE_LIMIT + 1];
    let res = http
        .post(
            cluster.load_balancers[0]
                .join(SecretsRequest::PATH)
                .unwrap(),
        )
        .body(req)
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::PAYLOAD_TOO_LARGE, res.status());

    let req = vec![1; BODY_SIZE_LIMIT];
    let res = http
        .post(
            cluster.load_balancers[0]
                .join(SecretsRequest::PATH)
                .unwrap(),
        )
        .body(req)
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::BAD_REQUEST, res.status());
}
