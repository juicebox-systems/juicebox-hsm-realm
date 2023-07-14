use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use once_cell::sync::Lazy;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{ProcessExt, SystemExt};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_rustls::rustls::{self, Certificate, ClientConfig, ServerName};
use tokio_rustls::TlsConnector;
use url::Url;

use juicebox_sdk_process_group::ProcessGroup;
use testing::exec::bigtable::emulator;
use testing::exec::certs::{create_localhost_key_and_cert, Certificates};
use testing::exec::cluster_gen::{create_cluster, ClusterConfig, RealmConfig};
use testing::exec::hsm_gen::{Entrust, MetricsParticipants};
use testing::exec::PortIssuer;

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8777));

#[tokio::test]
async fn sighup_reloads_cert() {
    let bt_args = emulator(PORT.next());
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
        secrets_file: Some(PathBuf::from("../secrets-demo.json")),
        entrust: Entrust(false),
        path_to_target: PathBuf::from(".."),
    };

    let cluster = create_cluster(cluster_args, &mut processes, PORT.clone())
        .await
        .unwrap();

    let server_certs = get_server_cert(&cluster.load_balancers[0], &cluster.certs)
        .await
        .unwrap();
    let server_certs2 = get_server_cert(&cluster.load_balancers[0], &cluster.certs)
        .await
        .unwrap();
    assert_eq!(server_certs, server_certs2);

    // Generate a new key/certificate
    let new_certificates = create_localhost_key_and_cert("../target".into())
        .expect("Failed to create TLS key/cert for load balancer");

    // SIGHUP the lb to get it to re-load the key/cert
    let mut system = sysinfo::System::default();
    system.refresh_all();
    for p in system.processes_by_name("load_balancer") {
        let pid = Pid::from_raw(usize::from(p.pid()) as i32);
        signal::kill(pid, Signal::SIGHUP).unwrap();
    }

    for _ in 1..10 {
        let new_server_certs =
            match get_server_cert(&cluster.load_balancers[0], &new_certificates).await {
                Ok(certs) => certs,
                Err(_) => {
                    // The LB may not have finished loading the new cert yet, give it a few chances.
                    sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
        assert_ne!(new_server_certs, server_certs);
        break;
    }
}

// Returns the server certificates reported by the load balancer over https.
async fn get_server_cert(lb: &Url, root_cert: &Certificates) -> anyhow::Result<Vec<Certificate>> {
    let host = format!("{}:{}", lb.domain().unwrap(), lb.port().unwrap());
    let mut root_certs = rustls::RootCertStore::empty();
    let cert = rustls::Certificate(fs::read(root_cert.cert_file_der.as_path()).unwrap());
    root_certs.add(&cert).unwrap();

    let client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_certs)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let stream = TcpStream::connect(&host).await.unwrap();
    Ok(connector
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await?
        .get_ref()
        .1
        .peer_certificates()
        .unwrap()
        .to_owned())
}
