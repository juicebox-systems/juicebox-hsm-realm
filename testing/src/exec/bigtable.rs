use google::GrpcConnectionOptions;
use juicebox_process_group::ProcessGroup;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

use store::{BigtableArgs, Options};

pub struct BigtableRunner;

impl BigtableRunner {
    pub async fn run(pg: &mut ProcessGroup, args: &BigtableArgs) {
        if let Some(emulator_url) = &args.url {
            info!(
                port = %emulator_url.port().unwrap(),
                "Starting bigtable emulator"
            );
            pg.spawn(
                Command::new("emulator")
                    .arg("-port")
                    .arg(emulator_url.port().unwrap().as_str()),
            );
            for _ in 0..200 {
                match args.connect_data(None, Options::default()).await {
                    Ok(_) => return,
                    Err(_e) => {
                        sleep(Duration::from_millis(10)).await;
                    }
                }
            }
            panic!("repeatedly failed to connect to bigtable data service");
        }
    }
}

pub fn emulator(port: u16) -> store::BigtableArgs {
    let u = format!("http://localhost:{port}").parse().unwrap();
    let d = GrpcConnectionOptions::default();
    store::BigtableArgs {
        project: String::from("prj"),
        instance: String::from("inst"),
        url: Some(u),
        timeout: d.timeout,
        connect_timeout: d.connect_timeout,
        http2_keepalive_interval: d.http2_keepalive_interval,
        http2_keepalive_timeout: d.http2_keepalive_timeout,
        http2_keepalive_while_idle: d.http2_keepalive_while_idle,
    }
}
