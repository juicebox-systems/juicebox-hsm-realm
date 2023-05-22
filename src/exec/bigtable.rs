use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

use crate::metrics;
use crate::process_group::ProcessGroup;
use crate::realm::store::bigtable::BigTableArgs;

pub struct BigTableRunner;

impl BigTableRunner {
    pub async fn run(pg: &mut ProcessGroup, args: &BigTableArgs) {
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
            for _ in 0..100 {
                match args.connect_data(None, metrics::Client::NONE).await {
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
