use http::Uri;
use juicebox_sdk::RealmId;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;

use juicebox_process_group::ProcessGroup;
use observability::metrics;
use pubsub_api::{Message, Publisher};

// Runs the local pubsub emulator and returns the URL to it.
// Requires Docker.
pub async fn run(pg: &mut ProcessGroup, port: u16, project: String) -> Uri {
    pg.spawn(
        Command::new("docker")
            .arg("run")
            .arg("-p")
            .arg(format!("{port}:8085"))
            .arg("-i")
            .arg("--init")
            .arg("gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators")
            .arg("gcloud")
            .arg("beta")
            .arg("emulators")
            .arg("pubsub")
            .arg("start")
            .arg("--host-port=0.0.0.0:8085"),
    );
    let uri = Uri::try_from(&format!("http://localhost:{port}")).unwrap();

    for _tries in 0..500 {
        match google_pubsub::Publisher::new(
            Some(uri.clone()),
            project.clone(),
            None,
            metrics::Client::NONE,
        )
        .await
        {
            Ok(p) => match p.publish(RealmId([0; 16]), "bob", Message(vec![42])).await {
                Ok(_) => return uri,
                Err(_) => {
                    sleep(Duration::from_millis(20)).await;
                }
            },
            Err(_) => {
                sleep(Duration::from_millis(20)).await;
            }
        }
    }
    panic!("failed to connect to pubsub emulator after many attempts");
}
