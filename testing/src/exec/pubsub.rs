use http::Uri;
use juicebox_sdk::RealmId;
use serde_json::json;
use std::env;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;

use juicebox_process_group::ProcessGroup;
use observability::metrics;
use pubsub_api::{Message, Publisher};

// Runs the local pubsub emulator and returns the URL to it. By default runs the
// emulator from a docker container. If the environment variable PUBSUB_JAR is
// set it will running the emulator jar directly instead.
//
// The jar file is typically at
// ~/google-cloud-sdk/platform/pubsub-emulator/lib/cloud-pubsub-emulator-0.8.6.jar
// but may vary depending on installation method of the cloud SDK. Once you have
// the SDK installed you need to additionally install the emulator with `gcloud
// components install pubsub-emulator`
pub async fn run(pg: &mut ProcessGroup, port: u16, project: String) -> Uri {
    match env::var("PUBSUB_JAR") {
        Ok(jar) => run_from_jar(pg, port, jar),
        Err(_) => run_in_docker(pg, port),
    }
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
            Ok(p) => match p.publish(RealmId([0; 16]), "bob", Message(json!(42))).await {
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

fn run_in_docker(pg: &mut ProcessGroup, port: u16) {
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
}

fn run_from_jar(pg: &mut ProcessGroup, port: u16, jar: String) {
    if !Path::new(&jar).exists() {
        panic!("Jar file indicated by environment variable PUBSUB_JAR does not exist: {jar}");
    }
    // The official way to run the emulator is with `glcoud beta emulators
    // pubsub start` However this runs the gcloud python tool, which in turns
    // runs a shell script which in turn launches the java process. When we then
    // kill the gcloud process, it stops but leaves the child processes running.
    pg.spawn(
        Command::new("java")
            .arg("-jar")
            .arg(jar)
            .arg("--host=localhost")
            .arg(format!("--port={port}")),
    )
}
