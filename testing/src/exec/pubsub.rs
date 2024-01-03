use google::GrpcConnectionOptions;
use http::Uri;
use juicebox_sdk::RealmId;
use serde_json::json;
use std::env;
use std::error::Error;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::info;

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

    let start = Instant::now();
    let mut connect_attempts = 0u64;
    loop {
        connect_attempts += 1;
        let last_err: Box<dyn Error> = match google_pubsub::Publisher::new(
            Some(uri.clone()),
            project.clone(),
            None,
            metrics::Client::NONE,
            GrpcConnectionOptions::default(),
        )
        .await
        {
            Ok(p) => match p.publish(RealmId([0; 16]), "bob", Message(json!(42))).await {
                Ok(_) => {
                    info!(
                        %uri,
                        elapsed_s = format!("{:.1}", start.elapsed().as_secs_f32()),
                        connect_attempts,
                        "pubsub emulator is up (published test message)"
                    );
                    return uri;
                }
                Err(err) => err,
            },
            Err(err) => Box::new(err),
        };

        // 20 seconds ought to be more than enough. As of 2023-11, macos-12
        // runners in CI often took over 10 seconds to connect, but they were so
        // overloaded that they went on to time out on other tests after that.
        // Occasionally still see timeouts at 20 seconds, suspect there is a
        // more systematic issue, perhaps related to socket recycling.
        let elapsed = start.elapsed();
        if elapsed > Duration::from_secs(20) {
            println!(
                "failed to connect to pubsub emulator at {uri} after {:.1} s and \
                                 {connect_attempts} attempts. last error: {last_err}",
                elapsed.as_secs_f32(),
            );
            if elapsed > Duration::from_secs(40) {
                panic!("giving up")
            }
            sleep(Duration::from_secs(1)).await;
        } else {
            sleep(Duration::from_millis(10)).await;
        }
    }
}

fn run_in_docker(pg: &mut ProcessGroup, host_port: u16) {
    let image = "gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators";

    // Downloading and extracting the image can take longer than the timeout
    // for connecting to the emulator, so pull the image now and wait if
    // needed.
    if Command::new("docker")
        .arg("images")
        .arg("--quiet")
        .arg(image)
        .output()
        .is_ok_and(|output| output.stdout.is_empty())
    {
        info!(image, "pulling pubsub emulator Docker image");
        let status = Command::new("docker")
            .arg("pull")
            .arg(image)
            .status()
            .expect("docker pull failed");
        if !status.success() {
            panic!("docker pull failed: {status}");
        }
    }

    let container_port: u16 = 8085;
    info!(
        %image,
        %host_port,
        %container_port,
        "starting pubsub emulator in Docker",
    );
    pg.spawn(
        Command::new("docker")
            .arg("run")
            .arg("-p")
            .arg(format!("{host_port}:{container_port}"))
            .arg("-i")
            .arg("--init")
            .arg("--rm")
            .arg(image)
            .arg("gcloud")
            .arg("beta")
            .arg("emulators")
            .arg("pubsub")
            .arg("start")
            .arg(format!("--host-port=0.0.0.0:{container_port}")),
    );
}

fn run_from_jar(pg: &mut ProcessGroup, port: u16, jar: String) {
    info!(jar, port, "starting pubsub emulator in Java");
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
