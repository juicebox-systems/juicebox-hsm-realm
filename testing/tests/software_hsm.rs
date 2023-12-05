use std::process::Command;
use std::time::Duration;
use std::{env, fs};

use agent_core::hsm::HsmClient;
use juicebox_process_group::ProcessGroup;
use observability::metrics;
use software_hsm_client::HsmHttpClient;

#[tokio::test]
async fn hsm_reload_state() {
    let dir = env::temp_dir().join("start_hsm_from_saved_state");
    let _ignore_error = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let mut pg = ProcessGroup::new();
    let mut cmd = Command::new("../target/debug/software_hsm");
    cmd.arg("--key")
        .arg("start_hsm_from_saved_state")
        .arg("--state-dir")
        .arg(&dir)
        .arg("--listen")
        .arg("127.0.0.1:10101");
    pg.spawn(&mut cmd);
    let hsm_url = "http://localhost:10101".parse().unwrap();

    let hsm_client = HsmClient::new(
        HsmHttpClient::new(hsm_url),
        "test".to_owned(),
        metrics::Client::NONE,
    );
    wait_til_running(&hsm_client).await;
    hsm_client.send(hsm_api::NewRealmRequest {}).await.unwrap();
    let status = hsm_client.send(hsm_api::StatusRequest {}).await.unwrap();

    pg.kill();
    pg.spawn(&mut cmd);
    wait_til_running(&hsm_client).await;

    let status2 = hsm_client.send(hsm_api::StatusRequest {}).await.unwrap();
    assert_eq!(status.id, status2.id);
    assert_eq!(status.public_key, status2.public_key);
    let realm = status.realm.unwrap();
    let realm2 = status2.realm.unwrap();
    assert_eq!(realm.id, realm2.id);
    assert_eq!(realm.statement, realm2.statement);
}

async fn wait_til_running(hsm_client: &HsmClient<HsmHttpClient>) {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if hsm_client.send(hsm_api::StatusRequest {}).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
