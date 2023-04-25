use clap::Parser;
use loam_sdk::TokioSleeper;
use loam_sdk_core::types::Policy;
use loam_sdk_networking::rpc::LoadBalancerService;
use reqwest::Certificate;
use std::fs;
use std::path::PathBuf;
use tracing::info;

use loam_mvp::http_client;
use loam_mvp::logging;
use loam_sdk::{AuthToken, Client, Pin, RecoverError, UserSecret};

#[derive(Parser)]
#[command(about = "A rust demo of the loam-sdk")]
struct Args {
    /// The SDK client configuration information, as a JSON string.
    #[arg(short, long)]
    configuration: String,

    /// The SDK client auth token, as a base64-encoded JWT.
    #[arg(short, long)]
    auth_token: AuthToken,

    /// Name of the file containing the certificate(s) used by the load balancer for terminating TLS.
    #[arg(long)]
    tls_certificate: PathBuf,
}

#[tokio::main]
async fn main() {
    logging::configure("loam-demo");

    let args = Args::parse();

    let configuration =
        serde_json::from_str(&args.configuration).expect("failed to parse configuration");

    let lb_cert = Certificate::from_der(
        &fs::read(&args.tls_certificate).expect("failed to read certificate file"),
    )
    .expect("failed to decode certificate file");

    let client: Client<TokioSleeper, http_client::Client<LoadBalancerService>> = Client::with_tokio(
        configuration,
        vec![],
        args.auth_token,
        http_client::Client::new(http_client::ClientOptions {
            additional_root_certs: vec![lb_cert],
        }),
    );

    info!("Starting register (allowing 2 guesses)");
    client
        .register(
            &Pin::from(b"1234".to_vec()),
            &UserSecret::from(b"teyla21".to_vec()),
            Policy { num_guesses: 2 },
        )
        .await
        .expect("register failed");
    info!("Register succeeded");

    info!("Starting recover with wrong PIN (guess 1)");
    match client.recover(&Pin::from(b"1212".to_vec())).await {
        Err(RecoverError::InvalidPin { guesses_remaining }) => {
            assert_eq!(guesses_remaining, 1);
            info!("Recover expectedly unsuccessful")
        }
        result => panic!("Unexpected result from recover: {result:?}"),
    };

    info!("Starting recover with correct PIN (guess 2)");
    let secret = client
        .recover(&Pin::from(b"1234".to_vec()))
        .await
        .expect("recover failed");
    info!(
        secret = String::from_utf8_lossy(secret.expose_secret()).to_string(),
        "Recovered secret"
    );

    info!("Starting recover with wrong PIN (guess 1)");
    match client.recover(&Pin::from(b"1212".to_vec())).await {
        Err(RecoverError::InvalidPin { guesses_remaining }) => {
            assert_eq!(guesses_remaining, 1);
            info!("Recover expectedly unsuccessful")
        }
        result => panic!("Unexpected result from recover: {result:?}"),
    };

    info!("Starting recover with wrong PIN (guess 2)");
    match client.recover(&Pin::from(b"1212".to_vec())).await {
        Err(RecoverError::InvalidPin { guesses_remaining }) => {
            assert_eq!(guesses_remaining, 0);
            info!("Recover expectedly unsuccessful")
        }
        result => panic!("Unexpected result from recover: {result:?}"),
    };

    info!("Starting recover with correct PIN (guess 3)");
    match client.recover(&Pin::from(b"1234".to_vec())).await {
        Err(RecoverError::InvalidPin { guesses_remaining }) => {
            assert_eq!(guesses_remaining, 0);
            info!("Recover expectedly unsuccessful")
        }
        result => panic!("Unexpected result from recover: {result:?}"),
    };

    info!("Starting register");
    client
        .register(
            &Pin::from(b"4321".to_vec()),
            &UserSecret::from(b"presso42".to_vec()),
            Policy { num_guesses: 2 },
        )
        .await
        .expect("register failed");
    info!("register succeeded");

    info!("Starting recover with correct PIN (guess 1)");
    let secret = client
        .recover(&Pin::from(b"4321".to_vec()))
        .await
        .expect("recover failed");
    info!(
        secret = String::from_utf8_lossy(secret.expose_secret()).to_string(),
        "Recovered secret"
    );

    info!("Deleting secret");
    client
        .delete_all()
        .await
        .expect("delete unexpectedly failed");
    info!("delete succeeded");

    logging::flush();
    info!(pid = std::process::id(), "exiting");
}
