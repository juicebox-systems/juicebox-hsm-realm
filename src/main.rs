use actix::prelude::*;
use tracing::{info, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::FmtSubscriber;

mod client;
mod realm;
mod server;
mod types;

use client::{Client, Configuration, Pin, Realm, RecoverError, UserSecret};
use server::Server;
use types::{AuthToken, Policy};

async fn initialize_realm() -> Result<(), realm::cluster::NewRealmError> {
    use realm::agent::Agent;
    use realm::hsm::{Hsm, RealmKey};
    use realm::store::Store;

    info!("creating in-memory store");
    let store = Store::new().start();

    let num_hsms = 5;
    info!(count = num_hsms, "creating HSMs and agents");
    let agents: Vec<Addr<Agent>> = {
        let key = RealmKey::random();
        (1..=num_hsms)
            .map(|i| {
                let hsm = Hsm::new(format!("hsm{i:02}"), key.clone()).start();
                Agent::new(format!("agent{i:02}"), hsm, store.clone()).start()
            })
            .collect()
    };

    let realm_id = realm::cluster::new_realm(&agents).await?;
    info!(?realm_id, "initialized cluster");
    Ok(())
}

#[actix_rt::main]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_file(true)
        .with_line_number(true)
        .with_max_level(Level::DEBUG)
        .with_span_events(FmtSpan::ACTIVE)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    info!("set up tracing");

    initialize_realm().await.unwrap();

    println!("main: Starting 4 servers");
    let server1_addr = Server::new(String::from("server1")).start();
    let server2_addr = Server::new(String::from("server2")).start();
    let server3_addr = Server::new(String::from("server3")).start();
    let server4_addr = Server::new(String::from("dead-server4")).start();
    println!();

    let client = Client::new(
        Configuration {
            realms: vec![
                Realm {
                    address: server1_addr,
                    public_key: b"qwer".to_vec(),
                },
                Realm {
                    address: server2_addr,
                    public_key: b"asdf".to_vec(),
                },
                Realm {
                    address: server3_addr,
                    public_key: b"zxcv".to_vec(),
                },
                Realm {
                    address: server4_addr,
                    public_key: b"uiop".to_vec(),
                },
            ],
            register_threshold: 3,
            recover_threshold: 3,
        },
        AuthToken {
            user: String::from("mario"),
            signature: String::from("it's-a-me!"),
        },
    );

    println!("main: Starting register (allowing 2 guesses)");
    client
        .register(
            &Pin(b"1234".to_vec()),
            &UserSecret(b"teyla21".to_vec()),
            Policy { num_guesses: 2 },
        )
        .await
        .expect("register failed");
    println!("main: register succeeded");
    println!();

    println!("main: Starting recover with wrong PIN (guess 1)");
    match client.recover(&Pin(b"1212".to_vec())).await {
        Err(RecoverError::Unsuccessful(_)) => { /* ok */ }
        result => panic!("Unexpected result from recover: {result:?}"),
    };
    println!();

    println!("main: Starting recover with correct PIN (guess 2)");
    let secret = client
        .recover(&Pin(b"1234".to_vec()))
        .await
        .expect("recover failed");
    println!(
        "main: Recovered secret {:?}",
        String::from_utf8_lossy(&secret.0)
    );
    println!();

    println!("main: Starting recover with wrong PIN (guess 1)");
    match client.recover(&Pin(b"1212".to_vec())).await {
        Err(RecoverError::Unsuccessful(_)) => { /* ok */ }
        result => panic!("Unexpected result from recover: {result:?}"),
    };
    println!();

    println!("main: Starting recover with wrong PIN (guess 2)");
    match client.recover(&Pin(b"1212".to_vec())).await {
        Err(RecoverError::Unsuccessful(_)) => { /* ok */ }
        result => panic!("Unexpected result from recover: {result:?}"),
    };
    println!();

    println!("main: Starting recover with correct PIN (guess 3)");
    match client.recover(&Pin(b"1234".to_vec())).await {
        Err(RecoverError::Unsuccessful(_)) => { /* ok */ }
        result => panic!("Unexpected result from recover: {result:?}"),
    };
    println!();

    println!("main: Starting register");
    client
        .register(
            &Pin(b"1234".to_vec()),
            &UserSecret(b"teyla21".to_vec()),
            Policy { num_guesses: 2 },
        )
        .await
        .expect("register failed");
    println!("main: register succeeded");
    println!();

    println!("main: Deleting secret");
    match client.delete_all().await {
        Ok(()) => {
            println!("main: delete succeeded");
        }
        Err(e) => {
            println!("main: warning: delete failed: {e:?}");
        }
    }
    println!();

    println!("main: exiting");
    System::current().stop();
}
