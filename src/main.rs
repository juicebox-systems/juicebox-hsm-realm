use actix::prelude::*;

mod client;
mod server;
mod types;

use client::{Client, Pin, Realm, RecoverError, UserSecret};
use server::Server;
use types::{AuthToken, Policy};

#[actix_rt::main]
async fn main() {
    println!("main: Hello, world!");

    let server1_addr = Server::new(String::from("server1")).start();
    let server2_addr = Server::new(String::from("server2")).start();
    let server3_addr = Server::new(String::from("server3")).start();

    let client = Client::new(
        vec![
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
        ],
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
    client.delete_all().await.expect("delete_all failed");
    println!();

    println!("main: exiting");
    System::current().stop();
}
