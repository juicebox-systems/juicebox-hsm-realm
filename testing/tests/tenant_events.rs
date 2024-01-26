use digest::Digest;
use google::pubsub::v1::subscriber_client::SubscriberClient;
use google::pubsub::v1::{AcknowledgeRequest, PullRequest};
use google_pubsub::subscription_name;
use hsm_api::GuessState;
use once_cell::sync::Lazy;
use serde_json::json;
use sha2::Sha256;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tonic::transport::{Channel, Endpoint};

use juicebox_process_group::ProcessGroup;
use juicebox_sdk::{Pin, Policy, RealmId, RecoverError, UserInfo, UserSecret};
use testing::exec::bigtable::emulator;
use testing::exec::cluster_gen::{create_cluster, ClusterConfig, RealmConfig};
use testing::exec::hsm_gen::Entrust;
use testing::exec::PortIssuer;

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8666));

#[tokio::test]
async fn events() {
    let bt_args = emulator(PORT.next());
    let mut processes = ProcessGroup::new();

    let cluster_args = ClusterConfig {
        load_balancers: 1,
        cluster_managers: 1,
        realms: vec![RealmConfig {
            hsms: 3,
            groups: 1,
            state_dir: None,
        }],
        bigtable: bt_args.clone(),
        local_pubsub: true,
        secrets_file: Some(PathBuf::from("../secrets-demo.json")),
        entrust: Entrust(false),
        path_to_target: fs::canonicalize("..").unwrap(),
    };

    let cluster = create_cluster(cluster_args, &mut processes, PORT.clone())
        .await
        .unwrap();

    let channel = Endpoint::from(cluster.pubsub.as_ref().unwrap().clone())
        .connect()
        .await
        .unwrap();
    let mut sub = Subscriber {
        client: SubscriberClient::new(channel),
        project: bt_args.project,
        tenant: cluster.tenant.clone(),
        realm: cluster.realms[0].realm,
    };

    let client = cluster.client_for_user("bob");
    let pin = Pin::from(vec![1, 2, 3, 4]);
    let info = UserInfo::from(vec![4, 3, 2, 1]);

    client
        .register(
            &pin,
            &UserSecret::from(b"secret".to_vec()),
            &info,
            Policy { num_guesses: 42 },
        )
        .await
        .unwrap();
    sub.assert_has_event("bob", "registered", None).await;

    let recover_error = client
        .recover(&Pin::from(vec![42, 43, 44, 45]), &info)
        .await
        .unwrap_err();
    assert_eq!(
        RecoverError::InvalidPin {
            guesses_remaining: 41
        },
        recover_error
    );
    sub.assert_has_event(
        "bob",
        "guess_used",
        Some(GuessState {
            num_guesses: 42,
            guess_count: 1,
        }),
    )
    .await;

    client.recover(&pin, &info).await.unwrap();
    sub.assert_has_event(
        "bob",
        "guess_used",
        Some(GuessState {
            num_guesses: 42,
            guess_count: 2,
        }),
    )
    .await;
    sub.assert_has_event("bob", "share_recovered", None).await;

    client.delete().await.unwrap();
    sub.assert_has_event("bob", "deleted", None).await;
}

struct Subscriber {
    client: SubscriberClient<Channel>,
    project: String,
    realm: RealmId,
    tenant: String,
}

impl Subscriber {
    async fn assert_has_event(&mut self, user: &str, event: &str, guess: Option<GuessState>) {
        let sub = subscription_name(&self.project, self.realm, &self.tenant);
        let pulled = self
            .client
            .pull(PullRequest {
                subscription: sub.clone(),
                max_messages: 1,
                ..PullRequest::default()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(1, pulled.received_messages.len());

        self.client
            .acknowledge(AcknowledgeRequest {
                subscription: sub,
                ack_ids: vec![pulled.received_messages[0].ack_id.clone()],
            })
            .await
            .unwrap();

        let parsed: HashMap<String, serde_json::Value> = serde_json::from_slice(
            &pulled
                .received_messages
                .first()
                .unwrap()
                .message
                .as_ref()
                .unwrap()
                .data,
        )
        .unwrap();

        let hashed_id = hex::encode(
            Sha256::new()
                .chain_update(format!("{}:{}", self.tenant, user))
                .finalize(),
        );

        let mut exp = HashMap::from([
            (String::from("event"), json!(event)),
            (String::from("user"), json!(hashed_id)),
        ]);
        if let Some(g) = guess {
            exp.insert(String::from("num_guesses"), json!(g.num_guesses));
            exp.insert(String::from("guess_count"), json!(g.guess_count));
        }
        assert_eq!(exp, parsed);
    }
}
