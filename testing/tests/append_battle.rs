use futures::future::join_all;
use itertools::Itertools;
use once_cell::sync::Lazy;
use rand_core::{OsRng, RngCore};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use agent_api::{AgentService, AppResponse, BecomeLeaderResponse};
use hsm_api::RecordId;
use juicebox_marshalling as marshalling;
use juicebox_networking::reqwest::{self, Client, ClientOptions};
use juicebox_networking::rpc::{self, RpcError};
use juicebox_noise::client::Handshake;
use juicebox_process_group::ProcessGroup;
use juicebox_realm_api::requests::{
    ClientRequestKind, NoiseRequest, NoiseResponse, Register1Response, SecretsRequest,
    SecretsResponse,
};
use juicebox_realm_api::types::SessionId;
use juicebox_sdk::Policy;
use testing::exec::bigtable::emulator;
use testing::exec::cluster_gen::{create_cluster, ClusterConfig, RealmConfig, RealmResult};
use testing::exec::hsm_gen::{Entrust, MetricsParticipants};
use testing::exec::PortIssuer;

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8777));

static TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn leader_battle() {
    let bt_args = emulator(PORT.next());
    let mut processes = ProcessGroup::new();

    let cluster_args = ClusterConfig {
        load_balancers: 1,
        cluster_managers: 3,
        realms: vec![RealmConfig {
            hsms: 3,
            groups: 1,
            metrics: MetricsParticipants::All,
            state_dir: None,
        }],
        bigtable: bt_args,
        secrets_file: Some(PathBuf::from("../secrets-demo.json")),
        entrust: Entrust(false),
        path_to_target: PathBuf::from(".."),
    };

    let cluster = create_cluster(cluster_args, &mut processes, PORT.clone())
        .await
        .unwrap();

    // sanity check the cluster health.
    cluster
        .client_for_user("presso".into())
        .register(
            &b"1234".to_vec().into(),
            &b"secret".to_vec().into(),
            &b"info".to_vec().into(),
            Policy { num_guesses: 4 },
        )
        .await
        .unwrap();

    let opts = ClientOptions {
        timeout: TIMEOUT,
        ..ClientOptions::default()
    };
    let agent_client: Client<AgentService> = reqwest::Client::new(opts);

    make_all_agents_leader(&agent_client, &cluster.realms[0]).await;

    // Make a request to all the agents. We have to do this directly to the
    // agent as the load balancer will stop iterating the potential agents once
    // one successfully handles the request.
    let (successes, errors) =
        make_app_request_to_agents(&agent_client, &cluster.realms[0], SecretsRequest::Register1)
            .await;
    // Register1 doesn't write to the tree. Because hsmId is part of the log
    // entry each HSM will still generate a unique log entry. Only one of them
    // should get written/committed.
    assert!(matches!(
        successes.as_slice(),
        [SecretsResponse::Register1(Register1Response::Ok)]
    ));
    assert_eq!(2, errors.len());
    // The HSMs that lost the write battle will end up responding NotLeader. And
    // should have stepped down.
    assert!(matches!(
        errors.as_slice(),
        [
            AgentAppRequestError::NotOk(AppResponse::NotLeader),
            AgentAppRequestError::NotOk(AppResponse::NotLeader)
        ]
    ));
    assert_eq!(1, num_leaders(&agent_client, &cluster.realms[0]).await);

    // Should still be able to make a request via the LB fine.
    make_all_agents_leader(&agent_client, &cluster.realms[0]).await;
    cluster
        .client_for_user("presso".into())
        .register(
            &b"1234".to_vec().into(),
            &b"secret".to_vec().into(),
            &b"info".to_vec().into(),
            Policy { num_guesses: 4 },
        )
        .await
        .unwrap();

    // The LB sent the request to the original leader, the other agents didn't
    // see anything so they'll still think they're a leader until they see a
    // capture next for the new log entry (which to them is unexpected). At
    // which point they should step down.
    let start = Instant::now();
    loop {
        if num_leaders(&agent_client, &cluster.realms[0]).await == 1 {
            break;
        }
        if start.elapsed() > TIMEOUT {
            panic!("Timed out waiting for HSMs to step down");
        }
        sleep(Duration::from_millis(2)).await;
    }

    // Should still be able to make a request via the LB fine.
    cluster
        .client_for_user("presso".into())
        .register(
            &b"1234".to_vec().into(),
            &b"secret".to_vec().into(),
            &b"info".to_vec().into(),
            Policy { num_guesses: 4 },
        )
        .await
        .unwrap();

    assert_eq!(1, num_leaders(&agent_client, &cluster.realms[0]).await);

    // All the HSMs should be able to transition back to leader.
    make_all_agents_leader(&agent_client, &cluster.realms[0]).await;
}

#[derive(Debug)]
enum AgentAppRequestError {
    NotOk(AppResponse),
    Rpc(RpcError),
}

async fn make_app_request_to_agents(
    agent_client: &Client<AgentService>,
    realm: &RealmResult,
    req: SecretsRequest,
) -> (Vec<SecretsResponse>, Vec<AgentAppRequestError>) {
    let group = *realm.groups.last().unwrap();

    let mut pub_key_bytes = [0u8; 32];
    pub_key_bytes.copy_from_slice(&realm.communication_public_key.0);
    let pub_key = x25519_dalek::PublicKey::from(pub_key_bytes);

    let req = marshalling::to_vec(&req).unwrap();
    join_all(realm.agents.iter().map(|agent| async {
        let (handshake, req) = Handshake::start(&pub_key, &req, &mut OsRng).unwrap();
        let mut record_id = RecordId::max_id();
        OsRng.fill_bytes(&mut record_id.0);
        let r = agent_api::AppRequest {
            realm: realm.realm,
            group,
            record_id,
            session_id: SessionId(OsRng.next_u32()),
            kind: ClientRequestKind::SecretsRequest,
            encrypted: NoiseRequest::Handshake { handshake: req },
            tenant: "Bob".into(),
        };
        match rpc::send(agent_client, agent, r).await {
            Ok(AppResponse::Ok(NoiseResponse::Handshake {
                handshake: result, ..
            })) => {
                let app_res = handshake.finish(&result).unwrap();
                let secret_response: SecretsResponse = marshalling::from_slice(&app_res.1).unwrap();
                Ok(secret_response)
            }
            Ok(other_response) => Err(AgentAppRequestError::NotOk(other_response)),
            Err(err) => Err(AgentAppRequestError::Rpc(err)),
        }
    }))
    .await
    .into_iter()
    .partition_result()
}

// Asks all the agents in the realm to become leader and verifies that they all think they're leader.
async fn make_all_agents_leader(agent_client: &Client<AgentService>, realm: &RealmResult) {
    let start = Instant::now();
    let group = *realm.groups.last().unwrap();
    loop {
        let res = join_all(realm.agents.iter().map(|agent| {
            rpc::send(
                agent_client,
                agent,
                agent_api::BecomeLeaderRequest {
                    realm: realm.realm,
                    group,
                    last: None,
                },
            )
        }))
        .await;

        // There may be HSMs that are still stepping down, so we need to wait for those to complete
        // before they can become leader again.
        if res
            .iter()
            .any(|r| matches!(r, Ok(BecomeLeaderResponse::StepdownInProgress)))
        {
            if start.elapsed() > TIMEOUT {
                panic!("Timed out waiting for stepdown to complete");
            }
            sleep(Duration::from_millis(5)).await;
            continue;
        }

        assert!(res
            .into_iter()
            .all(|r| r.is_ok_and(|r| r == BecomeLeaderResponse::Ok)));

        // Check that they all think they're leader.
        assert_eq!(realm.agents.len(), num_leaders(agent_client, realm).await);
        return;
    }
}

async fn num_leaders(agent_client: &Client<AgentService>, realm: &RealmResult) -> usize {
    let group = *realm.groups.last().unwrap();
    join_all(
        realm
            .agents
            .iter()
            .map(|agent| rpc::send(agent_client, agent, agent_api::StatusRequest {})),
    )
    .await
    .into_iter()
    .filter_map(|r| r.ok())
    .filter_map(|s| s.hsm)
    .filter_map(|hsm| hsm.realm)
    .filter(|r| r.groups.iter().any(|g| g.id == group && g.leader.is_some()))
    .count()
}
