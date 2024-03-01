use futures::future::join_all;
use http::StatusCode;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use store::StoreClient;
use url::Url;

use ::reqwest::ClientBuilder;
use agent_api::{ReloadTenantConfigurationRequest, ReloadTenantConfigurationResponse};
use cluster_core::{JoinRealmError, NewRealmError};
use juicebox_networking::reqwest::{self, ClientOptions};
use juicebox_networking::rpc;
use juicebox_process_group::ProcessGroup;
use juicebox_sdk::{
    AuthToken, Client, Pin, Policy, RealmId, RecoverError, RegisterError, TokioSleeper, UserInfo,
    UserSecret,
};
use store::tenant_config::TenantConfiguration;
use testing::exec::bigtable::emulator;
use testing::exec::cluster_gen::{create_cluster, ClusterConfig, RealmConfig};
use testing::exec::hsm_gen::Entrust;
use testing::exec::PortIssuer;

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8666));

#[tokio::test]
async fn realm() {
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
        bigtable: bt_args,
        local_pubsub: true,
        secrets_file: Some(PathBuf::from("../secrets-demo.json")),
        entrust: Entrust(false),
        path_to_target: fs::canonicalize("..").unwrap(),
    };

    let cluster = create_cluster(cluster_args, &mut processes, PORT.clone())
        .await
        .unwrap();

    // create_cluster put all the agents in a realm, so we shouldn't be able to
    // new_realm or join_realm them to something else.
    let agent_client = reqwest::Client::new(ClientOptions::default());
    for agent in &cluster.realms[0].agents {
        let r = cluster_core::new_realm(&agent_client, agent).await;
        assert_eq!(Err(NewRealmError::HaveRealm), r);
    }
    let agents = cluster.realms[0].agents.clone();
    let r =
        cluster_core::join_realm(&agent_client, RealmId([42; 16]), &agents[1..], &agents[0]).await;
    assert!(matches!(r, Err(JoinRealmError::InvalidRealm { agent: _ })));

    // can join the realm we're already in
    let r = cluster_core::join_realm(
        &agent_client,
        cluster.realms[0].realm,
        &agents[1..],
        &agents[0],
    )
    .await;
    assert!(r.is_ok());

    // check the agent health check
    let http_client = ClientBuilder::new().build().unwrap();
    for result in join_all(
        cluster.realms[0]
            .agents
            .iter()
            .map(|url| http_client.get(url.join("/livez").unwrap()).send()),
    )
    .await
    .into_iter()
    {
        let resp = result.unwrap();
        assert_eq!(StatusCode::OK, resp.status());
        assert!(resp.text().await.unwrap().contains("hsm"));
    }

    // check the cluster manager health check
    for result in join_all(
        cluster
            .cluster_managers
            .iter()
            .map(|url| http_client.get(url.join("/livez").unwrap()).send()),
    )
    .await
    .into_iter()
    {
        let resp = result.unwrap();
        assert_eq!(StatusCode::OK, resp.status());
        assert!(resp.text().await.unwrap().contains("ok"));
    }

    processes.kill();
}

#[tokio::test]
async fn rate_limiting() {
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
        bigtable: bt_args,
        local_pubsub: true,
        secrets_file: Some(PathBuf::from("../secrets-demo.json")),
        entrust: Entrust(false),
        path_to_target: fs::canonicalize("..").unwrap(),
    };

    let cluster = create_cluster(cluster_args, &mut processes, PORT.clone())
        .await
        .unwrap();

    type JbClient = Client<TokioSleeper, reqwest::Client, HashMap<RealmId, AuthToken>>;

    let reg_recover = |client: JbClient| async move {
        let secret = UserSecret::from(vec![42, 45]);
        let pin = Pin::from(vec![1, 2, 3, 4]);
        let info = UserInfo::from(vec![b'c']);
        let mut rate_limit_errors = match client
            .register(&pin, &secret, &info, Policy { num_guesses: 22 })
            .await
        {
            Ok(_) => 0,
            Err(RegisterError::RateLimitExceeded) => 1,
            Err(e) => panic!("Unexpected error during register {e:?}"),
        };
        if rate_limit_errors == 0 {
            // can only recover if we successfully registered
            match client.recover(&pin, &info).await {
                Ok(recovered_secret) => {
                    assert_eq!(recovered_secret.expose_secret(), secret.expose_secret())
                }
                Err(RecoverError::RateLimitExceeded) => {
                    rate_limit_errors += 1;
                }
                Err(e) => panic!("Unexpected error during recover {e:?}"),
            }
        }
        println!("reg_recover finished with {rate_limit_errors} errors");
        rate_limit_errors
    };
    assert_eq!(0, reg_recover(cluster.client_for_user("presso")).await);

    update_rate_limit(
        &cluster.store,
        &cluster.realms[0].agents,
        &cluster.tenant,
        2,
    )
    .await;

    let rate_limit_errors =
        join_all((0..10).map(|i| reg_recover(cluster.client_for_user(&format!("presso_{i}")))))
            .await
            .into_iter()
            .sum::<i32>();
    assert!(
        rate_limit_errors > 0 && rate_limit_errors < 20,
        "expecting rate_limit_errors to be between 1 and 19, but was {rate_limit_errors}"
    );

    update_rate_limit(
        &cluster.store,
        &cluster.realms[0].agents,
        &cluster.tenant,
        200,
    )
    .await;
    let rate_limit_errors =
        join_all((0..10).map(|i| reg_recover(cluster.client_for_user(&format!("presso_{i}")))))
            .await
            .into_iter()
            .sum::<i32>();
    assert_eq!(0, rate_limit_errors);
}

async fn update_rate_limit(store: &StoreClient, agents: &[Url], tenant: &str, ops_per_sec: usize) {
    store
        .update_tenant(
            tenant,
            &TenantConfiguration {
                capacity_ops_per_sec: ops_per_sec,
            },
        )
        .await
        .unwrap();

    let http_client = reqwest::Client::default();
    for r in join_all(
        agents
            .iter()
            .map(|url| rpc::send(&http_client, url, ReloadTenantConfigurationRequest {})),
    )
    .await
    {
        match r.unwrap() {
            ReloadTenantConfigurationResponse::Ok { num_tenants } => assert!(num_tenants > 0),
            ReloadTenantConfigurationResponse::NoStore => {
                panic!("agent was unable to reload config due to a bigtable error")
            }
        }
    }
}
