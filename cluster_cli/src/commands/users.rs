use anyhow::{anyhow, Context};
use chrono::{DateTime, Months, Utc};
use futures::future::join_all;
use std::collections::HashSet;
use std::time::SystemTime;

use agent_api::{AgentService, StatusRequest};
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc;
use juicebox_sdk::RealmId;
use store::StoreClient;

use crate::UserSummaryWhen;

pub(crate) async fn user_summary(
    store: &StoreClient,
    agents_client: &Client<AgentService>,
    mut realms: Vec<RealmId>,
    when: UserSummaryWhen,
) -> anyhow::Result<()> {
    let when = match when {
        UserSummaryWhen::ThisMonth => SystemTime::now(),
        UserSummaryWhen::LastMonth => last_month(),
    };
    if realms.is_empty() {
        realms = find_realms(store, agents_client)
            .await
            .context("service discovery failed")?;
        if realms.is_empty() {
            return Err(anyhow!("couldn't find any realms via service discovery"));
        }
    }
    let mut printed_headers = false;
    for realm in realms {
        let r = store
            .count_realm_users(&realm, when)
            .await
            .context("counting rows in realm-users table")?;
        if !printed_headers {
            println!(
                "{} - {}",
                DateTime::<Utc>::from(r.start),
                DateTime::<Utc>::from(r.end)
            );
            println!("realm,tenant,users");
            printed_headers = true;
        }
        for row in r.tenant_user_counts {
            println!("{:?},\"{}\",{}", realm, row.0, row.1);
        }
    }
    Ok(())
}

fn last_month() -> SystemTime {
    let d = Utc::now();
    let prev = d.checked_sub_months(Months::new(1)).unwrap();
    prev.into()
}

async fn find_realms(
    store: &StoreClient,
    agents_client: &Client<AgentService>,
) -> Result<Vec<RealmId>, tonic::Status> {
    let agents = store.get_addresses(Some(store::ServiceKind::Agent)).await?;

    let status = join_all(
        agents
            .iter()
            .map(|(url, _)| rpc::send(agents_client, url, StatusRequest {})),
    )
    .await;

    let mut realms = HashSet::<RealmId>::new();
    for rs in status
        .into_iter()
        .filter_map(|s| s.ok())
        .filter_map(|s| s.hsm)
        .filter_map(|s| s.realm)
    {
        realms.insert(rs.id);
    }
    let mut results = Vec::new();
    results.extend(realms);
    Ok(results)
}
