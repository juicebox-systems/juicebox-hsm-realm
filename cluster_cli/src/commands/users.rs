use anyhow::{anyhow, Context};
use chrono::{DateTime, Datelike, Months, Utc};
use futures::future::join_all;
use std::collections::HashSet;
use std::time::SystemTime;

use agent_api::StatusRequest;
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc;
use juicebox_sdk::RealmId;
use retry_loop::RetryError;
use store::StoreClient;

use crate::UserSummaryWhen;

pub(crate) async fn user_summary(
    store: &StoreClient,
    agents_client: &Client,
    mut realms: Vec<RealmId>,
    when: UserSummaryWhen,
    start: Option<SystemTime>,
    end: Option<SystemTime>,
) -> anyhow::Result<()> {
    let (start, end) = date_range(when, start, end)?;
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
            .count_realm_users(&realm, start, end)
            .await
            .context("counting rows in realm-users table")?;
        if !printed_headers {
            println!("start,end,realm,tenant,users");
            printed_headers = true;
        }
        let start = DateTime::<Utc>::from(r.start);
        let end = DateTime::<Utc>::from(r.end);
        for row in r.tenant_user_counts {
            println!("{},{},{:?},\"{}\",{}", start, end, realm, row.0, row.1);
        }
    }
    Ok(())
}

fn date_range(
    w: UserSummaryWhen,
    start: Option<SystemTime>,
    end: Option<SystemTime>,
) -> anyhow::Result<(SystemTime, SystemTime)> {
    match (start, end) {
        (Some(s), Some(e)) => Ok((s, e)),
        (Some(_), None) | (None, Some(_)) => {
            Err(anyhow!("must specify both start and end dates or neither"))
        }
        (None, None) => {
            let mut start = Utc::now().with_day(1).unwrap();
            if w == UserSummaryWhen::LastMonth {
                start = start.checked_sub_months(Months::new(1)).unwrap();
            }
            let end = start.checked_add_months(Months::new(1)).unwrap();
            Ok((start.into(), end.into()))
        }
    }
}

async fn find_realms(
    store: &StoreClient,
    agents_client: &Client,
) -> Result<Vec<RealmId>, RetryError<tonic::Status>> {
    let agents = store.get_addresses(Some(store::ServiceKind::Agent)).await?;

    let status = join_all(
        agents
            .iter()
            .map(|(url, _)| rpc::send(agents_client, url, StatusRequest {})),
    )
    .await;

    let realms: HashSet<RealmId> = status
        .into_iter()
        .filter_map(|s| s.ok())
        .filter_map(|s| s.hsm)
        .filter_map(|s| s.realm)
        .map(|rs| rs.id)
        .collect();

    Ok(Vec::from_iter(realms))
}
