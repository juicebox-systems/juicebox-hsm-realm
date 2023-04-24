use anyhow::Context;
use cli_table::{
    format::{Justify, Separator},
    print_stdout, Cell, Table,
};
use futures::{future::join_all, FutureExt};
use reqwest::Url;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use hsmcore::hsm::types::{GroupId, GroupStatus, HsmId, LogIndex, StatusResponse};
use loam_mvp::{
    http_client::Client,
    realm::{
        agent::types::{AgentService, StatusRequest},
        store::bigtable::StoreClient,
    },
};
use loam_sdk::RealmId;
use loam_sdk_networking::rpc::{self};

pub async fn status(c: Client<AgentService>, store: StoreClient) -> anyhow::Result<()> {
    println!("Status");
    let addresses = store
        .get_addresses()
        .await
        .context("Failed to get agent addresses from bigtable")?;
    println!("{} Agents listed in service discovery", addresses.len());

    let status_responses: Vec<StatusResponse> =
        join_all(addresses.iter().map(|(hsm_id, url)| {
            rpc::send(&c, url, StatusRequest {}).map(move |r| (r, hsm_id, url))
        }))
        .await
        .into_iter()
        .filter_map(|(s, hsm_id, _)| s.ok().and_then(|s| s.hsm).filter(|s| s.id == *hsm_id))
        .collect();

    #[derive(Default)]
    struct GroupInfo {
        members: Vec<(HsmId, GroupStatus)>,
        leader: Option<(HsmId, Option<LogIndex>)>, //commit
    }
    let mut realms: BTreeMap<RealmId, BTreeSet<GroupId>> = BTreeMap::new();
    let mut groups: BTreeMap<GroupId, GroupInfo> = BTreeMap::new();
    for status_response in status_responses {
        if let Some(realm_status) = status_response.realm {
            for group in realm_status.groups {
                realms.entry(realm_status.id).or_default().insert(group.id);
                let entry = groups.entry(group.id).or_default();
                entry.members.push((status_response.id, group.clone()));
                if group.leader.is_some() {
                    entry.leader = Some((status_response.id, group.leader.unwrap().committed));
                }
            }
        }
    }

    let addresses: HashMap<HsmId, Url> = addresses.into_iter().collect();
    for (realm, realm_groups) in realms {
        println!("Realm: {:?}", realm);
        for group_id in realm_groups {
            println!("\tGroup: {:?}", group_id);
            let group = &groups[&group_id];
            let rows: Vec<_> = group
                .members
                .iter()
                .map(|(hsm_id, group_status)| {
                    vec![
                        hsm_id.to_string().cell(),
                        addresses.get(hsm_id).unwrap().to_string().cell(),
                        group_status.role.to_string().cell(),
                        match &group_status.captured {
                            None => "None".cell(),
                            Some((index, _hmac)) => index.to_string().cell(),
                        }
                        .justify(Justify::Right),
                        match group.leader {
                            Some((leader_id, Some(commit_idx))) if leader_id == *hsm_id => {
                                commit_idx.to_string().cell()
                            }
                            Some((leader_id, None)) if leader_id == *hsm_id => "None".cell(),
                            None | Some(_) => "".cell(),
                        }
                        .justify(Justify::Right),
                    ]
                })
                .collect();
            let table = rows
                .table()
                .separator(Separator::builder().title(Some(Default::default())).build())
                .title(vec!["HSM", "Agent URL", "Role", "Captured", "Commit"])
                .color_choice(cli_table::ColorChoice::Never);
            assert!(print_stdout(table).is_ok());
        }
        println!();
    }
    Ok(())
}
