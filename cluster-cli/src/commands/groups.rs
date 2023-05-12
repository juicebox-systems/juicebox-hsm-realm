use cli_table::format::{Justify, Separator};
use cli_table::{print_stdout, Cell, Table};
use reqwest::Url;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use hsmcore::hsm::types::{GroupId, GroupStatus, HsmId, LeaderStatus};
use loam_mvp::http_client::Client;
use loam_mvp::realm::{agent::types::AgentService, store::bigtable::StoreClient};
use loam_sdk_core::types::RealmId;

use crate::get_hsm_statuses;

pub async fn status(c: &Client<AgentService>, store: &StoreClient) -> anyhow::Result<()> {
    let status_responses = get_hsm_statuses(c, store).await?;

    #[derive(Default)]
    struct GroupInfo {
        members: Vec<(HsmId, GroupStatus)>,
        leader: Option<(HsmId, LeaderStatus)>,
    }
    let mut realms: BTreeMap<RealmId, BTreeSet<GroupId>> = BTreeMap::new();
    let mut groups: BTreeMap<GroupId, GroupInfo> = BTreeMap::new();
    for (_, status_response) in &status_responses {
        if let Some(realm_status) = &status_response.realm {
            for group in &realm_status.groups {
                realms.entry(realm_status.id).or_default().insert(group.id);
                let entry = groups.entry(group.id).or_default();
                entry.members.push((status_response.id, group.clone()));
                if let Some(leader) = &group.leader {
                    entry.leader = Some((status_response.id, leader.clone()));
                }
            }
        }
    }

    let addresses: HashMap<HsmId, Url> = status_responses
        .into_iter()
        .map(|(url, status)| (status.id, url))
        .collect();
    for (realm, realm_groups) in realms {
        println!("Realm: {:?}", realm);
        for group_id in realm_groups {
            println!("\tGroup: {:?}", group_id);
            let group = &groups[&group_id];
            let rows: Vec<_> = group
                .members
                .iter()
                .map(|(hsm_id, group_status)| {
                    let leader = group
                        .leader
                        .as_ref()
                        .filter(|(id, _)| id == hsm_id)
                        .map(|(_, status)| status);
                    vec![
                        hsm_id.to_string().cell(),
                        addresses.get(hsm_id).unwrap().to_string().cell(),
                        group_status.role.to_string().cell(),
                        match &group_status.captured {
                            None => "None".cell(),
                            Some((index, _hmac)) => index.to_string().cell(),
                        }
                        .justify(Justify::Right),
                        match leader {
                            Some(LeaderStatus {
                                committed: Some(commit_idx),
                                ..
                            }) => commit_idx.to_string().cell(),
                            Some(LeaderStatus {
                                committed: None, ..
                            }) => "None".cell(),
                            _ => "".cell(),
                        }
                        .justify(Justify::Right),
                        match leader {
                            Some(LeaderStatus {
                                owned_range: Some(range),
                                ..
                            }) => format!(
                                "{}-\n{}",
                                hex::encode(range.start.0),
                                hex::encode(range.end.0)
                            )
                            .cell(),
                            Some(LeaderStatus {
                                owned_range: None, ..
                            }) => "None".cell(),
                            _ => "".cell(),
                        },
                    ]
                })
                .collect();
            let table = rows
                .table()
                .separator(Separator::builder().title(Some(Default::default())).build())
                .title(vec![
                    "HSM ID",
                    "Agent URL",
                    "Role",
                    "Captured",
                    "Commit",
                    "Owned Range",
                ])
                .color_choice(cli_table::ColorChoice::Never);
            assert!(print_stdout(table).is_ok());
        }
        println!();
    }
    Ok(())
}
