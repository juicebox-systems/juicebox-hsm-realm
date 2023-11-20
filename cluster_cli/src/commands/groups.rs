use reqwest::Url;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use hsm_api::{GroupId, GroupStatus, HsmId, LeaderStatus, OwnedRange};
use juicebox_networking::reqwest::Client;
use juicebox_realm_api::types::RealmId;
use store::StoreClient;
use table::{Column, FmtWriteStdOut, Justify, Table, TableStyle};

use crate::get_hsm_statuses;

#[derive(Default)]
struct GroupInfo {
    members: Vec<(HsmId, GroupStatus)>,
    leader: Option<(HsmId, LeaderStatus)>,
}

pub async fn status(c: &Client, store: &StoreClient) -> anyhow::Result<()> {
    let status_responses = get_hsm_statuses(c, store).await?;

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
            if let Some((_, leader)) = &group.leader {
                if let Some(OwnedRange { start, end }) = &leader.owned_range {
                    println!("\tOwns: {}-", hex::encode(start.0));
                    println!("\t      {}", hex::encode(end.0));
                }
            }
            print_group_table(group, &addresses);
        }
        println!();
    }
    Ok(())
}

fn print_group_table(group: &GroupInfo, addresses: &HashMap<HsmId, Url>) {
    let rows: Vec<_> = group
        .members
        .iter()
        .map(|(hsm_id, group_status)| {
            let leader = group
                .leader
                .as_ref()
                .filter(|(id, _)| id == hsm_id)
                .map(|(_, status)| status);
            [
                hsm_id.to_string(),
                addresses.get(hsm_id).unwrap().to_string(),
                group_status.role.to_string(),
                match &group_status.captured {
                    None => String::from("None"),
                    Some((index, _mac)) => index.to_string(),
                },
                match leader {
                    Some(LeaderStatus {
                        committed: Some(commit_idx),
                        ..
                    }) => commit_idx.to_string(),
                    Some(LeaderStatus {
                        committed: None, ..
                    }) => String::from("None"),
                    _ => String::from(""),
                },
            ]
        })
        // Include rows for HSMs in the configuration that didn't respond.
        .chain(
            group.members[0]
                .1
                .configuration
                .iter()
                .filter(|hsm_id| !group.members.iter().any(|(h, _)| &h == hsm_id))
                .map(|hsm_id| {
                    [
                        hsm_id.to_string(),
                        String::from("[error: not found]"),
                        String::from(""),
                        String::from(""),
                        String::from(""),
                    ]
                }),
        )
        .collect();

    let table = Table::new(
        [
            Column::new("HSM ID"),
            Column::new("Agent URL"),
            Column::new("Role"),
            Column::new("Captured").justify(Justify::Right),
            Column::new("Commit").justify(Justify::Right),
        ],
        rows,
        TableStyle::default(),
    );
    table.render(&mut FmtWriteStdOut::stdout()).unwrap();
}
