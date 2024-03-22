use std::collections::{BTreeMap, BTreeSet, HashMap};

use agent_api::AgentGroupStatus;
use hsm_api::{GroupId, GroupStatus, HsmId, LeaderStatus};
use juicebox_realm_api::types::RealmId;
use table::{Column, FmtWriteStdOut, Justify, Table, TableStyle};

use crate::cluster::ClusterInfo;

#[derive(Default)]
struct GroupInfo {
    members: Vec<(HsmId, GroupStatus)>,
    leader: Option<(HsmId, LeaderStatus)>,
    agents: Vec<(HsmId, AgentGroupStatus)>,
}

pub async fn status(cluster: &ClusterInfo) -> anyhow::Result<()> {
    let mut realms: BTreeMap<RealmId, BTreeSet<GroupId>> = BTreeMap::new();
    let mut groups: BTreeMap<GroupId, GroupInfo> = BTreeMap::new();
    for (status_response, _) in &cluster.statuses {
        if let Some(hsm_response) = &status_response.hsm {
            if let Some(realm_status) = &hsm_response.realm {
                for group in &realm_status.groups {
                    realms.entry(realm_status.id).or_default().insert(group.id);
                    let entry = groups.entry(group.id).or_default();
                    entry.members.push((hsm_response.id, group.clone()));
                    if let Some(leader) = &group.leader {
                        entry.leader = Some((hsm_response.id, leader.clone()));
                    }
                }
                for group in &status_response.agent.groups {
                    let entry = groups.entry(group.group).or_default();
                    entry.agents.push((hsm_response.id, group.clone()))
                }
            }
        }
    }

    let agent_names: HashMap<HsmId, String> = cluster
        .statuses
        .iter()
        .filter(|s| s.0.hsm.is_some())
        .map(|(status, _url)| (status.hsm.as_ref().unwrap().id, status.agent.name.clone()))
        .collect();

    for (realm, realm_groups) in realms {
        println!("Realm: {:?}", realm);
        for group_id in realm_groups {
            println!("\tGroup: {:?}", group_id);
            let group = &groups[&group_id];
            if let Some((_, leader)) = &group.leader {
                if let Some(range) = &leader.owned_range {
                    println!("\tOwns: {}", range);
                }
            }
            print_group_table(group, &agent_names);
        }
        println!();
    }
    Ok(())
}

fn print_group_table(group: &GroupInfo, agent_names: &HashMap<HsmId, String>) {
    let rows: Vec<_> = group
        .members
        .iter()
        .map(|(hsm_id, group_status)| {
            let leader = group
                .leader
                .as_ref()
                .filter(|(id, _)| id == hsm_id)
                .map(|(_, status)| status);
            let agent_ldr = group
                .agents
                .iter()
                .find(|a| a.0 == *hsm_id)
                .and_then(|(_, a)| a.leader.clone());

            [
                hsm_id.to_string(),
                agent_names.get(hsm_id).unwrap().clone(),
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
                match agent_ldr.as_ref().map(|l| &l.last_appended) {
                    Some(None) | None => String::from(""),
                    Some(Some((idx, _mac))) => idx.to_string(),
                },
                match agent_ldr.as_ref().map(|l| l.append_queue_len) {
                    None => String::from(""),
                    Some(l) => l.to_string(),
                },
                match agent_ldr.as_ref().map(|l| l.num_waiting_clients) {
                    None => String::from(""),
                    Some(n) => n.to_string(),
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
            Column::new("Agent Name"),
            Column::new("Role"),
            Column::new("Captured").justify(Justify::Right),
            Column::new("Commit").justify(Justify::Right),
            Column::new("Last Appended").justify(Justify::Right),
            Column::new("Append Q Len").justify(Justify::Right),
            Column::new("Clients Waiting").justify(Justify::Right),
        ],
        rows,
        TableStyle::default(),
    );
    table.render(&mut FmtWriteStdOut::stdout()).unwrap();
}
