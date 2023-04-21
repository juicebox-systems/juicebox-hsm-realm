use cli_table::{
    format::{Justify, Separator},
    print_stdout, Cell, Table,
};
use futures::{future::join_all, FutureExt};
use reqwest::Url;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use hsmcore::hsm::types::{GroupId, HsmId, LogIndex};
use loam_mvp::{
    http_client::Client,
    realm::{
        agent::types::{AgentService, StatusRequest},
        store::bigtable::StoreClient,
    },
};
use loam_sdk::RealmId;
use loam_sdk_networking::rpc::{self, RpcError};

pub async fn status(c: Client<AgentService>, store: StoreClient) -> Result<(), RpcError> {
    println!("Status");
    let addresses = store.get_addresses().await.map_err(|_| RpcError::Network)?;
    println!("{} Agents listed in service discovery", addresses.len());

    let s: Vec<_> =
        join_all(addresses.iter().map(|(hsm_id, url)| {
            rpc::send(&c, url, StatusRequest {}).map(move |r| (r, hsm_id, url))
        }))
        .await
        .into_iter()
        .filter_map(|(s, hsm_id, _)| s.ok().and_then(|s| s.hsm).filter(|s| s.id == *hsm_id))
        .collect();

    #[derive(Default)]
    struct GroupInfo {
        members: Vec<(HsmId, Option<LogIndex>)>,   //captured
        leader: Option<(HsmId, Option<LogIndex>)>, //commit
    }
    let mut realms: BTreeMap<RealmId, BTreeSet<GroupId>> = BTreeMap::new();
    let mut groups: BTreeMap<GroupId, GroupInfo> = BTreeMap::new();
    for sr in s {
        if let Some(r) = sr.realm {
            for g in r.groups {
                realms.entry(r.id).or_default().insert(g.id);
                let e = groups.entry(g.id).or_default();
                e.members
                    .push((sr.id, g.captured.map(|(index, _hmac)| index)));
                if g.leader.is_some() {
                    e.leader = Some((sr.id, g.leader.unwrap().committed));
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
                .map(|(hsm_id, captured)| {
                    vec![
                        hsm_id.to_string().cell(),
                        addresses.get(hsm_id).unwrap().to_string().cell(),
                        match captured {
                            None => "None".cell(),
                            Some(i) => i.to_string().cell(),
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
                .title(vec!["HSM", "Agent URL", "Captured", "Commit"])
                .color_choice(cli_table::ColorChoice::Never);
            assert!(print_stdout(table).is_ok());
        }
        println!();
    }
    Ok(())
}
