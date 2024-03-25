use anyhow::anyhow;
use std::iter;

use super::super::cluster::ClusterInfo;
use juicebox_sdk::RealmId;
use table::{Column, FmtWriteStdOut, Table, TableStyle};

pub async fn print(cluster: &ClusterInfo, realm: Option<RealmId>) -> anyhow::Result<()> {
    if let Some(r) = realm {
        if !cluster.realms.contains(&r) {
            return Err(anyhow!("realm {r:?} not found in cluster"));
        }
    }
    let mut leaders: Vec<_> = cluster
        .statuses
        .iter()
        .filter(|s| {
            s.0.hsm.as_ref().is_some_and(|h| {
                h.realm
                    .as_ref()
                    .is_some_and(|rs| realm.is_none() || Some(rs.id) == realm)
            })
        })
        .flat_map(|(s, _)| {
            let r = s.hsm.as_ref().unwrap().realm.as_ref().unwrap();
            r.groups
                .iter()
                .filter(|g| g.leader.as_ref().is_some_and(|l| l.owned_range.is_some()))
                .map(|g| (r.id, g.id, g.leader.as_ref().unwrap()))
        })
        .collect();

    leaders.sort_by(|a, b| {
        a.0.cmp(&b.0).then_with(|| {
            a.2.owned_range
                .as_ref()
                .unwrap()
                .start
                .cmp(&b.2.owned_range.as_ref().unwrap().start)
        })
    });

    let mut realm: Option<RealmId> = None;
    let mut realms = Vec::new();
    let mut realm_ids = Vec::new();
    let mut current = Vec::new();

    for (r, g, ls) in leaders {
        if Some(r) != realm {
            realm = Some(r);
            if !current.is_empty() {
                realms.push(current);
            }
            realm_ids.push(r);
            current = Vec::new();
        }
        current.push((g, ls));
    }
    realms.push(current);

    for (id, partitions) in iter::zip(realm_ids, realms) {
        println!("Realm: {id:?}");
        let rows = partitions.into_iter().map(|(g, ls)| {
            let p = ls.owned_range.as_ref().unwrap();
            [
                g.to_string(),
                p.start.to_string(),
                p.end.to_string(),
                match &ls.committed {
                    None => String::from("None"),
                    Some(i) => i.to_string(),
                },
            ]
        });
        let table = Table::new(
            [
                Column::new("Group ID"),
                Column::new("Start"),
                Column::new("End"),
                Column::new("Commit Index"),
            ],
            rows,
            TableStyle::default(),
        );
        table.render(&mut FmtWriteStdOut::stdout()).unwrap();
    }
    Ok(())
}
