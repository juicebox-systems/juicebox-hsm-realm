use anyhow::{anyhow, Context};

use super::super::cluster::ClusterInfo;
use cluster_api::TransferRequest;
use cluster_core::{plan_transfers, plan_transfers_range};
use hsm_api::{GroupId, OwnedRange, RecordId};
use jburl::Url;
use juicebox_networking::rpc;
use juicebox_sdk::reqwest::Client;
use juicebox_sdk::RealmId;

pub async fn transfer(
    cluster: &ClusterInfo,
    agents_client: &Client,
    cluster_url: &Option<Url>,
    realm: RealmId,
    destination: GroupId,
    start: RecordId,
    end: RecordId,
) -> anyhow::Result<()> {
    let dest_leaders: Vec<_> = cluster
        .hsm_statuses()
        .filter_map(|(sr, _)| sr.realm.as_ref())
        .flat_map(|rs| {
            rs.groups
                .iter()
                .filter(|g| g.id == destination && g.leader.is_some())
        })
        .collect();
    if dest_leaders.is_empty() {
        return Err(anyhow!(
            "couldn't find a leader for the destination group {destination}"
        ));
    } else if dest_leaders.len() > 1 {
        return Err(anyhow!(
            "destination group {destination} has {} leaders",
            dest_leaders.len()
        ));
    }
    let dest_leader = dest_leaders
        .first()
        .and_then(|gs| gs.leader.as_ref())
        .expect("gs only contains items with Some(leader)");

    let target_range = OwnedRange { start, end };
    // They key range that we need to know the ownership of in order to plan the
    // transfer.
    let owners_range = plan_transfers_range(&dest_leader.owned_range, &target_range);
    let owners = match cluster_core::range_owners(
        cluster.hsm_statuses().map(|(s, _url)| s),
        realm,
        &owners_range,
    ) {
        Some(owners) => owners,
        None => {
            return Err(anyhow!(
                "failed to determine current owners of the range: {owners_range}"
            ))
        }
    };
    let transfers = plan_transfers(
        destination,
        dest_leader.owned_range.clone(),
        &owners,
        &target_range,
    )?;
    let url = match cluster_url {
        Some(url) => url,
        None => {
            if cluster.managers.is_empty() {
                return Err(anyhow!("No cluster managers in service discovery, and no explicit cluster manager URL set."));
            }
            &cluster.managers[0]
        }
    };
    if transfers.is_empty() {
        println!("nothing to do!");
        return Ok(());
    }
    for t in transfers {
        println!(
            "Transferring range {} in realm {realm:?} from group {:?} to {:?}",
            t.range, t.source, t.destination
        );

        let req = TransferRequest {
            realm,
            source: t.source,
            destination: t.destination,
            range: t.range,
        };

        rpc::send(agents_client, url, req)
            .await
            .context("error while asking cluster manager to perform ownership transfer")??;
    }
    println!("Ownership transfers completed successfully");
    Ok(())
}
