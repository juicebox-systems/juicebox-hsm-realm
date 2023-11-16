use anyhow::anyhow;
use cluster_api::{RebalanceRequest, RebalanceResponse};
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc;
use reqwest::Url;
use store::{ServiceKind, StoreClient};

pub(crate) async fn rebalance(
    store: &StoreClient,
    agent_client: &Client,
    cluster_url: Option<Url>,
    full: bool,
) -> anyhow::Result<()> {
    let url = match cluster_url {
        Some(url) => url,
        None => {
            let managers: Vec<(Url, _)> = store
                .get_addresses(Some(ServiceKind::ClusterManager))
                .await?;
            if managers.is_empty() {
                return Err(anyhow!("No cluster managers in service discovery, and no explicit cluster manager URL set."));
            }
            managers[0].0.clone()
        }
    };

    let res = rpc::send(agent_client, &url, RebalanceRequest {}).await?;
    print(&res);
    if !full || !matches!(res, RebalanceResponse::Rebalanced(_)) {
        return Ok(());
    }
    loop {
        let res = rpc::send(agent_client, &url, RebalanceRequest {}).await?;
        if matches!(res, RebalanceResponse::AlreadyBalanced) {
            println!("Finished rebalancing.");
            return Ok(());
        }
        print(&res);
        if !matches!(res, RebalanceResponse::Rebalanced(_)) {
            return Ok(());
        }
    }
}

fn print(res: &RebalanceResponse) {
    match res {
        RebalanceResponse::AlreadyBalanced => {
            println!("Already balanced.");
        }
        RebalanceResponse::Rebalanced(r) => println!(
            "Moved leadership for {:?} in realm {:?} from {:?} to {:?}.",
            r.group, r.realm, r.from, r.to
        ),
        RebalanceResponse::StepDownFailed => {
            println!("Leadership stepdown failed.");
        }
        RebalanceResponse::LeadershipTransferRolledBack => {
            println!("Failed to move leadership, it was rolled back.");
        }
        RebalanceResponse::LeadershipTransferFailed => {
            println!("Failed to move leadership.");
        }
        RebalanceResponse::Busy {
            realm: _realm,
            group,
        } => {
            println!(
                "The group to move is busy doing some other management operation. Group {group:?}."
            );
        }
        RebalanceResponse::NoStore => {
            println!("Error accessing data store.");
        }
        RebalanceResponse::RpcError(r) => {
            println!("There was an RPC error: {:?}.", r);
        }
    }
}
