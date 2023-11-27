use anyhow::anyhow;
use cluster_api::{RebalanceError, RebalanceRequest, RebalanceSuccess};
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
    if !full || !matches!(res, Ok(RebalanceSuccess::Rebalanced(_))) {
        return Ok(res.map(|_| ())?);
    }
    loop {
        let res = rpc::send(agent_client, &url, RebalanceRequest {}).await?;
        if matches!(res, Ok(RebalanceSuccess::AlreadyBalanced)) {
            println!("Finished rebalancing.");
            return Ok(());
        }
        print(&res);
        if !matches!(res, Ok(RebalanceSuccess::Rebalanced(_))) {
            return Ok(res.map(|_| ())?);
        }
    }
}

fn print(res: &Result<RebalanceSuccess, RebalanceError>) {
    match res {
        Ok(RebalanceSuccess::AlreadyBalanced) => {
            println!("Already balanced.");
        }
        Ok(RebalanceSuccess::Rebalanced(r)) => println!(
            "Moved leadership for {:?} in realm {:?} from {:?} to {:?}.",
            r.group, r.realm, r.from, r.to
        ),
        Err(_) => {
            // errors get printed by main()
        }
    }
}
