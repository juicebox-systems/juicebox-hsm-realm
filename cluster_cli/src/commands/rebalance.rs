use anyhow::anyhow;

use cluster_api::{RebalanceRequest, RebalanceSuccess};
use jburl::Url;
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc;
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
    if full {
        loop {
            let res = rpc::send(agent_client, &url, RebalanceRequest {}).await??;
            print(&res);
            if res == RebalanceSuccess::AlreadyBalanced {
                break;
            }
        }
    } else {
        let res = rpc::send(agent_client, &url, RebalanceRequest {}).await??;
        print(&res);
    }
    Ok(())
}

fn print(res: &RebalanceSuccess) {
    match res {
        RebalanceSuccess::AlreadyBalanced => {
            println!("Already balanced.");
        }
        RebalanceSuccess::Rebalanced(r) => println!(
            "Moved leadership for {:?} in realm {:?} from {:?} to {:?}.",
            r.group, r.realm, r.from, r.to
        ),
    }
}
