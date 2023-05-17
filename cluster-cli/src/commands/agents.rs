use anyhow::Context;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use reqwest::Url;

use hsmcore::hsm::types::{GroupStatus, HsmId, OwnedRange};
use loam_mvp::http_client::Client;
use loam_mvp::realm::agent::types::{AgentService, StatusRequest, StatusResponse};
use loam_mvp::realm::store::bigtable::StoreClient;
use loam_sdk_networking::rpc::{self, RpcError};

pub async fn list_agents(c: &Client<AgentService>, store: &StoreClient) -> anyhow::Result<()> {
    let addresses: Vec<(HsmId, Url)> = store
        .get_addresses()
        .await
        .context("failed to get agent addresses from Bigtable")?;

    println!("found {} agents in service discovery", addresses.len());
    if addresses.is_empty() {
        return Ok(());
    }
    let mut futures = addresses
        .iter()
        .map(|(hsm_id, url)| async move {
            let result = rpc::send(c, url, StatusRequest {}).await;
            ((hsm_id, url), result)
        })
        .collect::<FuturesUnordered<_>>();

    println!();
    while let Some(((hsm_id, url), result)) = futures.next().await {
        print_agent_status(hsm_id, url, result)
    }

    Ok(())
}

const TAB: &str = "    ";

fn print_agent_status(hsm_id: &HsmId, url: &Url, status: Result<StatusResponse, RpcError>) {
    println!("agent:");
    println!("{TAB}discovery URL: {url}");
    println!("{TAB}discovery HSM ID: {hsm_id}");

    match status {
        Ok(StatusResponse { uptime, hsm }) => {
            println!("{TAB}uptime: {} s", uptime.as_secs());
            match hsm {
                Some(status) => {
                    println!(
                        "{TAB}reported HSM ID:  {} ({})",
                        status.id,
                        if &status.id == hsm_id {
                            "matches"
                        } else {
                            "differs"
                        }
                    );
                    println!("{TAB}public key: {}", hex::encode(status.public_key));

                    match status.realm {
                        Some(mut realm) => {
                            println!("{TAB}realm ID: {:?}", realm.id);

                            realm.groups.sort_unstable_by_key(|group| group.id);
                            for group in realm.groups {
                                print_group_status(&status.id, &group);
                            }
                        }

                        None => {
                            println!("{TAB}no realm");
                        }
                    }
                }

                None => {
                    println!("{TAB}no HSM found");
                }
            }
        }

        Err(e) => {
            println!("{TAB}error getting status: {e}");
        }
    }
    println!();
}

fn print_group_status(hsm_id: &HsmId, group: &GroupStatus) {
    println!("{TAB}group: {:?}", group.id);
    println!("{TAB}{TAB}role: {}", group.role);

    if let Some(leader) = &group.leader {
        println!("{TAB}{TAB}leader:");
        match leader.committed {
            Some(i) => {
                println!("{TAB}{TAB}{TAB}committed index: {i}")
            }
            None => {
                println!("{TAB}{TAB}{TAB}committed index: none")
            }
        }
        match &leader.owned_range {
            Some(OwnedRange { start, end }) => {
                println!("{TAB}{TAB}{TAB}owned range start: {start:?}");
                println!("{TAB}{TAB}{TAB}owned range end:   {end:?}");
            }
            None => {
                println!("{TAB}{TAB}{TAB}owned range: none");
            }
        }
    }

    println!("{TAB}{TAB}configuration:");
    for hsm in &group.configuration.0 {
        if hsm == hsm_id {
            println!("{TAB}{TAB}{TAB}- HSM ID: {hsm} (self)");
        } else {
            println!("{TAB}{TAB}{TAB}- HSM ID: {hsm}");
        }
    }

    match &group.captured {
        Some((index, entry_mac)) => {
            println!("{TAB}{TAB}captured index: {index}");
            println!("{TAB}{TAB}captured entry MAC: {entry_mac:?}");
        }
        None => {
            println!("{TAB}{TAB}captured: none");
        }
    }
}
