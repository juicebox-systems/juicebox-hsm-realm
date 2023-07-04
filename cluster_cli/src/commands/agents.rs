use anyhow::Context;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use reqwest::Url;
use std::fmt;
use std::time::Duration;

use hsmcore::hsm::types::{GroupStatus, HsmId, OwnedRange};
use juicebox_hsm::realm::agent::types::{AgentService, StatusRequest, StatusResponse};
use juicebox_hsm::realm::store::bigtable::{ServiceKind, StoreClient};
use juicebox_sdk_networking::reqwest::Client;
use juicebox_sdk_networking::rpc::{self, RpcError};

pub async fn list_agents(c: &Client<AgentService>, store: &StoreClient) -> anyhow::Result<()> {
    let addresses: Vec<(Url, _)> = store
        .get_addresses(Some(ServiceKind::Agent))
        .await
        .context("failed to get agent addresses from Bigtable")?;

    println!("found {} agents in service discovery", addresses.len());
    if addresses.is_empty() {
        return Ok(());
    }
    let mut futures = addresses
        .iter()
        .map(|(url, _)| async move {
            let result = rpc::send(c, url, StatusRequest {}).await;
            (url, result)
        })
        .collect::<FuturesUnordered<_>>();

    println!();
    while let Some((url, result)) = futures.next().await {
        print_agent_status(url, result)
    }

    Ok(())
}

const TAB: &str = "    ";

fn print_agent_status(url: &Url, status: Result<StatusResponse, RpcError>) {
    println!("agent:");
    println!("{TAB}discovery URL: {url}");

    match status {
        Ok(StatusResponse { uptime, hsm }) => {
            println!("{TAB}uptime: {}", Uptime(uptime));
            match hsm {
                Some(status) => {
                    println!("{TAB}HSM ID:  {}", status.id);
                    println!("{TAB}public key: {:?}", status.public_key);

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
    for hsm in &group.configuration {
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

struct Uptime(Duration);

impl fmt::Display for Uptime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.as_secs();
        let seconds = s % 60;
        let m = s / 60;
        let minutes = m % 60;
        let h = m / 60;
        let hours = h % 24;
        let days = h / 24;
        write!(f, "{days}d {hours}h {minutes}m {seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uptime_display() {
        assert_eq!(
            Uptime(Duration::from_millis(30999)).to_string(),
            "0d 0h 0m 30s"
        );
        assert_eq!(
            Uptime(Duration::from_secs(
                (2 * 24 * 60 * 60) + (3 * 60 * 60) + (4 * 60) + 5
            ))
            .to_string(),
            "2d 3h 4m 5s"
        );
    }
}
