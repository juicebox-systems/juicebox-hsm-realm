use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::fmt;
use std::time::Duration;

use agent_api::{StatusRequest, StatusResponse};
use cluster_core::workload::{GroupWorkload, HsmWorkload};
use hsm_api::{GroupStatus, HsmId, OwnedRange, Transferring};
use jburl::Url;
use juicebox_networking::reqwest::Client;
use juicebox_networking::rpc::{self, RpcError};

use crate::cluster::ClusterInfo;

pub async fn list_agents(c: &Client, cluster: &ClusterInfo) -> anyhow::Result<()> {
    println!("found {} agents in service discovery", cluster.agents.len());
    if cluster.agents.is_empty() {
        return Ok(());
    }
    let mut futures = cluster
        .agents
        .iter()
        .map(|url| async move {
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
        Ok(StatusResponse { uptime, hsm, agent }) => {
            println!("{TAB}uptime: {}", Uptime(uptime));
            match hsm {
                Some(status) => {
                    let hsm_work = HsmWorkload::new(&status);
                    if let Some(wl) = hsm_work.as_ref() {
                        println!("{TAB}workload: {}", wl.work());
                    }
                    println!("{TAB}HSM ID: {}", status.id);
                    println!("{TAB}public key: {:?}", status.public_key);

                    match status.realm {
                        Some(mut realm) => {
                            println!("{TAB}realm ID: {:?}", realm.id);

                            realm.groups.sort_unstable_by_key(|group| group.id);
                            for group in realm.groups {
                                let group_workload = GroupWorkload::new(realm.id, &group);
                                print_group_status(&status.id, &group, &group_workload);
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
            if let Some(mut status) = agent {
                println!("{TAB}Agent status:");
                println!("{TAB}{TAB}name: {}", status.name);
                println!("{TAB}{TAB}build: {}", status.build_hash);
                status.groups.sort_unstable_by_key(|s| s.group);
                for group in status.groups {
                    println!("{TAB}{TAB}group: {}", group.group);
                    println!("{TAB}{TAB}{TAB}role:  {}", group.role);
                    if let Some(l) = group.leader {
                        println!(
                            "{TAB}{TAB}{TAB}{TAB}waiting clients:  {}",
                            l.num_waiting_clients
                        );
                        println!(
                            "{TAB}{TAB}{TAB}{TAB}append queue len: {}",
                            l.append_queue_len
                        );
                        print!("{TAB}{TAB}{TAB}{TAB}last appended: ");
                        match l.last_appended {
                            None => println!("None"),
                            Some((idx, mac)) => println!("{} / {:?}", idx, mac),
                        }
                    }
                }
            }
        }

        Err(e) => {
            println!("{TAB}error getting status: {e}");
        }
    }
    println!();
}

fn print_group_status(hsm_id: &HsmId, group: &GroupStatus, work: &GroupWorkload) {
    println!("{TAB}group: {:?}", group.id);
    println!("{TAB}{TAB}role: {}", group.role);
    println!("{TAB}{TAB}workload: {}", work.work());
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
        match &leader.transferring {
            None => {
                println!("{TAB}{TAB}{TAB}transfer: none");
            }
            Some(Transferring::In(prepared)) => {
                let r = &prepared.range;
                println!("{TAB}{TAB}{TAB}prepared transfer:");
                println!("{TAB}{TAB}{TAB}{TAB}source: {:?}", prepared.source);
                println!("{TAB}{TAB}{TAB}{TAB}since log index: {:?}", prepared.at);
                println!("{TAB}{TAB}{TAB}{TAB}range start: {:?}", r.start);
                println!("{TAB}{TAB}{TAB}{TAB}range end:   {:?}", r.end);
            }

            Some(Transferring::Out(tout)) => {
                let p = &tout.partition;
                println!("{TAB}{TAB}{TAB}transferring out:");
                println!("{TAB}{TAB}{TAB}{TAB}destination:  {:?}", tout.destination);
                println!("{TAB}{TAB}{TAB}{TAB}at log index: {:?}", tout.at);
                println!("{TAB}{TAB}{TAB}{TAB}range start: {:?}", p.range.start);
                println!("{TAB}{TAB}{TAB}{TAB}range end:   {:?}", p.range.end);
                println!("{TAB}{TAB}{TAB}{TAB}root hash:   {:?}", p.root_hash);
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
