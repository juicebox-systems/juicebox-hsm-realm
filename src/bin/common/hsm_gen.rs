//! Creates HSMs and their agents.
//!
//! This module exists in part to encapsulate the secret shared between the HSMs.

use futures::future::join_all;
use http::Uri;
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::Url;
use std::fmt::Write;
use std::iter;
use std::net::SocketAddr;
use std::ops::RangeFrom;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;

use super::process_group::ProcessGroup;
use loam_mvp::http_client;
use loam_mvp::realm::agent::types::{AgentService, StatusRequest};

type AgentClient = http_client::Client<AgentService>;

pub struct Entrust(pub bool);

pub struct HsmGenerator {
    secret: String,
    port: RangeFrom<u16>,
    entrust: Entrust,
}

impl HsmGenerator {
    pub fn new(entrust: Entrust, start_port: u16) -> Self {
        let buf = if entrust.0 {
            "010203".to_string()
        } else {
            let mut v = vec![0; 32];
            OsRng.fill_bytes(&mut v);
            let mut buf = String::new();
            for byte in v {
                write!(buf, "{byte:02x}").unwrap();
            }
            buf
        };
        Self {
            secret: buf,
            port: start_port..,
            entrust,
        }
    }

    pub async fn create_hsms(
        &mut self,
        mut count: usize,
        metrics: Option<Metrics>,
        process_group: &mut ProcessGroup,
        bigtable: &Uri,
    ) -> Vec<Url> {
        let mut agent_urls = Vec::with_capacity(count);
        let mut add_metrics = Metrics::report_metrics(&metrics);
        if self.entrust.0 {
            let agent_port = self.port.next().unwrap();
            let agent_address = SocketAddr::from(([127, 0, 0, 1], agent_port)).to_string();
            let agent_url = Url::parse(&format!("http://{agent_address}")).unwrap();
            let mut cmd = Command::new(format!(
                "target/{}/entrust-agent",
                if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                }
            ));
            cmd.arg("--listen")
                .arg(agent_address)
                .arg("--bigtable")
                .arg(bigtable.to_string());

            if add_metrics.next().is_some() {
                cmd.arg("--metrics").arg("1000");
            };

            process_group.spawn(&mut cmd);
            agent_urls.push(agent_url);
            count -= 1;
        }
        iter::repeat_with(|| {
            let hsm_port = self.port.next().unwrap();
            let agent_port = self.port.next().unwrap();
            let hsm_address = SocketAddr::from(([127, 0, 0, 1], hsm_port));
            let hsm_url = Url::parse(&format!("http://{hsm_address}")).unwrap();
            process_group.spawn(
                Command::new(format!(
                    "target/{}/http_hsm",
                    if cfg!(debug_assertions) {
                        "debug"
                    } else {
                        "release"
                    }
                ))
                .arg("--listen")
                .arg(hsm_address.to_string())
                .arg("--key")
                .arg(&self.secret),
            );
            let agent_address = SocketAddr::from(([127, 0, 0, 1], agent_port)).to_string();
            let agent_url = Url::parse(&format!("http://{agent_address}")).unwrap();
            let mut cmd = Command::new(format!(
                "target/{}/agent",
                if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                }
            ));
            cmd.arg("--listen")
                .arg(agent_address)
                .arg("--bigtable")
                .arg(bigtable.to_string())
                .arg("--hsm")
                .arg(hsm_url.to_string());
            if add_metrics.next().is_some() {
                cmd.arg("--metrics").arg("1000");
            }
            process_group.spawn(&mut cmd);
            agent_url
        })
        .take(count)
        .for_each(|url| agent_urls.push(url));

        self.wait_for_agents(&agent_urls).await;
        agent_urls
    }

    async fn wait_for_agents(&self, agents: &[Url]) {
        // Wait for the agent to be up, which in turn waits for the HSM
        // to be up.
        //
        // TODO: we shouldn't wait here. Other code needs to handle
        // failures, since servers can go down at any later point.
        let waiters = agents.iter().map(|agent_url| async move {
            let agent_client = AgentClient::new();
            for attempt in 1.. {
                if let Ok(response) = agent_client.send(agent_url, StatusRequest {}).await {
                    if response.hsm.is_some() {
                        break;
                    }
                }
                if attempt >= 1000 {
                    panic!("Failed to connect to agent/HSM at {agent_url}");
                }
                sleep(Duration::from_millis(1)).await;
            }
            agent_url
        });
        join_all(waiters).await;
    }
}

#[allow(dead_code)] // the compiler doesn't seem to see the usage from hsm_bench
#[derive(Clone, Debug)]
pub enum Metrics {
    Leader,
    All,
}

impl Metrics {
    #[allow(dead_code)] // the compiler doesn't seem to see the usage from hsm_bench
    pub fn parse(arg: &str) -> Result<Metrics, String> {
        let arg = arg.trim().to_ascii_lowercase();
        match arg.as_str() {
            "leader" => Ok(Metrics::Leader),
            "all" => Ok(Metrics::All),
            _ => Err(format!("valid options are Leader, All")),
        }
    }

    fn report_metrics(m: &Option<Metrics>) -> Box<dyn Iterator<Item = ()>> {
        match m {
            None => Box::new(iter::empty()),
            Some(Metrics::Leader) => Box::new(iter::once(())),
            Some(Metrics::All) => Box::new(iter::repeat(())),
        }
    }
}
