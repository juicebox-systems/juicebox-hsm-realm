//! Creates HSMs and their agents.
//!
//! This module exists in part to encapsulate the secret shared between the HSMs.

use futures::future::join_all;
use loam_mvp::realm::store::bigtable::BigTableArgs;
use loam_sdk_networking::rpc;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt::{Display, Write};
use std::iter;
use std::net::SocketAddr;
use std::ops::RangeFrom;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use url::Url;

use loam_mvp::http_client::{self, ClientOptions};
use loam_mvp::process_group::ProcessGroup;
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

    // Returns the URL(s) to the agents along with the communication public key.
    pub async fn create_hsms(
        &mut self,
        mut count: usize,
        metrics: MetricsParticipants,
        process_group: &mut ProcessGroup,
        bigtable: &BigTableArgs,
        hsm_dir: Option<PathBuf>,
    ) -> (Vec<Url>, Vec<u8>) {
        let mut agent_urls = Vec::with_capacity(count);
        let mut next_is_leader = true;
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
            if metrics.report_metrics(next_is_leader) {
                cmd.arg("--metrics").arg("1000");
            };
            next_is_leader = false;
            cmd.arg("--listen").arg(agent_address);
            bigtable.add_to_cmd(&mut cmd);
            process_group.spawn(&mut cmd);
            agent_urls.push(agent_url);
            count -= 1;
        }
        iter::repeat_with(|| {
            let hsm_port = self.port.next().unwrap();
            let agent_port = self.port.next().unwrap();
            let hsm_address = SocketAddr::from(([127, 0, 0, 1], hsm_port));
            let hsm_url = Url::parse(&format!("http://{hsm_address}")).unwrap();
            let mut cmd = Command::new(format!(
                "target/{}/http_hsm",
                if cfg!(debug_assertions) {
                    "debug"
                } else {
                    "release"
                }
            ));
            cmd.arg("--listen")
                .arg(hsm_address.to_string())
                .arg("--key")
                .arg(&self.secret);
            if let Some(d) = &hsm_dir {
                cmd.arg("--state-dir").arg(d.as_os_str());
            }
            process_group.spawn(&mut cmd);

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
                .arg("--hsm")
                .arg(hsm_url.to_string());
            if metrics.report_metrics(next_is_leader) {
                cmd.arg("--metrics").arg("1000");
            }
            next_is_leader = false;
            bigtable.add_to_cmd(&mut cmd);
            process_group.spawn(&mut cmd);
            agent_url
        })
        .take(count)
        .for_each(|url| agent_urls.push(url));

        let public_key = self.wait_for_agents(&agent_urls).await;
        (agent_urls, public_key)
    }

    // Returns the realm public key.
    async fn wait_for_agents(&self, agents: &[Url]) -> Vec<u8> {
        // Wait for the agent to be up, which in turn waits for the HSM
        // to be up.
        //
        // TODO: we shouldn't wait here. Other code needs to handle
        // failures, since servers can go down at any later point.
        let waiters = agents.iter().map(|agent_url| async move {
            let agent_client = AgentClient::new(ClientOptions::default());
            for attempt in 1.. {
                if let Ok(response) = rpc::send(&agent_client, agent_url, StatusRequest {}).await {
                    if let Some(hsm) = response.hsm {
                        return hsm.public_key;
                    }
                }
                if attempt >= 1000 {
                    panic!("Failed to connect to agent/HSM at {agent_url}");
                }
                sleep(Duration::from_millis(1)).await;
            }
            unreachable!()
        });
        join_all(waiters).await.pop().unwrap()
    }
}

#[allow(dead_code)] // the compiler doesn't seem to see the usage from hsm_bench
#[derive(Clone, Debug)]
pub enum MetricsParticipants {
    None,
    Leader,
    All,
}

impl Display for MetricsParticipants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetricsParticipants::None => f.write_str("None"),
            MetricsParticipants::Leader => f.write_str("Leader"),
            MetricsParticipants::All => f.write_str("All"),
        }
    }
}

impl MetricsParticipants {
    #[allow(dead_code)] // the compiler doesn't seem to see the usage from hsm_bench
    pub fn parse(arg: &str) -> Result<MetricsParticipants, String> {
        let arg = arg.trim().to_ascii_lowercase();
        match arg.as_str() {
            "leader" => Ok(MetricsParticipants::Leader),
            "all" => Ok(MetricsParticipants::All),
            "none" => Ok(MetricsParticipants::None),
            _ => Err(String::from("valid options are Leader, All")),
        }
    }

    fn report_metrics(&self, is_leader: bool) -> bool {
        match &self {
            MetricsParticipants::None => false,
            MetricsParticipants::Leader => is_leader,
            MetricsParticipants::All => true,
        }
    }
}
