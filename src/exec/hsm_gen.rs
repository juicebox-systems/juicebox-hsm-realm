//! Creates HSMs and their agents.
//!
//! This module exists in part to encapsulate the secret shared between the HSMs.

use futures::future::join_all;
use juicebox_sdk_networking::{
    reqwest::{self, ClientOptions},
    rpc,
};
use juicebox_sdk_process_group::ProcessGroup;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt::{Display, Write};
use std::iter;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use url::Url;

use super::PortIssuer;
use crate::realm::store::bigtable;
use agent_api::{AgentService, StatusRequest};
use hsmcore::hsm::types::PublicKey;

type AgentClient = reqwest::Client<AgentService>;

#[derive(Debug)]
pub struct Entrust(pub bool);

pub struct HsmGenerator {
    secret: String,
    port: PortIssuer,
    entrust: Entrust,
}

impl HsmGenerator {
    pub fn new(entrust: Entrust, ports: impl Into<PortIssuer>) -> HsmGenerator {
        let buf = if entrust.0 {
            "(this is not used)".to_string()
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
            port: ports.into(),
            entrust,
        }
    }

    // Returns the URL(s) to the agents along with the communication public key.
    pub async fn create_hsms(
        &mut self,
        mut count: usize,
        metrics: MetricsParticipants,
        process_group: &mut ProcessGroup,
        bigtable: &bigtable::Args,
        hsm_dir: Option<PathBuf>,
    ) -> (Vec<Url>, PublicKey) {
        let mode = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };

        let mut agent_urls = Vec::with_capacity(count);
        let mut next_is_leader = true;

        if self.entrust.0 {
            let agent_port = self.port.next();
            let agent_address = SocketAddr::from(([127, 0, 0, 1], agent_port)).to_string();
            let agent_url = Url::parse(&format!("http://{agent_address}")).unwrap();
            let mut cmd = Command::new(format!("target/{mode}/entrust_agent"));
            if metrics.report_metrics(next_is_leader) {
                cmd.arg("--metrics").arg("1000");
            };
            next_is_leader = false;
            cmd.arg("--listen").arg(agent_address);
            cmd.arg("--image").arg(format!(
                "target/powerpc-unknown-linux-gnu/{mode}/entrust-hsm.sar",
            ));
            cmd.arg("--userdata").arg(format!(
                "target/powerpc-unknown-linux-gnu/{mode}/userdata.sar"
            ));
            bigtable.add_to_cmd(&mut cmd);
            process_group.spawn(&mut cmd);
            agent_urls.push(agent_url);
            count -= 1;
        }

        iter::repeat_with(|| {
            let agent_port = self.port.next();
            let agent_address = SocketAddr::from(([127, 0, 0, 1], agent_port)).to_string();
            let agent_url = Url::parse(&format!("http://{agent_address}")).unwrap();
            let mut cmd = Command::new(format!("target/{mode}/software_agent"));
            cmd.arg("--key")
                .arg(&self.secret)
                .arg("--listen")
                .arg(agent_address);
            if metrics.report_metrics(next_is_leader) {
                cmd.arg("--metrics").arg("1000");
            }
            if let Some(d) = &hsm_dir {
                cmd.arg("--state-dir").arg(d.as_os_str());
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
    async fn wait_for_agents(&self, agents: &[Url]) -> PublicKey {
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
#[derive(Clone, Copy, Debug)]
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
