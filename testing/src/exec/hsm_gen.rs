//! Creates HSMs and their agents.
//!
//! This module exists in part to encapsulate the secret shared between the HSMs.

use futures::future::join_all;
use http::Uri;
use juicebox_networking::{
    reqwest::{self, ClientOptions},
    rpc,
};
use juicebox_process_group::ProcessGroup;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt::Write;
use std::iter;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;

use super::PortIssuer;
use agent_api::StatusRequest;
use hsm_api::PublicKey;
use jburl::Url;

type AgentClient = reqwest::Client;

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
        process_group: &mut ProcessGroup,
        path_to_target: PathBuf,
        bigtable: &store::BigtableArgs,
        pubsub_url: &Option<Uri>,
        hsm_dir: Option<PathBuf>,
    ) -> (Vec<Url>, PublicKey) {
        let mode = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };

        let mut agent_urls = Vec::with_capacity(count);

        if self.entrust.0 {
            let agent_port = self.port.next();
            let agent_address = SocketAddr::from(([127, 0, 0, 1], agent_port)).to_string();
            let agent_url = Url::parse(&format!("http://{agent_address}")).unwrap();
            let mut cmd = Command::new(
                path_to_target
                    .join("target")
                    .join(mode)
                    .join("entrust_agent"),
            );
            cmd.arg("--listen").arg(agent_address);
            cmd.arg("--image").arg(
                path_to_target
                    .join("target")
                    .join("powerpc-unknown-linux-gnu")
                    .join(mode)
                    .join("entrust_hsm.sar"),
            );
            if hsm_dir.is_none() {
                cmd.arg("--reinitialize");
            }
            cmd.arg("--userdata").arg(
                path_to_target
                    .join("target")
                    .join("powerpc-unknown-linux-gnu")
                    .join(mode)
                    .join("userdata.sar"),
            );
            bigtable.add_to_cmd(&mut cmd);
            if let Some(url) = pubsub_url {
                cmd.arg("--pubsub-url").arg(url.to_string());
            }
            process_group.spawn(&mut cmd);
            agent_urls.push(agent_url);
            count -= 1;
        }

        iter::repeat_with(|| {
            let agent_port = self.port.next();
            let agent_address = SocketAddr::from(([127, 0, 0, 1], agent_port)).to_string();
            let agent_url = Url::parse(&format!("http://{agent_address}")).unwrap();
            let mut cmd = Command::new(
                path_to_target
                    .join("target")
                    .join(mode)
                    .join("software_agent"),
            );
            cmd.arg("--key")
                .arg(&self.secret)
                .arg("--listen")
                .arg(agent_address)
                .arg("--default-rate-limit")
                .arg("1000");
            if let Some(d) = &hsm_dir {
                cmd.arg("--state-dir").arg(d.as_os_str());
            }
            bigtable.add_to_cmd(&mut cmd);
            if let Some(url) = &pubsub_url {
                cmd.arg("--pubsub-url").arg(url.to_string());
            }
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
                // The entrust agent can take a long time to start.
                if attempt >= 5000 {
                    panic!("Failed to connect to agent/HSM at {agent_url}");
                }
                sleep(Duration::from_millis(5)).await;
            }
            unreachable!()
        });
        join_all(waiters).await.pop().unwrap()
    }
}
