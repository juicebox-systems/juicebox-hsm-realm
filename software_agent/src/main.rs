use async_trait::async_trait;
use clap::Args;
use service_core::future_task::FutureTask;
use std::path::PathBuf;
use std::process::Command;
use tracing::info;
use url::Url;

use agent_core::service::{AgentArgs, HsmTransportConstructor};
use observability::metrics;
use software_hsm_client::HsmHttpClient;

/// A host agent that embeds an insecure software HSM.
#[derive(Debug, Args)]
struct SoftwareAgentArgs {
    /// Derive realm keys from this input (insecure).
    #[arg(short, long)]
    key: String,

    /// Directory to store the persistent state file in [default: a random temp dir]
    #[arg(short, long)]
    state_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let mut tf = TransportConstructor;
    let h = agent_core::service::main("software-agent", &mut tf).await;
    h.await.unwrap();
}

struct TransportConstructor;

#[async_trait]
impl HsmTransportConstructor<SoftwareAgentArgs, HsmHttpClient> for TransportConstructor {
    async fn construct(
        &mut self,
        args: &AgentArgs<SoftwareAgentArgs>,
        _metrics: &metrics::Client,
    ) -> (HsmHttpClient, Option<FutureTask<()>>) {
        // Start software_hsm process. If the env var isn't set we default to the
        // same directory as our executable.
        let exec_dir = match std::env::var("SOFTWARE_HSM_DIR") {
            Ok(v) => PathBuf::from(v),
            Err(_) => {
                let mut dir = std::env::current_exe().unwrap();
                dir.pop();
                dir
            }
        };
        info!(?exec_dir, "Starting Software HSM");
        let mut cmd = Command::new(exec_dir.join("software_hsm"));
        cmd.arg("--key").arg(&args.service.key);
        if let Some(d) = &args.service.state_dir {
            cmd.arg("--state-dir").arg(d);
        }
        if let Some(n) = &args.name {
            cmd.arg("--name").arg(n);
        }
        let mut l = args.listen;
        l.set_port(l.port() + 10000);
        cmd.arg("--listen").arg(l.to_string());

        let mut child = cmd.spawn().unwrap();
        let hsm_url: Url = format!("http://{}", l).parse().unwrap();
        info!(url = %hsm_url, dir=?args.service.state_dir, "HSM started");
        (
            HsmHttpClient::new(hsm_url),
            Some(Box::pin(async move {
                let _ = child.kill();
            })),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use expect_test::expect_file;

    #[test]
    fn test_usage() {
        expect_file!["../usage.txt"].assert_eq(
            &AgentArgs::<SoftwareAgentArgs>::command()
                .try_get_matches_from(["agent", "--help"])
                .unwrap_err()
                .to_string(),
        );
    }
}
