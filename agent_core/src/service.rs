use async_trait::async_trait;
use clap::{Args, Parser};
use http::Uri;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::info;

use crate::hsm::{HsmClient, Transport};
use crate::Agent;
use google::{auth, GrpcConnectionOptions};
use observability::{logging, metrics};
use service_core::clap_parsers::{parse_duration, parse_listen};
use service_core::panic;
use service_core::term::install_termination_handler;

#[derive(Debug, Parser)]
#[command(version)]
pub struct AgentArgs<SA: Args + Debug> {
    #[command(flatten)]
    bigtable: store::BigtableArgs,

    /// The name of the GCP project to use for pub/sub.
    /// Defaults to the bigtable-project setting.
    #[arg(long = "pubsub-project")]
    pubsub_project: Option<String>,

    /// The url to the pubsub emulator [default uses GCP endpoints].
    #[arg(long = "pubsub-url")]
    pub pubsub_url: Option<Uri>,

    /// The pub-sub gRPC request timeout setting.
    #[arg(long="pubsub-timeout",
            value_parser=parse_duration,
            default_value=format!("{:?}", GrpcConnectionOptions::default().timeout))]
    pubsub_timeout: Duration,

    /// The pub-sub gRPC connection timeout setting.
    #[arg(long="pubsub-connect-timeout",
            value_parser=parse_duration,
            default_value=format!("{:?}", GrpcConnectionOptions::default().connect_timeout))]
    pubsub_connect_timeout: Duration,

    /// The pub-sub gRPC http keep-alive interval setting.
    ///
    /// Interval between sending http2 keep-alive ping messages.
    #[arg(long="pubsub-http-keepalive-interval",
            value_parser=parse_duration,
            default_value=format!("{:?}", GrpcConnectionOptions::default().http2_keepalive_interval))]
    pubsub_http2_keepalive_interval: Duration,

    /// The pub-sub gRPC http2 Keep-alive timeout setting.
    ///
    /// The timeout duration waiting for a http2 keep-alive ping response.
    #[arg(long = "pubsub-http-keepalive-timeout",
        value_parser=parse_duration,
        default_value=format!("{:?}", GrpcConnectionOptions::default().http2_keepalive_timeout))]
    pub pubsub_http2_keepalive_timeout: Duration,

    /// The pub-sub gRPC http2 Keep-alive while idle setting.
    ///
    /// If true http2 keep alive messages will continue to be sent when the connection would otherwise be idle
    #[arg(long = "pubsub-http-keepalive-while-idle",
        default_value_t=GrpcConnectionOptions::default().http2_keepalive_while_idle)]
    pub pubsub_http2_keepalive_while_idle: bool,

    /// The maximum size of the agent's LRU Merkle tree cache, in number of
    /// nodes.
    #[arg(
        long = "merkle-cache-size",
        value_name = "NODES",
        default_value_t = 25_000
    )]
    pub merkle_cache_nodes_limit: usize,

    /// The IP/port to listen on.
    #[arg(
        short,
        long,
        default_value_t = SocketAddr::from(([127,0,0,1], 8082)),
        value_parser=parse_listen,
    )]
    listen: SocketAddr,

    /// Name of the agent in logging [default: agent{listen}].
    #[arg(short, long)]
    name: Option<String>,

    // Args for a specific type of agent service.
    #[command(flatten)]
    pub service: SA,
}

impl<SA: Args + Debug> AgentArgs<SA> {
    pub fn name(&self) -> String {
        match &self.name {
            Some(n) => n.clone(),
            None => format!("agent{}", self.listen),
        }
    }
}

#[async_trait]
pub trait HsmTransportConstructor<SA, T>
where
    SA: Args + Debug,
    T: Transport,
{
    async fn construct(&mut self, args: &AgentArgs<SA>, metrics: &metrics::Client) -> T;
}

pub async fn main<SA, T>(
    service_name: &str,
    transport_constructor: &mut impl HsmTransportConstructor<SA, T>,
) -> JoinHandle<()>
where
    SA: Args + Debug,
    T: Transport + 'static,
{
    logging::configure(service_name);
    panic::set_abort_on_panic();
    let mut shutdown_tasks = install_termination_handler(Duration::from_secs(10));

    let args = AgentArgs::<SA>::parse();
    info!(?args, "Parsed command-line args");

    let metrics = metrics::Client::new(service_name);

    let auth_manager = if args.bigtable.needs_auth() || args.pubsub_url.is_none() {
        Some(
            auth::from_adc()
                .await
                .expect("failed to initialize Google Cloud auth"),
        )
    } else {
        None
    };

    let store = args
        .bigtable
        .connect_data(
            auth_manager.clone(),
            store::Options {
                metrics: metrics.clone(),
                merkle_cache_nodes_limit: Some(args.merkle_cache_nodes_limit),
            },
        )
        .await
        .expect("Unable to connect to Bigtable");

    let store_admin = args
        .bigtable
        .connect_admin(auth_manager.clone(), metrics.clone())
        .await
        .expect("Unable to connect to Bigtable admin");

    let transport = transport_constructor.construct(&args, &metrics).await;
    let name = args.name();
    let hsm_client = HsmClient::new(transport, name.clone(), metrics.clone());

    let pubsub_project = args.pubsub_project.unwrap_or(args.bigtable.project);
    let pubsub_options = GrpcConnectionOptions {
        timeout: args.pubsub_timeout,
        connect_timeout: args.pubsub_connect_timeout,
        http2_keepalive_interval: args.pubsub_http2_keepalive_interval,
        http2_keepalive_timeout: args.pubsub_http2_keepalive_timeout,
        http2_keepalive_while_idle: args.pubsub_http2_keepalive_while_idle,
    };
    let pubsub = Box::new(
        google_pubsub::Publisher::new(
            args.pubsub_url,
            pubsub_project,
            auth_manager,
            metrics.clone(),
            pubsub_options,
        )
        .await
        .unwrap(),
    );

    let agent = Agent::new(name, hsm_client, store, store_admin, pubsub, metrics);
    let agent_clone = agent.clone();
    shutdown_tasks.add(Box::pin(async move {
        agent_clone.shutdown().await;
    }));

    let (url, join_handle) = agent
        .listen(args.listen)
        .await
        .expect("failed to listen for connections");
    info!(url = %url, "Agent started");
    join_handle
}
