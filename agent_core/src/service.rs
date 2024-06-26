use clap::{Args, CommandFactory, FromArgMatches, Parser};
use http::Uri;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::info;

use crate::hsm::{HsmClient, Transport};
use crate::{Agent, AgentConfiguration};
use build_info::BuildInfo;
use google::{auth, GrpcConnectionOptions};
use observability::{logging, metrics};
use service_core::clap_parsers::{parse_duration, parse_listen};
use service_core::future_task::FutureTask;
use service_core::metrics::start_uptime_reporter;
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

    /// The maximum number of concurrent reads of "large" merkle paths.
    #[arg(long, default_value_t = 10)]
    pub merkle_large_read_permits: usize,

    /// The number of key prefixes in a merkle path read for it to be considered
    /// a large read.
    #[arg(long, default_value_t = 246)]
    pub merkle_large_read_limit: usize,

    /// The IP/port to listen on.
    #[arg(
        short,
        long,
        default_value_t = SocketAddr::from(([127,0,0,1], 8082)),
        value_parser=parse_listen,
    )]
    pub listen: SocketAddr,

    /// Name of the agent in logging [default: agent{listen}].
    #[arg(short, long)]
    pub name: Option<String>,

    /// Default rate limit to apply to tenants where there's no specific
    /// configuration found for them. In HTTP requests per second.
    #[arg(long, default_value_t = 10)]
    pub default_rate_limit: usize,

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

#[allow(async_fn_in_trait)]
pub trait HsmTransportConstructor<SA, T>
where
    SA: Args + Debug,
    T: Transport,
{
    async fn construct(
        &mut self,
        args: &AgentArgs<SA>,
        metrics: &metrics::Client,
        // returns the transport and a shutdown task
    ) -> (T, Option<FutureTask<()>>);
}

pub async fn main<SA, T>(
    service_name: &str,
    build_info: BuildInfo,
    transport_constructor: &mut impl HsmTransportConstructor<SA, T>,
) -> JoinHandle<()>
where
    SA: Args + Debug,
    T: Transport + 'static,
{
    logging::configure(service_name, build_info.clone());
    panic::set_abort_on_panic();
    let mut shutdown_tasks = install_termination_handler(Duration::from_secs(20));

    // This is the same logic as `AgentArgs::<SA>::parse()`, except this
    // injects the build info into the version string.
    let args = {
        let command = AgentArgs::<SA>::command().version(build_info.clap());
        match AgentArgs::<SA>::from_arg_matches_mut(&mut command.get_matches()) {
            Err(err) => err.format(&mut AgentArgs::<SA>::command()).exit(),
            Ok(args) => args,
        }
    };

    info!(?args, "Parsed command-line args");

    let metrics = metrics::Client::new(service_name, Some(&build_info));
    start_uptime_reporter(metrics.clone()).await;

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
                merkle_large_read_limit: args.merkle_large_read_limit,
                merkle_large_read_permits: args.merkle_large_read_permits,
            },
        )
        .await
        .expect("Unable to connect to Bigtable");

    let store_admin = args
        .bigtable
        .connect_admin(auth_manager.clone(), metrics.clone())
        .await
        .expect("Unable to connect to Bigtable admin");

    let (transport, transport_shutdown) = transport_constructor.construct(&args, &metrics).await;
    if let Some(shutdown_task) = transport_shutdown {
        shutdown_tasks.add(shutdown_task);
    }

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

    let agent = Agent::new(
        AgentConfiguration {
            name,
            build_info,
            store,
            store_admin,
            event_publisher: pubsub,
            metrics,
            default_rate_limiter_rate: args.default_rate_limit,
        },
        hsm_client,
    );
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
