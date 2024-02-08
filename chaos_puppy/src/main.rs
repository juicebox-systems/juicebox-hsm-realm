use anyhow::Context;
use clap::Parser;
use rand::seq::SliceRandom;
use rand_core::OsRng;
use std::collections::HashMap;
use std::process::ExitCode;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, warn, Level};

use google::auth;
use juicebox_networking::reqwest::{Client, ClientOptions};
use observability::{logging, metrics};
use service_core::clap_parsers::parse_duration;

mod actions;

// A tool to cause chaos in a cluster.
#[derive(Parser)]
#[command(version = build_info::clap!())]
struct Args {
    #[command(flatten)]
    bigtable: store::BigtableArgs,

    /// How often to trigger some chaos
    #[arg(long, default_value="1m", value_parser=parse_duration)]
    interval: Duration,

    /// How many times to trigger chaos, default is infinite.
    #[arg(long)]
    count: Option<usize>,
}

#[tokio::main]
async fn main() -> ExitCode {
    logging::configure_with_options(logging::Options {
        process_name: String::from("chaos"),
        default_log_level: Level::INFO,
        ..logging::Options::default()
    });

    let args = Args::parse();
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:?}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
    let metrics = metrics::Client::new("chaos");

    let auth_manager = auth::from_adc()
        .await
        .context("failed to initialize Google Cloud auth")?;

    info!(project=?args.bigtable.project, instance=?args.bigtable.instance, "connecting to Bigtable instance");
    let store = args
        .bigtable
        .connect_data(
            Some(auth_manager),
            store::Options {
                metrics,
                ..store::Options::default()
            },
        )
        .await
        .context("unable to connect to Bigtable")?;

    let client = Client::new(ClientOptions {
        timeout: Duration::from_secs(10),
        ..ClientOptions::default()
    });
    let actions = actions::actions();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut total_count = 0;
    loop {
        let puppy = actions.choose(&mut OsRng).unwrap();
        let name = format!("{puppy:?}");
        *counts.entry(name.clone()).or_default() += 1;
        info!(?name, "running chaos action");
        match puppy.run(&store, &client).await {
            Ok(_) => {
                debug!(?name, "chaos action completed with success");
            }
            Err(err) => warn!(?err, "error during chaos action"),
        }
        info!(?counts, "action counts");
        total_count += 1;
        if args.count.is_some_and(|c| total_count >= c) {
            info!(?total_count, "stopping after specified count");
            return Ok(());
        }
        sleep(args.interval).await;
    }
}
