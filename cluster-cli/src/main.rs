use anyhow::Context;
use clap::{command, Parser, Subcommand};
use reqwest::Url;
use thiserror::Error;

use hsmcore::hsm::types::HsmId;
use loam_mvp::{
    google_auth,
    http_client::{Client, ClientOptions},
    realm::{
        agent::types::AgentService,
        store::bigtable::{BigTableArgs, StoreClient},
    },
};

mod status;
mod stepdown;

use status::status;
use stepdown::stepdown;

#[derive(Parser)]
#[command(about = "A CLI tool for interacting with the Cluster")]
struct Args {
    #[command(flatten)]
    bigtable: BigTableArgs,

    /// Url to the cluster manager.
    #[arg(short, long, default_value = "http://localhost:8079")]
    cluster: Url,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Ask the HSM to stepdown as leader for any groups that is leading.
    Stepdown { hsm: String },
    /// Show the current status of all the reams/groups it can discover.
    Status,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let c = Client::<AgentService>::new(ClientOptions::default());
    let auth_manager = if args.bigtable.needs_auth() {
        Some(
            google_auth::from_adc()
                .await
                .expect("failed to initialize Google Cloud auth"),
        )
    } else {
        None
    };

    let store = args
        .bigtable
        .connect_data(auth_manager.clone())
        .await
        .expect("Unable to connect to Bigtable");

    let result = match &args.command.unwrap_or(Commands::Status) {
        Commands::Stepdown { hsm } => match resolve_hsm_id(&store, hsm).await {
            Err(e) => {
                println!("{:?}", e);
                return;
            }
            Ok(id) => stepdown(&args.cluster, id).await,
        },
        Commands::Status => status(c, store).await,
    };
    if let Err(err) = result {
        println!("error: {:?}", err);
    }
}

async fn resolve_hsm_id(store: &StoreClient, id: &str) -> anyhow::Result<HsmId> {
    if id.len() == 32 {
        let h = hex::decode(id).context("decoding HSM Id.")?;
        Ok(HsmId(h.try_into().unwrap()))
    } else {
        let id = id.to_lowercase();
        let ids: Vec<_> = store
            .get_addresses()
            .await
            .context("RPC error to bigtable")?
            .into_iter()
            .filter(|(hsm_id, _url)| hsm_id.to_string().to_lowercase().starts_with(&id))
            .collect();
        match ids.len() {
            0 => Err(HsmIdError::NoMatch.into()),
            1 => Ok(ids[0].0),
            c => Err(HsmIdError::Ambiguous(c).into()),
        }
    }
}

#[derive(Error, Debug)]
enum HsmIdError {
    #[error("No HSM with that Id.")]
    NoMatch,
    #[error("Ambiguous Hsm id. There are {0} HSMs that start with that Id.")]
    Ambiguous(usize),
}