use anyhow::Context;
use clap::{command, Parser, Subcommand};
use reqwest::Url;
use std::process::ExitCode;
use std::time::Duration;
use thiserror::Error;
use tracing::{info, Level};

use agent_api::AgentService;
use cluster_core::discover_hsm_ids;
use google::auth;
use hsm_api::{GroupId, HsmId, OwnedRange, RecordId};
use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_networking::reqwest::{Client, ClientOptions};
use observability::{logging, metrics};
use secret_manager::new_google_secret_manager;
use store::{self, StoreClient};

mod commands;
mod statuses;

use statuses::get_hsm_statuses;

/// A CLI tool for interacting with the cluster.
#[derive(Parser)]
struct Args {
    #[command(flatten)]
    bigtable: store::Args,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print detailed information about every discoverable agent.
    ///
    /// See 'groups' for a higher-level view of the realms and groups in the
    /// cluster.
    Agents,

    /// Create an auth token for a test tenant.
    ///
    /// The token is printed to stdout.
    AuthToken {
        /// A tenant ID that must begin with "test-".
        ///
        /// The tenant's secret auth key must already exist in GCP Secret
        /// Manager.
        tenant: String,
        /// Any user ID.
        user: String,
        /// The ID of the realm that the token should be valid for.
        #[arg(value_parser = parse_realm_id)]
        realm: RealmId,
    },

    /// Print a configuration that uses the discoverable realm(s).
    ///
    /// The configuration is printed in a JSON format that the demo client
    /// accepts.
    Configuration {
        /// A URL to a load balancer that sends requests to all of the
        /// discoverable realms.
        ///
        /// The load balancer is not accessed, but its URL is included in the
        /// configuration.
        load_balancer: Url,
    },

    /// Subcommands that are not yet stable and may be dangerous.
    Experimental {
        #[command(subcommand)]
        command: ExperimentalCommand,
    },

    /// Print information about every discoverable realm and group.
    ///
    /// This does not include information about agents that are not
    /// participating in any groups. See 'agents' for lower-level information
    /// about agents.
    Groups,

    /// Request HSMs to irreversibly adopt an existing realm.
    ///
    /// At least one HSM that is already in the realm must be online for this
    /// to complete.
    JoinRealm {
        /// The ID of the realm to join.
        #[arg(long, value_parser = parse_realm_id)]
        realm: RealmId,

        /// URLs of agents whose HSMs will join the realm.
        #[arg(required = true)]
        agents: Vec<Url>,
    },

    /// Create a new group on a set of agents' HSMs.
    ///
    /// The new group will not have ownership of any user records. Use
    /// 'transfer' to assign it ownership.
    NewGroup {
        /// The ID of the realm in which to create the new group.
        #[arg(long, value_parser = parse_realm_id)]
        realm: RealmId,

        /// URLs of agents whose HSMs will form the new group.
        ///
        /// All of the HSMs should have already joined the realm.
        #[arg(required = true)]
        agents: Vec<Url>,
    },

    /// Create a new realm and group on a single agent's HSM.
    ///
    /// The new group will own all of the user record space. Use 'new-group'
    /// and 'transfer' to repartition across additional groups.
    NewRealm {
        /// URL of agent whose HSM will form the new realm and group.
        agent: Url,
    },

    /// Ask an HSM to step down as leader for any groups that it's leading.
    Stepdown {
        /// URL to a cluster manager, which will execute the request. By
        /// default it will find a cluster manager using service discovery.
        #[arg(short, long)]
        cluster: Option<Url>,

        /// A full HSM ID or an unambiguous prefix of an HSM ID.
        hsm: String,
    },

    /// Transfer ownership of user records from one group to another.
    ///
    /// Both groups must already exist and be part of the same realm.
    Transfer {
        /// Realm ID.
        #[arg(long, value_parser = parse_realm_id)]
        realm: RealmId,

        /// ID of group that currently owns the range to be transferred.
        ///
        /// The source group's current ownership must extend from exactly
        /// '--start' and/or up to exactly '--end'. In other words, this
        /// transfer cannot leave a gap in the source group's owned range.
        #[arg(long, value_parser = parse_group_id)]
        source: GroupId,

        /// ID of group that should be the new owner of the range.
        ///
        /// The destination group must currently own either nothing or an
        /// adjacent range.
        #[arg(long, value_parser = parse_group_id)]
        destination: GroupId,

        /// The first record ID in the range, in hex.
        ///
        /// Example:
        /// 0000000000000000000000000000000000000000000000000000000000000000
        #[arg(long, value_parser = parse_record_id)]
        start: RecordId,

        /// The last record ID in the range (inclusive), in hex.
        ///
        /// Example:
        /// 7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        #[arg(long, value_parser = parse_record_id)]
        end: RecordId,
    },
}

#[derive(Subcommand)]
enum ExperimentalCommand {
    /// Reconfigure any available agents/HSMs into a nominal and well-balanced
    /// realm.
    ///
    /// This is marked experimental because it does not currently handle all
    /// scenarios. It's included because it can still be a useful time-saving
    /// tool for development and testing purposes for scenarios it does
    /// support.
    Assimilate {
        /// The target number of HSMs per group (and also the number of groups
        /// each HSM is a member of).
        ///
        /// The number of HSMs available must be at least this large.
        #[arg(long, default_value_t = 5)]
        group_size: usize,

        /// If provided, the HSMs already in this realm, as well as HSMs not
        /// currently in any realm, are assimilated.
        ///
        /// Default: create a new realm if none are discoverable, use the one
        /// realm if exactly one is found, or fail if more than one realm is
        /// found.
        #[arg(long, value_parser = parse_realm_id)]
        realm: Option<RealmId>,
    },
}

impl Command {
    fn needs_secret_manager(&self) -> bool {
        matches!(self, Command::AuthToken { .. })
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    logging::configure_with_options(logging::Options {
        process_name: String::from("cluster-cli"),
        default_log_level: Level::ERROR,
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
    let metrics = metrics::Client::new("cluster_cli");

    let auth_manager = if args.bigtable.needs_auth() || args.command.needs_secret_manager() {
        Some(
            auth::from_adc()
                .await
                .context("failed to initialize Google Cloud auth")?,
        )
    } else {
        None
    };

    let secret_manager = if args.command.needs_secret_manager() {
        info!("connecting to Google Cloud Secret Manager");
        Some(
            new_google_secret_manager(
                &args.bigtable.project,
                auth_manager.clone().unwrap(),
                Duration::MAX,
            )
            .await
            .context("failed to load Google SecretManager secrets")?,
        )
    } else {
        None
    };

    let store = args
        .bigtable
        .connect_data(
            auth_manager,
            store::Options {
                metrics,
                ..store::Options::default()
            },
        )
        .await
        .context("unable to connect to Bigtable")?;

    let agents_client = Client::<AgentService>::new(ClientOptions::default());

    match args.command {
        Command::Agents => commands::agents::list_agents(&agents_client, &store).await,

        Command::AuthToken {
            tenant,
            user,
            realm,
        } => {
            commands::auth_token::mint_auth_token(&secret_manager.unwrap(), tenant, user, realm)
                .await
        }

        Command::Configuration { load_balancer } => {
            commands::configuration::print_sensible_configuration(
                &load_balancer,
                &agents_client,
                &store,
            )
            .await
        }

        Command::Experimental { command } => match command {
            ExperimentalCommand::Assimilate { realm, group_size } => {
                commands::assimilate::assimilate(realm, group_size, &agents_client, &store).await
            }
        },

        Command::Groups => commands::groups::status(&agents_client, &store).await,

        Command::JoinRealm { realm, agents } => {
            commands::join_realm::join_realm(realm, &agents, &agents_client, &store).await
        }

        Command::NewGroup { realm, agents } => {
            commands::new_group::new_group(realm, &agents, &agents_client).await
        }

        Command::NewRealm { agent } => commands::new_realm::new_realm(&agent, &agents_client).await,

        Command::Transfer {
            realm,
            source,
            destination,
            start,
            end,
        } => {
            commands::transfer::transfer(
                realm,
                source,
                destination,
                OwnedRange { start, end },
                &store,
            )
            .await
        }

        Command::Stepdown { cluster, hsm } => {
            let hsm = resolve_hsm_id(&store, &agents_client, &hsm).await?;
            commands::stepdown::stepdown(&store, &cluster, hsm).await
        }
    }
}

async fn resolve_hsm_id(
    store: &StoreClient,
    agent_client: &Client<AgentService>,
    id: &str,
) -> anyhow::Result<HsmId> {
    if id.len() == 32 {
        let h = hex::decode(id).context("error decoding HSM id")?;
        Ok(HsmId(h.try_into().unwrap()))
    } else {
        let id = id.to_lowercase();
        let ids: Vec<_> = discover_hsm_ids(store, agent_client)
            .await
            .context("RPC error to bigtable")?
            .filter(|(hsm_id, _url)| hsm_id.to_string().to_lowercase().starts_with(&id))
            .map(|(hsm_id, _url)| hsm_id)
            .collect();
        match ids.len() {
            0 => Err(HsmIdError::NoMatch.into()),
            1 => Ok(ids[0]),
            c => Err(HsmIdError::Ambiguous(c).into()),
        }
    }
}

#[derive(Error, Debug)]
enum HsmIdError {
    #[error("no HSM with that ID")]
    NoMatch,
    #[error("ambiguous HSM ID: {0} HSMs share that prefix")]
    Ambiguous(usize),
}

fn parse_realm_id(buf: &str) -> Result<RealmId, hex::FromHexError> {
    let id = hex::decode(buf)?;
    Ok(RealmId(
        id.try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?,
    ))
}

fn parse_group_id(buf: &str) -> Result<GroupId, hex::FromHexError> {
    let id = hex::decode(buf)?;
    Ok(GroupId(
        id.try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?,
    ))
}

fn parse_record_id(buf: &str) -> Result<RecordId, hex::FromHexError> {
    let id = hex::decode(buf)?;
    Ok(RecordId(
        id.try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use expect_test::expect_file;
    use std::fmt::Write;

    #[test]
    fn test_usage() {
        let mut actual = String::new();
        for cmd in [
            vec!["cluster", "--help"],
            vec!["cluster", "agents", "--help"],
            vec!["cluster", "auth-token", "--help"],
            vec!["cluster", "configuration", "--help"],
            vec!["cluster", "experimental", "--help"],
            vec!["cluster", "experimental", "assimilate", "--help"],
            vec!["cluster", "groups", "--help"],
            vec!["cluster", "join-realm", "--help"],
            vec!["cluster", "new-group", "--help"],
            vec!["cluster", "new-realm", "--help"],
            vec!["cluster", "stepdown", "--help"],
            vec!["cluster", "transfer", "--help"],
        ] {
            writeln!(actual, "## `{}`", cmd.join(" ")).unwrap();
            writeln!(actual).unwrap();
            writeln!(actual, "```").unwrap();
            writeln!(
                actual,
                "{}",
                Args::command().try_get_matches_from(cmd).unwrap_err()
            )
            .unwrap();
            writeln!(actual, "```").unwrap();
            writeln!(actual).unwrap();
        }
        expect_file!["../usage.md"].assert_eq(&actual);
    }
}
