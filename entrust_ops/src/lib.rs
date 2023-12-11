use clap::{self, command, Parser};

pub mod commands;
mod digests;
mod errors;
mod paths;
mod system;

use digests::Sha256Sum;
pub use errors::Error;
use paths::join_path;
pub use paths::Paths;
use system::Process;

/// Tool to manage Entrust HSMs with safer and more convenient command
/// wrappers.
#[derive(Debug, Parser)]
#[clap(version = build_info::clap!())]
pub struct Args {
    #[clap(flatten)]
    pub common: CommonArgs,

    #[command(subcommand)]
    pub command: commands::Command,
}

/// Global command-line arguments (part of [`Args`]). Available in [`Context`].
#[derive(Debug, Parser)]
pub struct CommonArgs {
    /// Don't execute commands but display them unambiguously.
    #[arg(long, global(true))]
    pub dry_run: bool,
}

/// There is one `Context` per invocation of this program. Commands use this to
/// access global state and call methods that need global state.
///
// Note: the `digests` and `system` modules also add impls to Context.
pub struct Context {
    pub common_args: CommonArgs,
    pub paths: &'static Paths,
}
