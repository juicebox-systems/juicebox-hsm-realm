use clap::{self, Subcommand};

use crate::{Context, Error, Process};

/// Manage the host computer.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Shut down the host computer gracefully.
    #[clap(alias = "shut-down")]
    Shutdown,
}

pub fn run(command: &Command, context: &Context) -> Result<(), Error> {
    match command {
        Command::Shutdown => context.exec(Process::new("systemctl", &["poweroff"])),
    }
}
