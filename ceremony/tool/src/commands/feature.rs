use clap::{self, Subcommand};

use crate::{join_path, Context, Error, Process};

/// Manage optional HSM capabilities.
///
/// Features can be enabled with a certificate from Entrust. This tool supports
/// enabling features using certificates in plain files (but certificates can
/// also be delivered on smartcards). Most features are static: once enabled
/// they cannot be disabled, even by erasing the HSM.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Enable an HSM feature.
    ///
    /// WARNING: Most features are static: once enabled they cannot be
    /// disabled, even by erasing the HSM.
    Activate {
        /// An ASCII certificate file signed from Entrust for this particular
        /// HSM.
        #[clap(value_name = "FILE")]
        certificate_file: String,
    },

    /// Print which features have been activated on this HSM.
    Info,
}

pub fn run(command: &Command, context: &Context) -> Result<(), Error> {
    match command {
        Command::Activate { certificate_file } => context.exec(Process::new(
            &join_path(&context.paths.nfast_bin, "fet"),
            &[
                "--cert",
                context.check_file_readable(certificate_file)?,
                "--reset-module",
            ],
        )),

        Command::Info => context.exec(Process::new(
            &join_path(&context.paths.nfast_bin, "fet"),
            &["--show-only"],
        )),
    }
}
