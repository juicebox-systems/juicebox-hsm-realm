use clap::{self, Subcommand};

use crate::{join_path, Context, Error, Paths, Process};

/// Manage HSM firmware.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print information about an HSM firmware file.
    FileInfo {
        /// A binary NFF file for this particular HSM model.
        #[clap(default_value_t = Paths::get().firmware_file.clone())]
        file: String,
    },

    /// Update the firmware on the HSM.
    ///
    /// The HSM must be in maintenance mode.
    Write {
        /// A binary NFF file for this particular HSM model.
        #[clap(default_value_t = Paths::get().firmware_file.clone())]
        file: String,
    },
}

pub fn run(command: &Command, context: &Context) -> Result<(), Error> {
    match command {
        Command::FileInfo { file } => {
            context.print_file_digest(file)?;
            context.exec(Process::new(
                &join_path(&context.paths.nfast_bin, "loadrom"),
                &["--view", file.as_str()],
            ))
        }

        Command::Write { file } => {
            context.print_file_digest(file)?;
            context.exec(Process::new(
                &join_path(&context.paths.nfast_bin, "loadrom"),
                &[file.as_str()],
            ))
        }
    }
}
