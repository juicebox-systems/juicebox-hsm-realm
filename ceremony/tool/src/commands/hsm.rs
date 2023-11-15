use clap::{self, Subcommand, ValueEnum};

use crate::{join_path, Context, Error, Process};

/// Manage the core aspects of the HSM.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new Security World and enroll the HSM into it.
    ///
    /// The HSM must be in initialization mode. This erases the HSM and
    /// writes to a single ACS smartcard.
    CreateWorld,

    /// Reinitialize the HSM state, generating a new module key.
    ///
    /// The HSM must be in initialization mode.
    ///
    // TODO: what does this clear vs not clear
    Erase,

    /// Print status information about the hardserver and the HSM.
    ///
    /// The hardserver is a host daemon that manages communication with the
    /// HSM.
    Info,

    /// Enroll the HSM into an existing Security World.
    ///
    /// The HSM must be in initialization mode. This erases the HSM and
    /// requires the ACS smartcard.
    JoinWorld,

    /// Restart the HSM, optionally switching to a different mode.
    ///
    /// Note: The switch and jumpers on the HSM may be configured to restrict
    /// changing the mode in software.
    Restart {
        /// HSM boot mode.
        #[arg(long, default_value_t, value_enum)]
        mode: Mode,
    },

    /// Print information about the HSM's current Security World.
    WorldInfo,
}

/// HSM boot mode.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum Mode {
    /// Used to create or join an existing Security World.
    ///
    /// This is also called "pre-initialization" mode.
    Initialization,

    /// Used to upgrade firmware.
    ///
    /// This is also called "pre-maintenance" mode.
    Maintenance,

    /// Used for normal functionality.
    #[default]
    Operational,
}

pub fn run(command: &Command, context: &Context) -> Result<(), Error> {
    match command {
        Command::CreateWorld => context.exec(Process::new(
            &join_path(&context.paths.nfast_bin, "new-world"),
            &[
                "--initialize",
                "--no-remoteshare-cert",
                "--no-recovery",
                "--acs-quorum",
                "1/1",
            ],
        )),

        Command::Erase => context.exec(Process::new(
            &join_path(&context.paths.nfast_bin, "initunit"),
            &["--strong-kml"],
        )),

        Command::Info => context.exec(Process::new(
            &join_path(&context.paths.nfast_bin, "enquiry"),
            &[],
        )),

        Command::JoinWorld => context.exec(Process::new(
            &join_path(&context.paths.nfast_bin, "new-world"),
            &["--program", "--no-remoteshare-cert"],
        )),

        Command::Restart { mode } => context.exec(Process::new(
            &join_path(&context.paths.nfast_bin, "nopclearfail"),
            &[
                "--all",
                match mode {
                    Mode::Initialization => "--initialization",
                    Mode::Maintenance => "--maintenance",
                    Mode::Operational => "--operational",
                },
                "--wait",
            ],
        )),

        Command::WorldInfo => context.exec(Process::new(
            &join_path(&context.paths.nfast_bin, "nfkminfo"),
            &[],
        )),
    }
}
