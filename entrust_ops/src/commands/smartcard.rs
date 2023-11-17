use clap::{self, Subcommand};

use crate::{join_path, Context, Error, Process};

/// Manage HSM smartcards (which can contain sensitive keys).
///
/// Smartcards are inserted into a card reader that is directly attached to the
/// HSM.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Erase the contents of a smartcard, if possible.
    ///
    /// It's possible to erase ACS cards, blank cards, and OCS cards from the
    /// current Security World. Due to restrictions in the underlying Entrust
    /// tools, it's not allowed to erase OCS cards from a different Security
    /// World.
    Erase,

    /// Print information about the currently attached smartcard.
    Info,

    /// Write a new operator card (OCS).
    ///
    /// The HSM must be in operational mode. This writes a cardset made up of a
    /// single operator card.
    WriteOcs,
}

pub fn run(command: &Command, context: &Context) -> Result<(), Error> {
    match command {
        Command::Erase => {
            // Prefer `slotinfo` over `createocs --erase` since `createocs`
            // does not allow erasing blank cards or ACS cards from the
            // current Security World.
            context.exec(Process::new(
                &join_path(&context.paths.nfast_bin, "slotinfo"),
                &["--format", "--ignoreauth", "--module", "1", "--slot", "0"],
            ))
        }

        Command::Info => context.exec(Process::new(
            &join_path(&context.paths.nfast_bin, "slotinfo"),
            &["--module", "1", "--slot", "0"],
        )),

        Command::WriteOcs => context.exec(Process::new(
            &join_path(&context.paths.nfast_bin, "createocs"),
            &[
                "--module",
                "1",
                "--name",
                "codesign",
                "--ocs-quorum",
                "1/1",
                "--no-persist",
                "--no-pp-recovery",
                "--timeout",
                "0",
            ],
        )),
    }
}
