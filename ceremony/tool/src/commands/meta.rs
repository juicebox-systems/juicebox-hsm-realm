use clap::{self, Subcommand};

use crate::{Context, Error};

/// Commands about this ceremony tool.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print the SHA-256 digest of this binary.
    ///
    /// The digest is printed in hex and as a BIP-39 mnemonic.
    Hash,

    /// Print the paths of things on the filesystem, reflecting the current
    /// environment variables.
    Paths,
}

pub fn run(command: &Command, context: &Context) -> Result<(), Error> {
    match command {
        Command::Hash => context.print_file_digest("/proc/self/exe"),

        Command::Paths => {
            println!("{:#?}", context.paths);
            Ok(())
        }
    }
}
