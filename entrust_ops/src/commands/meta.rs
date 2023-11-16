use clap::{self, Subcommand};
use std::env;

use crate::{Context, Error};

/// Commands about this tool.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print the SHA-256 digest of this binary.
    ///
    /// The digest is printed in hex and as a BIP-39 mnemonic.
    Hash,

    /// Print the paths of things on the filesystem, reflecting the current
    /// environment variables.
    ///
    /// The paths are controlled by the location of this executable and the
    /// environment variables $ENTRUST_INIT and $SIGNING_DIR.
    Paths,
}

pub fn run(command: &Command, context: &Context) -> Result<(), Error> {
    match command {
        Command::Hash => context.print_file_digest("/proc/self/exe"),

        Command::Paths => {
            println!("Environment variables:");
            for var in ["ENTRUST_INIT", "SIGNING_DIR"] {
                match env::var(var) {
                    Ok(value) => println!("    {var} is {value:?}"),
                    Err(env::VarError::NotPresent) => println!("    {var} is not set"),
                    Err(env::VarError::NotUnicode(value)) => {
                        println!("    {var} is invalid UTF-8: {value:?}")
                    }
                }
            }
            println!();

            println!("{:#?}", context.paths);
            Ok(())
        }
    }
}
