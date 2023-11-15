use clap::{self, Subcommand};
use std::io::{self, IsTerminal, Read};

use crate::{bip39, digests::print_bip39_mnemonic, Context, Error};

/// Convert to and from BIP-39 mnemonic phrase format.
///
/// BIP-39 mnemonic phrases encode 128 to 256 bits of data and include a
/// checksum in the final word. See
/// <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki> for
/// details. This program uses the standard English wordlist.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print the hex data encoded in a BIP-39 mnemonic phrase.
    ///
    /// The 12-24 word mnemonic should be given or typed as stdin and may span
    /// multiple lines.
    Decode,

    /// Encode data as a BIP-39 mnemonic phrase.
    Encode {
        /// 32-64 hex characters of input data.
        hex: String,
    },
}

pub fn run(command: &Command, _context: &Context) -> Result<(), Error> {
    match command {
        Command::Decode => {
            let mut stdin = io::stdin();
            let mut input = String::new();

            let stdin_error = |e| Error::new(format!("error reading from stdin: {e}"));
            if stdin.is_terminal() {
                println!("Enter BIP-39 mnemonic, then EOF (Ctrl-D):");
                stdin.read_to_string(&mut input).map_err(stdin_error)?;
                println!("^D");
                println!();
            } else {
                stdin.read_to_string(&mut input).map_err(stdin_error)?;
            }

            let entropy = bip39::from_mnemonic(&input)?;
            println!("BIP-39 decoded ({} bits):", entropy.len() * 8);
            println!("{}", hex::encode(entropy));
        }

        Command::Encode { hex } => {
            let entropy = hex::decode(hex)
                .map_err(|e| Error::new(format!("error decoding hex input: {e}")))?;
            println!("BIP-39 mnemonic ({} bits):", entropy.len() * 8);
            let mnemonic = bip39::to_mnemonic(&entropy)?;
            print_bip39_mnemonic(&mnemonic);
        }
    }

    Ok(())
}
