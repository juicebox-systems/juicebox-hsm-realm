use clap::{self, Subcommand};

use crate::{join_path, system::FileMode, Context, Error, Paths, Process, Sha256Sum};

/// Manage signing keys and sign HSM software and userdata.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a software signing key.
    ///
    /// This will prompt for the OCS smartcard if not inserted.
    CreateKey,

    /// Print information about the signing key, including its hash.
    ///
    /// The ACLs refer to the signing key based on its hash.
    KeyInfo,

    /// Sign the HSM software binary.
    ///
    /// This requires the OCS smartcard.
    Software {
        #[clap(
            long,
            value_name = "FILE",
            default_value_t = join_path(&Paths::get().signing_dir, "entrust_hsm.elf")
        )]
        input: String,

        #[clap(
            long,
            value_name = "FILE",
            default_value_t = join_path(&Paths::get().signing_dir, "entrust_hsm.sar")
        )]
        output: String,
    },

    /// Sign dummy HSM userdata.
    ///
    /// The userdata is a required file that may contain auxiliary information
    /// for the HSM software binary. Juicebox's software binary currently does
    /// not read this file, so its contents do not matter.
    ///
    /// This requires the OCS smartcard.
    Userdata {
        /// The path where the string "dummy" will be written.
        #[clap(
            long,
            value_name = "FILE",
            default_value_t = join_path(&Paths::get().signing_dir, "userdata.dummy")
        )]
        tempfile: String,

        #[clap(
            long,
            value_name = "FILE",
            default_value_t = join_path(&Paths::get().signing_dir, "userdata.sar")
        )]
        output: String,
    },
}

pub fn run(command: &Command, context: &Context) -> Result<(), Error> {
    match command {
        Command::CreateKey => {
            context.exec(Process::new(
                &join_path(&context.paths.nfast_bin, "generatekey"),
                &[
                    "--batch",
                    "--cardset",
                    "codesign",
                    /* APP: */ "seeinteg",
                    "recovery=no",
                    "size=4096",
                    "type=RSA",
                    "plainname=jbox-signer",
                ],
            ))
        }

        Command::KeyInfo => context.exec(Process::new(
            &join_path(&context.paths.nfast_bin, "nfkminfo"),
            &["--key-list", "seeinteg", "jbox-signer"],
        )),

        Command::Software { input, output } => {
            context.print_file_digest(input)?;
            context.exec(Process::new(
                &join_path(&context.paths.nfast_bin, "tct2"),
                &[
                    "--sign-and-pack",
                    "--infile",
                    input.as_str(),
                    "--outfile",
                    output.as_str(),
                    "--key",
                    "jbox-signer",
                    "--is-machine",
                    "--machine-type",
                    "PowerPCELF",
                    "--non-interactive",
                    "--show-metadata",
                ],
            ))?;
            println!();
            context.print_file_digest(output)
        }

        Command::Userdata { tempfile, output } => {
            context.remove_file(tempfile)?;
            context.create_file(tempfile, b"dummy", FileMode::R)?;
            context.check_file_digest(tempfile, &Sha256Sum::compute(b"dummy"))?;
            println!();

            context.exec(Process::new(
                &join_path(&context.paths.nfast_bin, "tct2"),
                &[
                    "--sign-and-pack",
                    "--infile",
                    tempfile.as_str(),
                    "--outfile",
                    output.as_str(),
                    "--key",
                    "jbox-signer",
                    "--machine-key-ident",
                    "jbox-signer",
                    "--machine-type",
                    "PowerPCELF",
                    "--non-interactive",
                    "--show-metadata",
                ],
            ))?;
            println!();
            context.print_file_digest(output)
        }
    }
}
