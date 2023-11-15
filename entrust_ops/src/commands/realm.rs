use clap::{self, Subcommand, ValueEnum};

use crate::{join_path, Context, Error, Process};

/// Commands for Juicebox-specific HSM and realm initialization.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Allocate a section of the HSM's NVRAM.
    ///
    /// An ACL on the NVRAM file ensures that it may only be accessed by the
    /// signed software.
    CreateNvramFile {
        /// The hash of the signing key, given as 40 hex characters. Used in the
        /// ACL for the NVRAM file.
        #[clap(long, value_parser = hex40)]
        signing_key_hash: String,
    },

    /// Create the secret keys for the Juicebox realm.
    ///
    /// ACLs on the keys ensure that they may only be accessed by the signed
    /// software.
    CreateKeys,

    /// Print the public key that clients will use to authenticate this realm.
    NoisePublicKey,

    /// Print the ACL for an existing key.
    PrintAcl { key: Key },
}

fn hex40(input: &str) -> Result<String, String> {
    if !input.bytes().all(|b| b.is_ascii_hexdigit()) {
        Err(String::from("need 40 hex characters, found non-hex digits"))
    } else if input.len() != 40 {
        Err(format!("need 40 hex characters, found {}", input.len()))
    } else {
        Ok(input.to_owned())
    }
}

/// Known HSM keys used in operating the realm or during its creation.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Key {
    /// Juicebox symmetric key used for HSM-to-HSM authentication.
    #[clap(alias = "jbox-mac")]
    Mac,

    /// Juicebox asymmetric key used for client-HSM communication.
    #[clap(alias = "jbox-noise")]
    Noise,

    /// Juicebox symmetric key used for data encryption.
    #[clap(alias = "jbox-record")]
    Record,

    /// Asymmetric key used for signing HSM software and userdata.
    #[clap(alias = "jbox-signer", alias = "signer")]
    Signing,
}

impl Key {
    fn app_ident(&self) -> (&'static str, &'static str) {
        match self {
            Self::Mac => ("simple", "jbox-mac"),
            Self::Noise => ("simple", "jbox-noise"),
            Self::Record => ("simple", "jbox-record"),
            Self::Signing => ("seeinteg", "jbox-signer"),
        }
    }
}

pub fn run(command: &Command, context: &Context) -> Result<(), Error> {
    match command {
        Command::CreateKeys => context.exec(Process::new(&context.paths.entrust_init, &["keys"])),

        Command::CreateNvramFile { signing_key_hash } => context.exec(Process::new(
            &context.paths.entrust_init,
            &["--signing", signing_key_hash, "nvram"],
        )),

        Command::NoisePublicKey => {
            let (app, ident) = Key::Noise.app_ident();
            context.exec(Process::new(
                &join_path(&context.paths.nfast_bin, "display-pubkey"),
                &[app, ident],
            ))
        }

        Command::PrintAcl { key } => {
            let (app, ident) = key.app_ident();
            context.exec(Process::new(
                &context.paths.entrust_init,
                &["acl", app, ident],
            ))
        }
    }
}
