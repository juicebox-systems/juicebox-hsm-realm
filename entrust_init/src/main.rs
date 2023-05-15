use anyhow::{anyhow, Context};
use clap::{command, Parser, Subcommand};
use std::ptr::null_mut;

use entrust_nfast::{
    find_key, M_Hash, M_ModuleID, NFKM_WorldInfo, NFKM_getinfo, NFastConn, NFastError,
};

mod acl;
mod keys;
mod nvram;

#[derive(Parser)]
#[command(about = "A tool for initializing an Entrust nCipher XC HSM ready for use with Juicebox.")]
struct Args {
    /// The HSM module to work with. (The default of 1 is fine unless there are
    /// multiple HSMs in a host).
    #[arg(short, long, default_value_t = 1)]
    module: M_ModuleID,

    /// The key that was used to sign the HSM SEE Machine executable and the
    /// userdata file. Can either be the name of the seeinteg key in the
    /// security world, or a hex string of its hash.
    #[arg(short, long, default_value = "jbox-signer")]
    signing: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create the NVRam allocation.
    Nvram(nvram::NVRamArgs),
    /// Create a new set of realm keys.
    Keys(keys::KeyArgs),
    /// Show the ACL on a key in the security world.
    Acl {
        /// The app name that the key is in. Typically simple or seeinteg.
        app: String,
        /// The name of the key.
        ident: String,
    },
}

impl Commands {
    fn validate(&self) -> anyhow::Result<()> {
        match &self {
            Commands::Nvram(args) => args.validate(),
            Commands::Keys(args) => args.validate(),
            Commands::Acl { app, ident } => acl::validate_args(app, ident),
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    args.command.validate()?;

    let mut conn = NFastConn::new();
    unsafe {
        conn.connect().context("Connecting to Entrust Hardserver")?;
    }

    let mut worldinfo: *mut NFKM_WorldInfo = null_mut();
    unsafe {
        let rc = NFKM_getinfo(conn.app, &mut worldinfo, null_mut());
        if rc != 0 {
            return Err(NFastError::Api(rc)).context("reading security world info");
        }
    }

    match args.command {
        Commands::Nvram(nvargs) => {
            let signing_key_hash =
                resolve_signing_key(&conn, &args.signing).context("Resolving signing key")?;
            nvram::command_nvram(&mut conn, args.module, worldinfo, signing_key_hash, &nvargs)
        }
        Commands::Keys(kargs) => {
            let signing_key_hash =
                resolve_signing_key(&conn, &args.signing).context("Resolving signing key")?;
            keys::command_keys(conn, args.module, worldinfo, signing_key_hash, &kargs)
        }
        Commands::Acl { app, ident } => {
            acl::command_acl(conn, args.module, worldinfo, &app, &ident)
        }
    }
}

// Resolve the signing key to its hash for the ACLs. The input can be either the name
// of the signing key from the security world, or a hex string of its hash.
fn resolve_signing_key(conn: &NFastConn, input: &str) -> anyhow::Result<M_Hash> {
    if let Ok(bytes) = hex::decode(input) {
        if let Ok(bytes) = bytes.try_into() {
            return Ok(M_Hash { bytes });
        }
    }
    // Input doesn't look like a hash, look for a key in the security world with the name
    match find_key(conn, "seeinteg", input)? {
        None => Err(anyhow!(
            "There is no signing key called '{}' in the security world",
            input,
        )),
        Some(key) => Ok(key.hash),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use expect_test::expect_file;

    #[test]
    fn test_usage() {
        expect_file!["usage.txt"].assert_eq(
            &Args::command()
                .try_get_matches_from(["entrust_init", "--help"])
                .unwrap_err()
                .to_string(),
        );
    }

    #[test]
    fn test_usage_nvram() {
        expect_file!["usage_nvram.txt"].assert_eq(
            &Args::command()
                .try_get_matches_from(["entrust_init", "nvram", "--help"])
                .unwrap_err()
                .to_string(),
        );
    }

    #[test]
    fn test_usage_keys() {
        expect_file!["usage_keys.txt"].assert_eq(
            &Args::command()
                .try_get_matches_from(["entrust_init", "keys", "--help"])
                .unwrap_err()
                .to_string(),
        );
    }

    #[test]
    fn test_usage_acl() {
        expect_file!["usage_acl.txt"].assert_eq(
            &Args::command()
                .try_get_matches_from(["entrust_init", "acl", "--help"])
                .unwrap_err()
                .to_string(),
        );
    }
}
