use anyhow::{anyhow, Context};
use clap::{command, Parser, Subcommand};
use std::{ffi::CString, ptr::null_mut};
use tracing::debug;

use entrust_nfast::{
    M_Hash, M_ModuleID, NFKM_Key, NFKM_KeyIdent, NFKM_WorldInfo, NFKM_findkey, NFKM_getinfo,
    NFastConn, NFastError,
};

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

#[derive(clap::Args)]
struct KeyArgs {
    /// The name of the key to generate for calculating MACs.
    #[arg(long, value_name = "KEYNAME", default_value = "jbox-mac")]
    mac: String,

    /// The name of the key pair to generate for communication.
    #[arg(long, value_name = "KEYNAME", default_value = "jbox-noise")]
    noise: String,

    /// The name of the key to generate for encrypting/decrypting user records.
    #[arg(long, value_name = "KEYNAME", default_value = "jbox-record")]
    record: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Create the NVRam allocation.
    Nvram(nvram::NVRamArgs),
    /// Create a new set of realm keys.
    Keys(KeyArgs),
}

impl Commands {
    fn validate(&self) -> anyhow::Result<()> {
        match &self {
            Commands::Nvram(args) => args.validate(),
            Commands::Keys(_args) => Ok(()),
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

    let signing_key_hash =
        resolve_signing_key(&conn, &args.signing).context("Resolving signing key")?;

    match args.command {
        Commands::Nvram(nvargs) => {
            nvram::command_nvram(&mut conn, args.module, worldinfo, signing_key_hash, &nvargs)
        }
        Commands::Keys(_kargs) => {
            todo!()
            // keys::command_keys(conn, args.module, worldinfo, signing_key_hash, &args.keys),
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
        Some(key) => unsafe { Ok((*key).hash) },
    }
}

fn find_key(conn: &NFastConn, app: &str, ident: &str) -> Result<Option<*mut NFKM_Key>, NFastError> {
    let app_cstr = CString::new(app).unwrap();
    let ident_cstr = CString::new(ident).unwrap();
    let keyid = NFKM_KeyIdent {
        appname: app_cstr.as_ptr() as *mut i8,
        ident: ident_cstr.as_ptr() as *mut i8,
    };

    let mut key: *mut NFKM_Key = null_mut();
    let rc = unsafe { NFKM_findkey(conn.app, keyid, &mut key, null_mut()) };
    if rc != 0 {
        return Err(NFastError::Api(rc));
    }
    if key.is_null() {
        debug!(?app, ?ident, "no key found");
        return Ok(None);
    }
    debug!(?app, ?ident, key=?unsafe{*key}, "found key");
    Ok(Some(key))
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
}
