use anyhow::anyhow;
use blake2::Blake2s256;
use clap::{command, Parser};
use hkdf::hmac::SimpleHmac;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fmt::Write;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tracing::info;

use hsm_core::hsm::mac::MacKey;
use hsm_core::hsm::{RealmKeys, RecordEncryptionKey};
use observability::logging;
use service_core::clap_parsers::parse_listen;
use service_core::panic;
use service_core::term::install_termination_handler;

use crate::host::HttpHsm;

mod host;

/// Software HSM, used for testing the HSM realm code without an HSM.
#[derive(Debug, Parser)]
#[command(version = build_info::clap!())]
struct Args {
    /// Derive realm keys from this input (insecure).
    #[arg(short, long)]
    key: String,

    /// Directory to store the persistent state file in [default: a random temp dir]
    #[arg(short, long)]
    state_dir: Option<PathBuf>,

    /// The IP/port to listen on.
    #[arg(
        short,
        long,
        default_value_t = SocketAddr::from(([127,0,0,1], 8078)),
        value_parser=parse_listen,
    )]
    listen: SocketAddr,

    /// Name of the hsm in logging [default: hsm{listen}].
    #[arg(short, long)]
    name: Option<String>,
}

#[tokio::main]
async fn main() {
    logging::configure("software-hsm");
    panic::set_abort_on_panic();
    install_termination_handler(Duration::from_secs(1));

    let args = Args::parse();
    info!(
        ?args,
        version = env!("CARGO_PKG_VERSION"),
        "starting Software HSM"
    );

    let dir = match &args.state_dir {
        None => random_tmp_dir(),
        Some(path) => path.clone(),
    };
    if !dir.exists() {
        fs::create_dir_all(&dir).unwrap_or_else(|e| {
            panic!("failed to create directory {dir:?} for persistent state: {e:?}")
        });
    } else if dir.is_file() {
        panic!("--state-dir should be a directory, but {dir:?} is a file");
    }

    let name = args.name.unwrap_or_else(|| format!("hsm{}", args.listen));
    let keys = insecure_derive_realm_keys(&args.key).unwrap();
    let hsm = HttpHsm::new(dir.clone(), name, keys)
        .expect("HttpHsm failed to initialize from prior state");
    let (hsm_url, hsm_handle) = hsm.listen(args.listen).await.unwrap();
    info!(url = %hsm_url, dir=%dir.display(), "HSM started");
    let _ = hsm_handle.await;
}

fn insecure_derive_realm_keys(s: &str) -> anyhow::Result<RealmKeys> {
    if s.is_empty() {
        return Err(anyhow!("the key can't be empty"));
    }
    let salts = [
        // from /dev/urandom
        hex::decode("12DC3D4454D4FFFDBCD5F3484DC23D6BD4CB1323DB3D5BFB53DE88589FD48D34")?,
        hex::decode("591ABF589B93E8F75EEA54F2BE94360C5BCA05903AA85C7DE6847F4E48A50EED")?,
        hex::decode("B9782DBCA82235A2871226DD05807C955592FD5FC29280A536DFD2E02D2A9BFE")?,
    ];
    let mac = MacKey::from(derive_from(s.as_bytes(), &salts[0]));
    let record = RecordEncryptionKey::from(derive_from(s.as_bytes(), &salts[1]));
    let noise_priv = x25519_dalek::StaticSecret::from(derive_from(s.as_bytes(), &salts[2]));
    let noise_pub = x25519_dalek::PublicKey::from(&noise_priv);
    Ok(RealmKeys {
        communication: (noise_priv, noise_pub),
        record,
        mac,
    })
}

fn derive_from<const N: usize>(b: &[u8], salt: &[u8]) -> [u8; N] {
    let kdf = Hkdf::<Blake2s256, SimpleHmac<Blake2s256>>::new(Some(salt), b);
    let mut out = [0u8; N];
    kdf.expand(&[], &mut out).unwrap();
    out
}

fn random_tmp_dir() -> PathBuf {
    let tmp = std::env::temp_dir();
    let mut n = [0u8; 10];
    OsRng.fill_bytes(&mut n);
    let mut dn = String::from("agent_hsm_");
    for b in n {
        write!(dn, "{b:02x}").unwrap()
    }
    tmp.join(dn)
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
                .try_get_matches_from(["software_hsm", "--help"])
                .unwrap_err()
                .to_string(),
        );
    }
}
