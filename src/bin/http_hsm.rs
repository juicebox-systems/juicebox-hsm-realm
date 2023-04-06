use clap::Parser;
use rand::{rngs::OsRng, RngCore};
use std::fmt::Write;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;

use hsmcore::hsm::RealmKey;
use loam_mvp::logging;
use loam_mvp::realm::hsm::http::host::HttpHsm;

#[derive(Parser)]
#[command(about = "A software not-HSM accessible via HTTP")]
struct Args {
    /// The IP/port to listen on.
    #[arg(
        short,
        long,
        default_value_t = SocketAddr::from(([127,0,0,1], 8080)),
        value_parser=parse_listen,
    )]
    listen: SocketAddr,

    /// Name of the hsm in logging [default: hsm{listen}]
    #[arg(short, long)]
    name: Option<String>,

    /// Derive realm key from this input.
    #[arg(short, long, value_parser=parse_realm_key)]
    key: RealmKey,

    /// Directory to store the persistent state file in [default: a random temp dir]
    #[arg(short, long)]
    dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    logging::configure("loam-http-hsm");
    let args = Args::parse();
    let name = args.name.unwrap_or_else(|| format!("hsm{}", args.listen));

    let dir = args.dir.unwrap_or_else(random_tmp_dir);
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .expect("failed to create specified directory for persistent state");
    } else if dir.is_file() {
        println!(
            "the --dir argument should be a directory, but {} is a file.",
            dir.display()
        );
        return;
    }
    let hsm = HttpHsm::new(dir.clone(), name, args.key)
        .expect("HttpHsm failed to initialize from prior state");
    let (url, join_handle) = hsm.listen(args.listen).await.unwrap();
    info!(url = %url, dir=%dir.display(), "HSM started");
    join_handle.await.unwrap();
}

fn parse_listen(s: &str) -> Result<SocketAddr, String> {
    s.parse()
        .map_err(|e| format!("couldn't parse listen argument: {e}"))
}

fn parse_realm_key(s: &str) -> Result<RealmKey, String> {
    Ok(RealmKey::derive_from(s.as_bytes()))
}

fn random_tmp_dir() -> PathBuf {
    let tmp = std::env::temp_dir();
    let mut n = [0u8; 10];
    OsRng.fill_bytes(&mut n);
    let mut dn = String::from("http_hsm_");
    for b in n {
        write!(dn, "{b:02x}").unwrap()
    }
    tmp.join(dn)
}
