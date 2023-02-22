use clap::Parser;
use std::net::SocketAddr;
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
}

#[tokio::main]
async fn main() {
    logging::configure();
    let args = Args::parse();
    let name = args.name.unwrap_or_else(|| format!("hsm{}", args.listen));
    let hsm = HttpHsm::new(name, args.key);
    let (url, join_handle) = hsm.listen(args.listen).await.unwrap();
    info!(url = %url, "HSM started");
    join_handle.await.unwrap();
}

fn parse_listen(s: &str) -> Result<SocketAddr, String> {
    s.parse()
        .map_err(|e| format!("couldn't parse listen argument: {e}"))
}

fn parse_realm_key(s: &str) -> Result<RealmKey, String> {
    Ok(RealmKey::derive_from(s.as_bytes()))
}
