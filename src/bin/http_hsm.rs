use std::net::SocketAddr;

use loam_mvp::logging;
use loam_mvp::realm::hsm::{http::host::HttpHsm, RealmKey};
use tracing::{info, warn};

const HELP: &str = "\
Http_hsm
A software not-HSM accessible via HTTP

USAGE:
    http_hsm [OPTIONS]

FLAGS:
    -h, --help      Print help information

OPTIONS:
    -k, --key       The input used to derive the realm key.
    -l, --listen    IP address & port to listen on. [default 127.0.0.1:8080]
    -n, --name      The hsm name to include in logging. [default hsm{listen}]

";

struct Args {
    listen: SocketAddr,
    name: String,
    secret: RealmKey,
}

#[tokio::main]
async fn main() {
    logging::configure();
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    let hsm = HttpHsm::new(args.name, args.secret);
    let (url, join_handle) = hsm.listen(args.listen).await.unwrap();
    info!("HSM started, available at {url}");
    join_handle.await.unwrap();
}

fn parse_args() -> Result<Args, pico_args::Error> {
    let mut args = pico_args::Arguments::from_env();

    // Help has a higher priority and should be handled separately.
    if args.contains(["-h", "--help"]) {
        print!("{}", HELP);
        std::process::exit(0);
    }

    let addr: SocketAddr = args
        .opt_value_from_fn(["-l", "--listen"], parse_listen)?
        .unwrap_or(SocketAddr::from(([127, 0, 0, 1], 8080)));
    let result = Args {
        listen: addr,
        name: args
            .opt_value_from_str(["-n", "--name"])?
            .unwrap_or(format!("hsm{addr}")),
        secret: args.value_from_fn(["-k", "--key"], parse_realm_key)?,
    };

    // It's up to the caller what to do with the remaining arguments.
    let remaining = args.finish();
    if !remaining.is_empty() {
        warn!("Unused command line arguments left: {:?}.", remaining);
    }
    Ok(result)
}

fn parse_listen(s: &str) -> Result<SocketAddr, String> {
    s.parse()
        .map_err(|e| format!("couldn't parse listen argument: {e}"))
}

fn parse_realm_key(s: &str) -> Result<RealmKey, String> {
    Ok(RealmKey::derive_from(s.as_bytes()))
}
