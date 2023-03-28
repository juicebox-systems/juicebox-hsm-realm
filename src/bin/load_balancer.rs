use clap::Parser;
use rustls::{Certificate, PrivateKey};
use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tracing::info;

use loam_mvp::logging;
use loam_mvp::realm::load_balancer::LoadBalancer;
use loam_mvp::realm::store::bigtable::BigTableArgs;

#[derive(Parser)]
#[command(about = "An HTTP load balancer for one or more realms")]
struct Args {
    #[command(flatten)]
    bigtable: BigTableArgs,

    /// The IP/port to listen on.
    #[arg(
        short,
        long,
        default_value_t = SocketAddr::from(([127,0,0,1], 8081)),
        value_parser=parse_listen,
    )]
    listen: SocketAddr,

    /// Name of the load balancer in logging [default: lb{listen}]
    #[arg(short, long)]
    name: Option<String>,

    /// Name of the file containing the private key for terminating TLS.
    #[arg(long)]
    tls_key: PathBuf,

    /// Name of the file containing the certificate(s) for terminating TLS.
    #[arg(long)]
    tls_cert: PathBuf,
}

#[tokio::main]
async fn main() {
    logging::configure("loam-load-balancer");

    ctrlc::set_handler(move || {
        info!(pid = std::process::id(), "received termination signal");
        logging::flush();
        info!(pid = std::process::id(), "exiting");
        std::process::exit(0);
    })
    .expect("error setting signal handler");

    let args = Args::parse();
    let name = args.name.unwrap_or_else(|| format!("lb{}", args.listen));
    let mut tls_key = load_keys(&args.tls_key).expect("failed to load TLS key");
    let tls_cert = load_certs(&args.tls_cert).expect("failed to load TLS cert");
    if tls_key.is_empty() {
        panic!(
            "failed to find a private key from the key file {}",
            &args.tls_key.display()
        );
    }
    if tls_cert.is_empty() {
        panic!(
            "failed to find a certificate from the cert file {}",
            &args.tls_cert.display()
        );
    }

    let store = args.bigtable.connect_data().await;

    let lb = LoadBalancer::new(name, store);
    let (url, join_handle) = lb
        .listen(args.listen, tls_cert, tls_key.remove(0))
        .await
        .expect("TODO");
    info!(url = %url, "Load balancer started");
    join_handle.await.unwrap();

    logging::flush();
    info!(pid = std::process::id(), "exiting");
}

fn parse_listen(s: &str) -> Result<SocketAddr, String> {
    s.parse()
        .map_err(|e| format!("couldn't parse listen argument: {e}"))
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}
