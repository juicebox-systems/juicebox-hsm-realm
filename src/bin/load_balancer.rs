use clap::Parser;
use rustls::{Certificate, PrivateKey};
use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use tracing::{info, warn};

use loam_mvp::logging;
use loam_mvp::realm::load_balancer::{CertResolver, LoadBalancer};
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

    let args = Args::parse();
    let name = args.name.unwrap_or_else(|| format!("lb{}", args.listen));

    let certs =
        CertificateReloader::new(args.tls_key, args.tls_cert).expect("Failed to load TLS key/cert");
    let cert_resolver = certs.resolver.clone();

    let mut signals =
        Signals::new([SIGHUP, SIGINT, SIGTERM, SIGQUIT]).expect("Failed to init signal handler");

    // This uses a real thread rather than a tokio task to resolve some weirdness in
    // logging::flush where the underlying opentelemetry call just hangs forever.
    thread::Builder::new()
        .name("signal_handler".into())
        .spawn(move || {
            for signal in &mut signals {
                match signal {
                    SIGHUP => {
                        info!("Reloading TLS certificate/key from disk");
                        match certs.reload() {
                            Err(err) => warn!(err, "Failed to reload TLS certificate/key"),
                            Ok(_) => info!("Successfully reloaded TLS certificate/key from disk"),
                        }
                    }
                    SIGTERM | SIGINT | SIGQUIT => {
                        info!(pid = std::process::id(), "received termination signal");
                        logging::flush();
                        info!(pid = std::process::id(), "exiting");
                        std::process::exit(0);
                    }
                    _ => unreachable!(),
                }
            }
        })
        .unwrap();

    let store = args.bigtable.connect_data().await;

    let lb = LoadBalancer::new(name, store);
    let (url, join_handle) = lb.listen(args.listen, cert_resolver).await.expect("TODO");
    info!(url = %url, "Load balancer started");
    join_handle.await.unwrap();

    logging::flush();
    info!(pid = std::process::id(), "exiting");
}

fn parse_listen(s: &str) -> Result<SocketAddr, String> {
    s.parse()
        .map_err(|e| format!("couldn't parse listen argument: {e}"))
}

struct CertificateReloader {
    key: PathBuf,
    cert: PathBuf,
    resolver: Arc<CertResolver>,
}

impl CertificateReloader {
    fn new(key: PathBuf, cert: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let certs = Self::load_certs(&cert)?;
        let mut keys = Self::load_keys(&key)?;
        Ok(Self {
            key,
            cert,
            resolver: Arc::new(CertResolver::new(certs, keys.remove(0))?),
        })
    }

    fn reload(&self) -> Result<(), Box<dyn std::error::Error>> {
        let certs = Self::load_certs(&self.cert)?;
        let mut keys = Self::load_keys(&self.key)?;
        self.resolver.update(certs, keys.remove(0))?;
        Ok(())
    }

    fn load_certs(path: &Path) -> Result<Vec<Certificate>, Box<dyn std::error::Error>> {
        let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
            .map(|certs| certs.into_iter().map(Certificate).collect())?;
        if certs.is_empty() {
            return Err("No certs found in file".into());
        }
        Ok(certs)
    }

    fn load_keys(path: &Path) -> Result<Vec<PrivateKey>, Box<dyn std::error::Error>> {
        let keys: Vec<_> =
            rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
                .map(|keys| keys.into_iter().map(PrivateKey).collect())?;
        if keys.is_empty() {
            return Err("No keys found in file".into());
        }
        Ok(keys)
    }
}
