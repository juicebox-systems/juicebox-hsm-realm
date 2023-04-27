use clap::Parser;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::{sign, Certificate, PrivateKey};
use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracing::{info, warn};

use loam_mvp::client_auth::new_google_secret_manager;
use loam_mvp::google_auth;
use loam_mvp::logging;
use loam_mvp::realm::store::bigtable::BigTableArgs;
use loam_mvp::secret_manager::{Periodic, SecretManager, SecretsFile};

mod load_balancer;

use load_balancer::LoadBalancer;

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

    /// Name of JSON file containing per-tenant keys for authentication. The
    /// default is to fetch these from Google Secret Manager.
    #[arg(long)]
    secrets_file: Option<PathBuf>,

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

    let certs = Arc::new(
        CertificateResolver::new(args.tls_key, args.tls_cert).expect("Failed to load TLS key/cert"),
    );
    let cert_resolver = certs.clone();

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

    let auth_manager = if args.bigtable.needs_auth() || args.secrets_file.is_none() {
        Some(
            google_auth::from_adc()
                .await
                .expect("failed to initialize Google Cloud auth"),
        )
    } else {
        None
    };

    let store = args
        .bigtable
        .connect_data(auth_manager.clone())
        .await
        .expect("Unable to connect to Bigtable");

    let secret_manager: Box<dyn SecretManager> = match args.secrets_file {
        Some(secrets_file) => {
            info!(path = ?secrets_file, "loading secrets from JSON file");
            Box::new(
                Periodic::new(SecretsFile::new(secrets_file), Duration::from_secs(5))
                    .await
                    .expect("failed to load secrets from JSON file"),
            )
        }

        None => {
            info!("connecting to Google Cloud Secret Manager");
            Box::new(
                new_google_secret_manager(
                    &args.bigtable.project,
                    auth_manager.unwrap(),
                    Duration::from_secs(5),
                )
                .await
                .expect("failed to load Google SecretManager secrets"),
            )
        }
    };

    let lb = LoadBalancer::new(name, store, secret_manager);
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

struct CertificateResolver {
    key_path: PathBuf,
    cert_path: PathBuf,
    current: Mutex<Arc<CertifiedKey>>,
}

impl CertificateResolver {
    fn new(key_path: PathBuf, cert_path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let ck = Self::load(&key_path, &cert_path)?;
        Ok(Self {
            key_path,
            cert_path,
            current: Mutex::new(ck),
        })
    }

    fn reload(&self) -> Result<(), Box<dyn std::error::Error>> {
        let ck = Self::load(&self.key_path, &self.cert_path)?;
        *self.current.lock().unwrap() = ck;
        Ok(())
    }

    fn load(
        key_path: &Path,
        cert_path: &Path,
    ) -> Result<Arc<CertifiedKey>, Box<dyn std::error::Error>> {
        let certs = Self::load_certs(cert_path)?;
        let keys = Self::load_keys(key_path)?;
        let key = sign::any_supported_type(&keys[0])
            .map_err(|_| rustls::Error::General("invalid private key".into()))?;
        Ok(Arc::new(CertifiedKey::new(certs, key)))
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

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.current.lock().unwrap().clone())
    }
}
