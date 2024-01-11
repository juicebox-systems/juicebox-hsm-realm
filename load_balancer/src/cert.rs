use anyhow::{anyhow, Context, Result};
use rustls::crypto::ring::sign::any_supported_type as parse_der_any;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub struct CertificateResolver {
    key_path: PathBuf,
    cert_path: PathBuf,
    current: Mutex<Arc<CertifiedKey>>,
}

impl fmt::Debug for CertificateResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateResolver")
            .field("key_path", &self.key_path)
            .field("cert_path", &self.cert_path)
            .finish_non_exhaustive()
    }
}

impl CertificateResolver {
    pub fn new(key_path: PathBuf, cert_path: PathBuf) -> Result<Self> {
        let ck = Self::load(&key_path, &cert_path)?;
        Ok(Self {
            key_path,
            cert_path,
            current: Mutex::new(ck),
        })
    }

    pub fn reload(&self) -> Result<()> {
        let ck = Self::load(&self.key_path, &self.cert_path)?;
        *self.current.lock().unwrap() = ck;
        Ok(())
    }

    fn load(key_path: &Path, cert_path: &Path) -> Result<Arc<CertifiedKey>> {
        let certs = Self::load_certs(cert_path)?;
        let keys = Self::load_keys(key_path)?;
        let key = parse_der_any(&keys[0]).context("invalid private key")?;
        Ok(Arc::new(CertifiedKey::new(certs, key)))
    }

    fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
        (|| {
            let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
                .collect::<Result<_, _>>()?;
            if certs.is_empty() {
                return Err(anyhow!("No certs found in file"));
            }
            Ok(certs)
        })()
        .with_context(|| format!("failed to read cert at {path:?}"))
    }

    fn load_keys(path: &Path) -> Result<Vec<PrivateKeyDer<'static>>> {
        (|| {
            let keys: Vec<PrivateKeyDer> =
                rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
                    .map(|result| result.map(PrivateKeyDer::Pkcs8))
                    .collect::<Result<_, _>>()?;
            if keys.is_empty() {
                return Err(anyhow!("No keys found in file"));
            }
            Ok(keys)
        })()
        .with_context(|| format!("failed to read keys at {path:?}"))
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.current.lock().unwrap().clone())
    }
}
