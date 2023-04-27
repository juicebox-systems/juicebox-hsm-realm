use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::{sign, Certificate, PrivateKey};
use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub struct CertificateResolver {
    key_path: PathBuf,
    cert_path: PathBuf,
    current: Mutex<Arc<CertifiedKey>>,
}

impl CertificateResolver {
    pub fn new(key_path: PathBuf, cert_path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let ck = Self::load(&key_path, &cert_path)?;
        Ok(Self {
            key_path,
            cert_path,
            current: Mutex::new(ck),
        })
    }

    pub fn reload(&self) -> Result<(), Box<dyn std::error::Error>> {
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
