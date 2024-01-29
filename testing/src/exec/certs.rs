use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use std::{fs, io, path::PathBuf, process::Command};

#[derive(Debug)]
pub struct Certificates {
    pub key_file_pem: PathBuf,
    pub cert_file_pem: PathBuf,
    pub cert_file_der: PathBuf,
}

static CERT_CREATION: Mutex<()> = Mutex::new(());

/// Creates a self signed cert & key for localhost in the specified directory.
pub fn create_localhost_key_and_cert(dir: PathBuf, force: bool) -> io::Result<Certificates> {
    let certs = Certificates {
        key_file_pem: dir.join("localhost.key"),
        cert_file_pem: dir.join("localhost.cert"),
        cert_file_der: dir.join("localhost.cert.der"),
    };

    let _locked = CERT_CREATION.lock().unwrap();
    let file_ok = |f: &PathBuf| -> io::Result<bool> {
        Ok(f.exists()
            && f.is_file()
            && SystemTime::now()
                .duration_since(f.metadata()?.created()?)
                .unwrap()
                < Duration::from_secs(60 * 60 * 24 * 300))
    };
    if !force
        && file_ok(&certs.key_file_pem).is_ok_and(|v| v)
        && file_ok(&certs.cert_file_pem).is_ok_and(|v| v)
        && file_ok(&certs.cert_file_der).is_ok_and(|v| v)
    {
        return Ok(certs);
    }

    let cfg = include_str!("openssl_req.txt");
    let config_file = dir.join("openssl_req.txt");
    fs::write(config_file, cfg.as_bytes())?;

    Command::new("openssl")
        .current_dir(&dir)
        .args([
            "req",
            "-config",
            "openssl_req.txt",
            "-new",
            "-newkey",
            "rsa:4096",
            "-nodes",
            "-subj",
            "/C=US/ST=CA/L=SanFrancisco/O=Juicebox Systems,Inc./OU=test/CN=localhost",
            "-x509",
            "-extensions",
            "ext",
            "-sha256",
            "-days",
            "365",
            "-out",
            "localhost.cert",
            "-keyout",
            "localhost.key",
        ])
        .status()
        .expect("couldn't create cert");

    Command::new("openssl")
        .current_dir(&dir)
        .args([
            "x509",
            "-in",
            "localhost.cert",
            "-out",
            "localhost.cert.der",
            "-outform",
            "DER",
        ])
        .status()
        .expect("couldn't covert cert PEM to DER");

    Ok(certs)
}
