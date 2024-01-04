use std::{fs, io, path::PathBuf, process::Command};

#[derive(Debug)]
pub struct Certificates {
    pub key_file_pem: PathBuf,
    pub cert_file_pem: PathBuf,
    pub cert_file_der: PathBuf,
}

/// Creates a self signed cert & key for localhost in the specified directory.
pub fn create_localhost_key_and_cert(dir: PathBuf) -> io::Result<Certificates> {
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

    Ok(Certificates {
        key_file_pem: dir.join("localhost.key"),
        cert_file_pem: dir.join("localhost.cert"),
        cert_file_der: dir.join("localhost.cert.der"),
    })
}
