use std::{fs, io, path::PathBuf, process::Command};

/// Creates a self signed cert & key for localhost in the specified directory.
/// Returns the key file & cert file in PEM format, as well as the cert file in DER format.
pub fn create_localhost_key_and_cert(dir: PathBuf) -> io::Result<(PathBuf, PathBuf, PathBuf)> {
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
            "/C=US/ST=CA/L=SanFrancisco/O=Loam,Inc./OU=test/CN=localhost",
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

    Ok((
        dir.join("localhost.key"),
        dir.join("localhost.cert"),
        dir.join("localhost.cert.der"),
    ))
}
