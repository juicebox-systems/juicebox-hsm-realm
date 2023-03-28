use std::{fs, io, path::PathBuf, process::Command};

/// Creates a self signed cert & key for localhost in the specified directory.
/// Returns the key file & cert file, both files are in PEM format.
pub fn create_localhost_key_and_cert(dir: PathBuf) -> io::Result<(PathBuf, PathBuf)> {
    let cfg = include_str!("openssl_req.txt");
    let config_file = dir.join("openssl_req.txt");
    fs::write(config_file, cfg.as_bytes())?;

    //  openssl req -config c.req -new -newkey rsa:4096 -nodes -subj "/C=US/ST=CA/L=SanFrancisco/O=Loam,Inc./OU=test/CN=localhost"
    //  -x509 -extensions ext -keyout lb.key -out lb.cert -days 365
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

    Ok((dir.join("localhost.key"), dir.join("localhost.cert")))
}
