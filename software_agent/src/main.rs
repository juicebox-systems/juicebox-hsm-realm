use anyhow::anyhow;
use async_trait::async_trait;
use blake2::Blake2s256;
use clap::Args;
use futures::future;
use hkdf::Hkdf;
use hmac::SimpleHmac;
use rand::{rngs::OsRng, RngCore};
use std::fmt::Write;
use std::fs;
use std::path::PathBuf;
use tokio::task::JoinHandle;
use tracing::info;

use agent_core::service::{AgentArgs, HsmTransportConstructor};
use hsm_core::hsm::mac::MacKey;
use hsm_core::hsm::{RealmKeys, RecordEncryptionKey};
use observability::metrics;

mod http_hsm;

use http_hsm::client::HsmHttpClient;
use http_hsm::host::HttpHsm;

/// A host agent that embeds an insecure software HSM.
#[derive(Debug, Args)]
struct SoftwareAgentArgs {
    /// Derive realm keys from this input (insecure).
    #[arg(short, long)]
    key: String,

    /// Directory to store the persistent state file in [default: a random temp dir]
    #[arg(short, long)]
    state_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let mut tf = TransportConstructor { hsm_handle: None };
    let h = agent_core::service::main("software-agent", &mut tf).await;
    future::try_join(h, tf.hsm_handle.unwrap()).await.unwrap();
}

struct TransportConstructor {
    hsm_handle: Option<JoinHandle<()>>,
}

#[async_trait]
impl HsmTransportConstructor<SoftwareAgentArgs, HsmHttpClient> for TransportConstructor {
    async fn construct(
        &mut self,
        args: &AgentArgs<SoftwareAgentArgs>,
        _metrics: &metrics::Client,
    ) -> HsmHttpClient {
        let dir = match &args.service.state_dir {
            None => random_tmp_dir(),
            Some(path) => path.clone(),
        };
        if !dir.exists() {
            fs::create_dir_all(&dir).unwrap_or_else(|e| {
                panic!("failed to create directory {dir:?} for persistent state: {e:?}")
            });
        } else if dir.is_file() {
            panic!("--state-dir should be a directory, but {dir:?} is a file");
        }

        let keys = insecure_derive_realm_keys(&args.service.key).unwrap();
        let hsm = HttpHsm::new(dir.clone(), args.name(), keys)
            .expect("HttpHsm failed to initialize from prior state");
        let (hsm_url, hsm_handle) = hsm.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
        info!(url = %hsm_url, dir=%dir.display(), "HSM started");
        self.hsm_handle = Some(hsm_handle);
        HsmHttpClient::new(hsm_url)
    }
}

fn insecure_derive_realm_keys(s: &str) -> anyhow::Result<RealmKeys> {
    if s.is_empty() {
        return Err(anyhow!("the key can't be empty"));
    }
    let salts = [
        // from /dev/urandom
        hex::decode("12DC3D4454D4FFFDBCD5F3484DC23D6BD4CB1323DB3D5BFB53DE88589FD48D34")?,
        hex::decode("591ABF589B93E8F75EEA54F2BE94360C5BCA05903AA85C7DE6847F4E48A50EED")?,
        hex::decode("B9782DBCA82235A2871226DD05807C955592FD5FC29280A536DFD2E02D2A9BFE")?,
    ];
    let mac = MacKey::from(derive_from(s.as_bytes(), &salts[0]));
    let record = RecordEncryptionKey::from(derive_from(s.as_bytes(), &salts[1]));
    let noise_priv = x25519_dalek::StaticSecret::from(derive_from(s.as_bytes(), &salts[2]));
    let noise_pub = x25519_dalek::PublicKey::from(&noise_priv);
    Ok(RealmKeys {
        communication: (noise_priv, noise_pub),
        record,
        mac,
    })
}

fn derive_from<const N: usize>(b: &[u8], salt: &[u8]) -> [u8; N] {
    let kdf = Hkdf::<Blake2s256, SimpleHmac<Blake2s256>>::new(Some(salt), b);
    let mut out = [0u8; N];
    kdf.expand(&[], &mut out).unwrap();
    out
}

fn random_tmp_dir() -> PathBuf {
    let tmp = std::env::temp_dir();
    let mut n = [0u8; 10];
    OsRng.fill_bytes(&mut n);
    let mut dn = String::from("agent_hsm_");
    for b in n {
        write!(dn, "{b:02x}").unwrap()
    }
    tmp.join(dn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_core::hsm::HsmClient;
    use clap::CommandFactory;
    use expect_test::expect_file;

    #[test]
    fn test_usage() {
        expect_file!["../usage.txt"].assert_eq(
            &AgentArgs::<SoftwareAgentArgs>::command()
                .try_get_matches_from(["agent", "--help"])
                .unwrap_err()
                .to_string(),
        );
    }

    #[tokio::test]
    async fn start_hsm_from_saved_state() {
        let keys = insecure_derive_realm_keys("start_hsm_from_saved_state").unwrap();
        let keys2 = insecure_derive_realm_keys("start_hsm_from_saved_state").unwrap();
        let dir = random_tmp_dir();
        fs::create_dir_all(&dir).unwrap();

        let hsm = HttpHsm::new(dir.clone(), "test".to_owned(), keys).unwrap();
        let (hsm_url, _) = hsm.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

        let hsm_client = HsmClient::new(
            HsmHttpClient::new(hsm_url),
            "test".to_owned(),
            metrics::Client::new("bob"),
        );
        hsm_client.send(hsm_api::NewRealmRequest {}).await.unwrap();
        let status = hsm_client.send(hsm_api::StatusRequest {}).await.unwrap();

        // we should be able to start another HSM instance from the persisted state.
        let hsm2 = HttpHsm::new(dir.clone(), "test".to_owned(), keys2).unwrap();
        let (hsm2_url, _) = hsm2.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let hsm2_client = HsmClient::new(
            HsmHttpClient::new(hsm2_url),
            "test".to_owned(),
            metrics::Client::new("bob"),
        );

        let status2 = hsm2_client.send(hsm_api::StatusRequest {}).await.unwrap();
        assert_eq!(status.id, status2.id);
        assert_eq!(status.public_key, status2.public_key);
        let realm = status.realm.unwrap();
        let realm2 = status2.realm.unwrap();
        assert_eq!(realm.id, realm2.id);
        assert_eq!(realm.statement, realm2.statement);
    }
}
