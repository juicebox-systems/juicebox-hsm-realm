use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use tokio::fs;

use super::{periodic::BulkLoad, Error, Secret, SecretName, SecretVersion};

/// An error message.
#[derive(Debug)]
struct StringError(String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for StringError {}

/// Loads secrets from a JSON file.
///
/// This can be used with [`super::Periodic`] to provide an implementation of
/// [`super::SecretManager`].
///
///
/// The file should look like this:
///
/// ```json
/// {
///     "tenant-a": {"1": "key1", "2": "key2"},
///     "tenant-b": {"5": "key5", "12": "key12"},
/// }
/// ```
#[derive(Clone, Debug)]
pub struct SecretsFile {
    path: PathBuf,
}

impl SecretsFile {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait]
impl BulkLoad for SecretsFile {
    async fn load_all(&self) -> Result<HashMap<SecretName, HashMap<SecretVersion, Secret>>, Error> {
        let contents: Vec<u8> = fs::read(&self.path).await.map_err(|e| {
            StringError(format!(
                "failed to read secrets from {path:?}: {e}",
                path = self.path
            ))
        })?;

        let secrets: HashMap<SecretName, HashMap<String, String>> =
            serde_json::from_slice(&contents).map_err(|e| {
                StringError(format!(
                    "failed to read secrets from {path:?}: {e}",
                    path = self.path
                ))
            })?;

        Ok(secrets
            .into_iter()
            .map(|(name, secrets)| {
                let versioned: HashMap<SecretVersion, Secret> = secrets
                    .into_iter()
                    .map(|(version, key)| {
                        Ok((
                            SecretVersion(version.parse::<u64>()?),
                            Secret::from(key.into_bytes()),
                        ))
                    })
                    .collect::<Result<_, Error>>()?;
                Ok((name, versioned))
            })
            .collect::<Result<_, Error>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use juicebox_realm_auth::AuthKeyAlgorithm;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_basic() {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            r#"
            {
                "a": {"1":"one"},
                "b": {"1":"one", "2":"two", "3":"three"},
                "c": {}
            }
            "#,
        )
        .unwrap();

        let secrets = SecretsFile::new(file.path().to_owned())
            .load_all()
            .await
            .unwrap();

        assert_eq!(secrets.len(), 3);
        let a = secrets.get(&SecretName(String::from("a"))).unwrap();
        let b = secrets.get(&SecretName(String::from("b"))).unwrap();
        let c = secrets.get(&SecretName(String::from("c"))).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 3);
        assert_eq!(c.len(), 0);
        assert_eq!(a.get(&SecretVersion(1)).unwrap().expose_secret(), b"one");
        assert_eq!(b.get(&SecretVersion(1)).unwrap().expose_secret(), b"one");
        assert_eq!(b.get(&SecretVersion(2)).unwrap().expose_secret(), b"two");
        assert_eq!(b.get(&SecretVersion(3)).unwrap().expose_secret(), b"three");
    }

    #[tokio::test]
    async fn test_auth_key_json() {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            r#"
            {
                "a": {
                    "1": "{\"encoding\":\"UTF8\",\"algorithm\":\"HS256\",\"key\":\"hello world\"}",
                    "2": "{\"encoding\":\"UTF8\",\"algorithm\":\"HS256\",\"key\":\"0102030405060708\"}",
                    "3": "0102030405060708"
                },
                "b": {
                    "1": "{\"encoding\":\"Hex\",\"algorithm\":\"HS256\",\"key\":\"0102030405060708\"}"
                },
                "c": {
                    "1": "{\"encoding\":\"Hex\",\"algorithm\":\"EdDSA\",\"key\":\"302a300506032b657003210053c1dfd0da1d1d9ecbd51fd873210e5f1ec4782ae77c39e56dbdf2a51bcd600c\"}"
                },
                "d": {
                    "1": "{\"encoding\":\"Hex\",\"algorithm\":\"RS256\",\"key\":\"30820222300d06092a864886f70d01010105000382020f003082020a0282020100be00afb5ac9d40cf97e68eef875b5542126ba7acb2578b486c055ff14b1dbc60907d05dfc718f44e14cccfe2bd9ff8fa4c31aed6922a52dc7003db988cf33732985197f5da277afca7322d390cb557f833048b68e23785e26a908529811f21dbf65193132b6d6b5d0b3ace6242b20cb07f7ba1d3c1b70fc86da217c8227c4a4fb6042a24e01ee6765daf6a672b21e404c4459e0e170b567019e99a3bb27e282d984ef77ee996f149512b87194485c1a932b7b6450ad61febe80914aef08c2ed7ae46d2692e15d619563e99b320d739d20e9ce638f6d22cfca7bbe913bde5bf2450e37568b3391f6c676207b19c471d3ea45f3611101977af2b251b42eb2206d20e7bffd71434fae3d7774b34b3b7e71479f1c721b3ece331e78b366c55de66b8c71e98af7212d5addffaef3a64be30b973b31da53217ac24e856bb27bb9891913bc302bae47f3b30f85dae3c978091064886e7fc05bfa5d14c7cf8b7d9c7064a8d50007c6e1ec07ce21dbe32c6ee8f5b819390c47d36f14330aca73bcaace32a5337bde6d9d372075f23a2b2f593d73799854878c1ed9c15c55a32bb72efb565baeacb528867b6d3f680d633d115a4b0efa88ecd004f20b246a69a5ca35d2503fb375e0f39dd6d1cbd5a0f95ee97a91e5536348695aa90c533fb6cb5b66339faea4e2e439fd2cc24755c998775bd27aa113bc157679e830f9998b00ea47b45330203010001\"}"
                }
            }
            "#,
        )
        .unwrap();

        let secrets = SecretsFile::new(file.path().to_owned())
            .load_all()
            .await
            .unwrap();

        assert_eq!(secrets.len(), 4);
        let a = secrets.get(&SecretName(String::from("a"))).unwrap();
        let b = secrets.get(&SecretName(String::from("b"))).unwrap();
        let c = secrets.get(&SecretName(String::from("c"))).unwrap();
        let d = secrets.get(&SecretName(String::from("d"))).unwrap();
        assert_eq!(a.len(), 3);
        assert_eq!(b.len(), 1);
        assert_eq!(c.len(), 1);
        assert_eq!(d.len(), 1);

        assert_eq!(
            a.get(&SecretVersion(1)).unwrap().auth_key().expose_secret(),
            b"hello world"
        );
        assert_eq!(
            a.get(&SecretVersion(1)).unwrap().auth_key_algorithm(),
            AuthKeyAlgorithm::HS256
        );
        assert_eq!(
            a.get(&SecretVersion(2)).unwrap().auth_key().expose_secret(),
            b"0102030405060708"
        );
        assert_eq!(
            a.get(&SecretVersion(2)).unwrap().auth_key_algorithm(),
            AuthKeyAlgorithm::HS256
        );
        assert_eq!(
            a.get(&SecretVersion(3)).unwrap().auth_key().expose_secret(),
            b"0102030405060708"
        );
        assert_eq!(
            a.get(&SecretVersion(3)).unwrap().auth_key_algorithm(),
            AuthKeyAlgorithm::HS256
        );

        assert_eq!(
            b.get(&SecretVersion(1)).unwrap().auth_key().expose_secret(),
            hex::decode("0102030405060708").unwrap()
        );
        assert_eq!(
            b.get(&SecretVersion(1)).unwrap().auth_key_algorithm(),
            AuthKeyAlgorithm::HS256
        );

        assert_eq!(
            c.get(&SecretVersion(1)).unwrap().auth_key().expose_secret(),
            hex::decode("302a300506032b657003210053c1dfd0da1d1d9ecbd51fd873210e5f1ec4782ae77c39e56dbdf2a51bcd600c").unwrap()
        );
        assert_eq!(
            c.get(&SecretVersion(1)).unwrap().auth_key_algorithm(),
            AuthKeyAlgorithm::EdDSA
        );

        assert_eq!(
            d.get(&SecretVersion(1)).unwrap().auth_key().expose_secret(),
            hex::decode("30820222300d06092a864886f70d01010105000382020f003082020a0282020100be00afb5ac9d40cf97e68eef875b5542126ba7acb2578b486c055ff14b1dbc60907d05dfc718f44e14cccfe2bd9ff8fa4c31aed6922a52dc7003db988cf33732985197f5da277afca7322d390cb557f833048b68e23785e26a908529811f21dbf65193132b6d6b5d0b3ace6242b20cb07f7ba1d3c1b70fc86da217c8227c4a4fb6042a24e01ee6765daf6a672b21e404c4459e0e170b567019e99a3bb27e282d984ef77ee996f149512b87194485c1a932b7b6450ad61febe80914aef08c2ed7ae46d2692e15d619563e99b320d739d20e9ce638f6d22cfca7bbe913bde5bf2450e37568b3391f6c676207b19c471d3ea45f3611101977af2b251b42eb2206d20e7bffd71434fae3d7774b34b3b7e71479f1c721b3ece331e78b366c55de66b8c71e98af7212d5addffaef3a64be30b973b31da53217ac24e856bb27bb9891913bc302bae47f3b30f85dae3c978091064886e7fc05bfa5d14c7cf8b7d9c7064a8d50007c6e1ec07ce21dbe32c6ee8f5b819390c47d36f14330aca73bcaace32a5337bde6d9d372075f23a2b2f593d73799854878c1ed9c15c55a32bb72efb565baeacb528867b6d3f680d633d115a4b0efa88ecd004f20b246a69a5ca35d2503fb375e0f39dd6d1cbd5a0f95ee97a91e5536348695aa90c533fb6cb5b66339faea4e2e439fd2cc24755c998775bd27aa113bc157679e830f9998b00ea47b45330203010001").unwrap()
        );
        assert_eq!(
            d.get(&SecretVersion(1)).unwrap().auth_key_algorithm(),
            AuthKeyAlgorithm::RS256
        );
    }

    #[tokio::test]
    #[should_panic(expected = "/does-not-exist")]
    async fn test_io_error_message_includes_path() {
        SecretsFile::new(PathBuf::from("/does-not-exist"))
            .load_all()
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "failed to read secrets from")]
    async fn test_json_error_message_includes_path() {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"{]").unwrap();
        SecretsFile::new(file.path().to_owned())
            .load_all()
            .await
            .unwrap();
    }
}
