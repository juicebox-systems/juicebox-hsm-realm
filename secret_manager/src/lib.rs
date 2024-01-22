//! General-purpose mechanisms to access databases of secrets at runtime.
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::Debug;
use std::time::Duration;

mod google_secret_manager;
mod periodic;
mod secrets_file;

use google::GrpcConnectionOptions;
use juicebox_realm_api::types::SecretBytesVec;
use juicebox_realm_auth::{AuthKey, AuthKeyAlgorithm, AuthKeyVersion};
use observability::metrics;

pub use anyhow::{anyhow, Error};
pub use google_secret_manager::Client as GoogleSecretManagerClient;
pub use periodic::{BulkLoad, Periodic};
pub use secrets_file::SecretsFile;

/// A value that should remain confidential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Secret {
    pub data: SecretBytesVec,
    pub algorithm: SecretAlgorithm,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum SecretAlgorithm {
    HmacSha256,
    RsaPkcs1Sha256,
    Blake2sMac256,
    Edwards25519,
}

#[derive(Debug, Deserialize)]
enum SecretDataEncoding {
    Hex,
    UTF8,
}

#[derive(Debug, Deserialize)]
struct SecretJSON {
    data: String,
    encoding: SecretDataEncoding,
    algorithm: SecretAlgorithm,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SecretParsingError {
    InvalidDataForEncoding,
    InvalidJSON,
}

impl Secret {
    pub fn from_json(slice: &[u8]) -> Result<Self, SecretParsingError> {
        if let Ok(json) = serde_json::from_slice::<SecretJSON>(slice) {
            Ok(Secret {
                data: match json.encoding {
                    SecretDataEncoding::Hex => match hex::decode(json.data) {
                        Ok(vec) => vec,
                        Err(_) => return Err(SecretParsingError::InvalidDataForEncoding),
                    },
                    SecretDataEncoding::UTF8 => json.data.as_bytes().to_vec(),
                }
                .into(),
                algorithm: json.algorithm,
            })
        } else {
            Err(SecretParsingError::InvalidJSON)
        }
    }

    /// Attempts to treat the provided `slice` as JSON data, but if
    /// it cannot successfully be parsed falls back to using it directly
    /// as data for an HmacSha256 Secret value.
    pub fn from_json_or_raw(data: Vec<u8>) -> Self {
        match Self::from_json(&data) {
            Ok(secret) => secret,
            Err(_) => Secret {
                data: SecretBytesVec::from(data),
                algorithm: SecretAlgorithm::HmacSha256,
            },
        }
    }
}

impl TryFrom<Secret> for AuthKey {
    type Error = Error;
    fn try_from(value: Secret) -> Result<Self, Self::Error> {
        match value.algorithm {
            SecretAlgorithm::HmacSha256 => Ok(AuthKey {
                data: value.data,
                algorithm: AuthKeyAlgorithm::HS256,
            }),
            SecretAlgorithm::RsaPkcs1Sha256 => Ok(AuthKey {
                data: value.data,
                algorithm: AuthKeyAlgorithm::RS256,
            }),
            SecretAlgorithm::Edwards25519 => Ok(AuthKey {
                data: value.data,
                algorithm: AuthKeyAlgorithm::EdDSA,
            }),
            _ => Err(anyhow!("unsupported JWT algorithm")),
        }
    }
}

/// An identifier for a secret. Secret names are not confidential.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretName(pub String);

/// A version number for a secret.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretVersion(pub u64);

impl From<AuthKeyVersion> for SecretVersion {
    fn from(value: AuthKeyVersion) -> Self {
        Self(value.0)
    }
}

impl From<SecretVersion> for AuthKeyVersion {
    fn from(value: SecretVersion) -> Self {
        Self(value.0)
    }
}

/// A client to access a database of secrets.
#[async_trait]
pub trait SecretManager: Debug + Send + Sync {
    /// Returns a particular version of a secret.
    async fn get_secret_version(
        &self,
        name: &SecretName,
        version: SecretVersion,
    ) -> Result<Option<Secret>, Error>;

    /// Returns the newest version of a secret.
    async fn get_latest_secret_version(
        &self,
        name: &SecretName,
    ) -> Result<Option<(SecretVersion, Secret)>, Error> {
        Ok(self
            .get_secrets(name)
            .await?
            .into_iter()
            .max_by(|(a_version, _), (b_version, _)| a_version.cmp(b_version)))
    }

    /// Returns the secret versions for this named secret, or an empty map if
    /// there are none.
    ///
    /// Trying multiple active keys can be useful for key rotation even when
    /// the secret's version is unknown.
    async fn get_secrets(&self, name: &SecretName)
        -> Result<HashMap<SecretVersion, Secret>, Error>;
}

/// A [`HashMap`] is a simple way to access a static set of secrets.
#[async_trait]
impl SecretManager for HashMap<SecretName, HashMap<SecretVersion, Secret>> {
    async fn get_secret_version(
        &self,
        name: &SecretName,
        version: SecretVersion,
    ) -> Result<Option<Secret>, Error> {
        Ok(self
            .get(name)
            .and_then(|versions| versions.get(&version))
            .cloned())
    }

    async fn get_secrets(
        &self,
        name: &SecretName,
    ) -> Result<HashMap<SecretVersion, Secret>, Error> {
        Ok(self.get(name).cloned().unwrap_or_default())
    }
}

/// Constructs a new Google Cloud Secret Manager client that's limited to
/// accessing tenant auth keys.
pub async fn new_google_secret_manager(
    project: &str,
    auth_manager: gcp_auth::AuthenticationManager,
    refresh_interval: Duration,
    options: GrpcConnectionOptions,
    metrics: metrics::Client,
) -> Result<impl SecretManager, Error> {
    let client = GoogleSecretManagerClient::new(
        project,
        auth_manager,
        Some(format!(
            "({}) OR ({})",
            format_args!(
                "name:{} AND labels.kind=record_id_randomization_key",
                record_id_randomization_key_name().0
            ),
            "name:tenant- AND labels.kind=tenant_auth_key",
        )),
        options,
        metrics,
    )
    .await?;
    let manager = Periodic::new(client, refresh_interval).await?;
    Ok(manager)
}

/// The name of a per-realm secret Blake2sMac256 key. The key must be exactly
/// 32 bytes long.
///
/// The key is used to pseudo-randomly distribute record IDs (even with
/// adversarially-generated user IDs), so that the Merkle trees stay balanced.
/// This is similar to how hash tables are randomized.
pub fn record_id_randomization_key_name() -> SecretName {
    SecretName(String::from("record-id-randomization"))
}

pub fn tenant_secret_name(tenant: &str) -> SecretName {
    SecretName(format!("tenant-{tenant}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_parsing_hs256_utf8() {
        let json = r#"
        {
            "data": "hello world",
            "encoding": "UTF8",
            "algorithm": "HmacSha256"
        }
        "#;
        assert_eq!(
            Secret::from_json(json.as_bytes()).unwrap(),
            Secret {
                data: b"hello world".to_vec().into(),
                algorithm: SecretAlgorithm::HmacSha256
            }
        );
    }

    #[test]
    fn test_json_parsing_eddsa_hex() {
        let json = r#"
        {
            "data": "302e020100300506032b6570042204207c6f273d5ecccf1c01706ccd98a4fb661aac4185edd58c4705c9db9670ef8cdd",
            "encoding": "Hex",
            "algorithm": "Edwards25519"
        }
        "#;
        assert_eq!(
            Secret::from_json(json.as_bytes()).unwrap(),
            Secret {
                data: hex::decode("302e020100300506032b6570042204207c6f273d5ecccf1c01706ccd98a4fb661aac4185edd58c4705c9db9670ef8cdd").unwrap().into(),
                algorithm: SecretAlgorithm::Edwards25519
            }
        );
    }

    #[test]
    fn test_json_parsing_invalid_hex() {
        let json = r#"
        {
            "data": "hello world",
            "encoding": "Hex",
            "algorithm": "HmacSha256"
        }
        "#;
        assert_eq!(
            Secret::from_json(json.as_bytes()).unwrap_err(),
            SecretParsingError::InvalidDataForEncoding
        );
    }

    #[test]
    fn test_json_parsing_invalid_encoding() {
        let json = r#"
        {
            "data": "hello world",
            "encoding": "Nope",
            "algorithm": "HmacSha256"
        }
        "#;
        assert_eq!(
            Secret::from_json(json.as_bytes()).unwrap_err(),
            SecretParsingError::InvalidJSON
        );
    }

    #[test]
    fn test_json_parsing_invalid_algorithm() {
        let json = r#"
        {
            "data": "hello world",
            "encoding": "UTF8",
            "algorithm": "LMNOP"
        }
        "#;
        assert_eq!(
            Secret::from_json(json.as_bytes()).unwrap_err(),
            SecretParsingError::InvalidJSON
        );
    }

    #[test]
    fn test_json_parsing_invalid_json() {
        let json = "xyz";
        assert_eq!(
            Secret::from_json(json.as_bytes()).unwrap_err(),
            SecretParsingError::InvalidJSON
        );
    }
}
