///! General-purpose mechanisms to access databases of secrets at runtime.
use async_trait::async_trait;
use secrecy;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::Debug;

mod google_secret_manager;
mod periodic;
mod secrets_file;

pub use anyhow::Error;
pub use google_secret_manager::Client as GoogleSecretManagerClient;
pub use periodic::{BulkLoad, Periodic};
pub use secrets_file::SecretsFile;

/// A value that should remain confidential.
#[derive(Deserialize)]
pub struct Secret(pub secrecy::Secret<Vec<u8>>);

impl Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

impl From<Vec<u8>> for Secret {
    fn from(value: Vec<u8>) -> Self {
        Self(secrecy::Secret::from(value))
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        use secrecy::ExposeSecret;
        Self::from(self.0.expose_secret().clone())
    }
}

/// An identifier for a secret. Secret names are not confidential.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretName(pub String);

/// A version number for a secret.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretVersion(pub u64);

/// A client to access a database of secrets.
#[async_trait]
pub trait SecretManager: Debug + Send + Sync {
    /// Returns a particular version of a secret.
    async fn get_secret_version(
        &self,
        name: &SecretName,
        version: SecretVersion,
    ) -> Result<Option<Secret>, Error>;

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
