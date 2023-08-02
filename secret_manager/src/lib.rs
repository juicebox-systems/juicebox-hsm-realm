//! General-purpose mechanisms to access databases of secrets at runtime.
use async_trait::async_trait;
use juicebox_realm_api::types::SecretBytesVec;
use juicebox_realm_auth::{AuthKey, AuthKeyVersion};
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

mod google_secret_manager;
mod periodic;
mod secrets_file;

pub use anyhow::Error;
pub use google_secret_manager::Client as GoogleSecretManagerClient;
pub use periodic::{BulkLoad, Periodic};
pub use secrets_file::SecretsFile;

/// A value that should remain confidential.
#[derive(Clone, Debug, Deserialize)]
pub struct Secret(pub SecretBytesVec);

impl From<Vec<u8>> for Secret {
    fn from(value: Vec<u8>) -> Self {
        Self(SecretBytesVec::from(value))
    }
}

impl From<Secret> for AuthKey {
    fn from(value: Secret) -> Self {
        Self(value.0)
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
    auth_manager: Arc<gcp_auth::AuthenticationManager>,
    refresh_interval: Duration,
) -> Result<impl SecretManager, Error> {
    const TENANT_KEY_FILTER: &str = "name:tenant- AND labels.kind=tenant_auth_key";
    let client =
        GoogleSecretManagerClient::new(project, auth_manager, Some(TENANT_KEY_FILTER.to_owned()))
            .await?;
    let manager = Periodic::new(client, refresh_interval).await?;
    Ok(manager)
}

pub fn tenant_secret_name(tenant: &str) -> SecretName {
    SecretName(format!("tenant-{tenant}"))
}
