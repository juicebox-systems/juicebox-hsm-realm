use async_trait::async_trait;
use futures::future::try_join_all;
use gcp_auth::AuthenticationManager;
use http::Uri;
use std::collections::HashMap;
use std::fmt;
use tonic::transport::Endpoint;

use super::{periodic::BulkLoad, Error, Secret, SecretName, SecretVersion};
use google::auth::AuthMiddleware;
use google::cloud::secretmanager::v1 as secretmanager;
use google::GrpcConnectionOptions;
use observability::metrics;
use secretmanager::secret_manager_service_client::SecretManagerServiceClient;
use secretmanager::{AccessSecretVersionRequest, ListSecretVersionsRequest, ListSecretsRequest};

/// Like `projects/myproject`.
#[derive(Debug, Clone)]
struct ProjectResource(String);

impl ProjectResource {
    fn from_name(name: &str) -> Self {
        Self(format!("projects/{name}"))
    }
}

/// Like `projects/myproject/secrets/mysecret`.
#[derive(Debug, Clone)]
struct SecretResource(String);

impl SecretResource {
    fn secret_name(&self) -> Option<SecretName> {
        let name = self.0.splitn(4, '/').last()?;
        Some(SecretName(name.to_owned()))
    }
}

/// Like `projects/myproject/secrets/mysecret/versions/3` or
/// `projects/myproject/secrets/mysecret/versions/latest`.
#[derive(Debug, Clone)]
struct VersionResource(String);

impl VersionResource {
    fn to_number(&self) -> Option<SecretVersion> {
        let name = self.0.splitn(6, '/').last()?;
        let number = name.parse().ok()?;
        Some(SecretVersion(number))
    }
}

/// A client to access Google Cloud Secret Manager.
///
/// This can be used with [`Periodic`] to provide an implementation of
/// [`SecretManager`].
///
/// This client uses the Secret Manager GRPC API.
#[derive(Clone)]
pub struct Client {
    // https://cloud.google.com/secret-manager/docs/reference/rpc/google.cloud.secretmanager.v1
    inner: SecretManagerServiceClient<AuthMiddleware>,
    project: ProjectResource,
    list_secrets_filter: String,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("google_secret_manager::Client")
            .field("project", &self.project)
            .field("list_secrets_filter", &self.list_secrets_filter)
            .finish_non_exhaustive()
    }
}

impl Client {
    pub async fn new(
        project: &str,
        auth_manager: AuthenticationManager,
        list_secrets_filter: Option<String>,
        options: GrpcConnectionOptions,
        metrics: metrics::Client,
    ) -> Result<Self, Error> {
        let channel = options
            .apply(Endpoint::from(Uri::from_static(
                "https://secretmanager.googleapis.com",
            )))
            .connect()
            .await?;
        let channel = AuthMiddleware::new(
            channel,
            Some(auth_manager),
            &["https://www.googleapis.com/auth/cloud-platform.read-only"],
            metrics,
        );
        Ok(Self {
            inner: SecretManagerServiceClient::new(channel),
            project: ProjectResource::from_name(project),
            list_secrets_filter: list_secrets_filter.unwrap_or_default(),
        })
    }

    // To go beyond the 25,000 maximum, this would have to deal with pagination.
    async fn list_secrets(&self) -> Result<Vec<SecretResource>, Error> {
        Ok(self
            .inner
            .clone()
            .list_secrets(ListSecretsRequest {
                parent: self.project.0.clone(),
                page_size: 25000,
                page_token: String::new(),
                filter: self.list_secrets_filter.clone(),
            })
            .await?
            .into_inner()
            .secrets
            .into_iter()
            .map(|secret| SecretResource(secret.name))
            .collect())
    }

    // To go beyond the 25,000 maximum, this would have to deal with pagination.
    async fn list_secret_versions(
        &self,
        secret: &SecretResource,
    ) -> Result<Vec<VersionResource>, Error> {
        Ok(self
            .inner
            .clone()
            .list_secret_versions(ListSecretVersionsRequest {
                parent: secret.0.clone(),
                page_size: 25000,
                page_token: String::new(),
                filter: String::new(),
            })
            .await?
            .into_inner()
            .versions
            .into_iter()
            .map(|version| VersionResource(version.name))
            .collect())
    }

    async fn access_secret_version(
        &self,
        version: &VersionResource,
    ) -> Result<Option<Secret>, Error> {
        Ok(self
            .inner
            .clone()
            .access_secret_version(AccessSecretVersionRequest {
                name: version.0.clone(),
            })
            .await?
            .into_inner()
            .payload
            .map(|payload| Secret::from(payload.data)))
    }
}

// This fetches all the secrets every time. Using a notification system
// to fetch only changed secrets would be more efficient at scale.
#[async_trait]
impl BulkLoad for Client {
    async fn load_all(&self) -> Result<HashMap<SecretName, HashMap<SecretVersion, Secret>>, Error> {
        let client = self.clone();

        let secret_resources: Vec<SecretResource> = client.list_secrets().await?;

        // TODO: This kicks off a lot of futures concurrently. At scale, that
        // could potentially cause problems, so the number of concurrent
        // requests may need to be limited.
        let secret_versions: Vec<(SecretName, HashMap<SecretVersion, Secret>)> =
            try_join_all(secret_resources.iter().map(|secret| async {
                let versions = client.list_secret_versions(secret).await?;
                let values: Vec<Option<Secret>> = try_join_all(
                    versions
                        .iter()
                        .map(|version| client.access_secret_version(version)),
                )
                .await?;
                let versioned_values: HashMap<SecretVersion, Secret> = versions
                    .into_iter()
                    .map(|version| version.to_number())
                    .zip(values.into_iter())
                    .filter_map(|(version, value)| version.zip(value))
                    .collect();
                let result: Result<_, Error> =
                    Ok((secret.secret_name().unwrap(), versioned_values));
                result
            }))
            .await?;

        Ok(secret_versions.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_names() {
        assert_eq!(
            ProjectResource::from_name("myproject").0,
            "projects/myproject"
        );

        assert_eq!(
            SecretResource(String::from("projects/myproject/secrets/mysecret"))
                .secret_name()
                .unwrap()
                .0,
            "mysecret"
        );

        assert_eq!(
            VersionResource(String::from(
                "projects/myproject/secrets/mysecret/versions/3"
            ))
            .to_number()
            .unwrap()
            .0,
            3
        );

        assert_eq!(
            VersionResource(String::from(
                "projects/myproject/secrets/mysecret/versions/latest"
            ))
            .to_number(),
            None
        );
    }
}
