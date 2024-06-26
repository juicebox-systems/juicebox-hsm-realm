use anyhow::anyhow;
use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use tokio::fs;

use super::{periodic::BulkLoad, Error, Secret, SecretJSON, SecretName, SecretVersion};

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

        let secrets: HashMap<SecretName, HashMap<SecretVersion, SecretJSON>> =
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
                    .map(|(version, json)| {
                        Ok((
                            version,
                            json.try_into()
                                .map_err(|e| anyhow!("failed to parse json secret: {e:?}"))?,
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
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_basic() {
        let file = NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            r#"
            {
                "a": {
                    "1": {
                      "data": "one",
                      "encoding": "UTF8",
                      "algorithm": "HmacSha256"
                    }
                  },
                "b": {
                    "1": {
                        "data": "one",
                        "encoding": "UTF8",
                        "algorithm": "HmacSha256"
                    },
                    "2": {
                        "data": "two",
                        "encoding": "UTF8",
                        "algorithm": "HmacSha256"
                    },
                    "3": {
                        "data": "three",
                        "encoding": "UTF8",
                        "algorithm": "HmacSha256"
                    }
                },
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
        assert_eq!(
            a.get(&SecretVersion(1)).unwrap().data.expose_secret(),
            b"one"
        );
        assert_eq!(
            b.get(&SecretVersion(1)).unwrap().data.expose_secret(),
            b"one"
        );
        assert_eq!(
            b.get(&SecretVersion(2)).unwrap().data.expose_secret(),
            b"two"
        );
        assert_eq!(
            b.get(&SecretVersion(3)).unwrap().data.expose_secret(),
            b"three"
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
