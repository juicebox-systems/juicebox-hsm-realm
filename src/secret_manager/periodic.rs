use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::sleep;
use tracing::warn;

use super::{Error, Secret, SecretManager, SecretName, SecretVersion};

/// Required of backends for [`Periodic`].
///
/// This can also be useful in isolation to one-shot load a database at
/// startup.
#[async_trait]
pub trait BulkLoad: Clone + fmt::Debug + Send + Sync + 'static {
    async fn load_all(&self) -> Result<HashMap<SecretName, HashMap<SecretVersion, Secret>>, Error>;
}

type Cache = Arc<Mutex<HashMap<SecretName, HashMap<SecretVersion, Secret>>>>;

/// A [`SecretManager`] implementation that loads an entire secrets database
/// into local memory and repeats this on a time interval.
#[derive(Debug)]
pub struct Periodic {
    cache: Cache,

    // This is included for its `Drop` implementation, which aborts the
    // background task(s).
    #[allow(unused)]
    tasks: JoinSet<()>,
}

impl Periodic {
    pub async fn new<B: BulkLoad>(backend: B, interval: Duration) -> Result<Self, Error> {
        let secrets = backend.load_all().await?;
        let cache = Arc::new(Mutex::new(secrets));
        let mut tasks = JoinSet::new();
        tasks.spawn(refresh_loop(backend, cache.clone(), interval));
        Ok(Self { cache, tasks })
    }
}

async fn refresh_loop<B: BulkLoad>(backend: B, cache: Cache, interval: Duration) {
    loop {
        sleep(interval).await;
        match backend.load_all().await {
            Ok(secrets) => {
                let mut locked = cache.lock().await;
                *locked = secrets;
            }
            Err(e) => warn!(e, "failed to refresh secrets cache"),
        }
    }
}

#[async_trait]
impl SecretManager for Periodic {
    async fn get_secrets(
        &self,
        name: &SecretName,
    ) -> Result<HashMap<SecretVersion, Secret>, Error> {
        let locked = self.cache.lock().await;
        Ok(locked.get(name).cloned().unwrap_or_default())
    }

    async fn get_secret_version(
        &self,
        name: &SecretName,
        version: SecretVersion,
    ) -> Result<Option<Secret>, Error> {
        let locked = self.cache.lock().await;
        Ok(locked
            .get(name)
            .and_then(|versions| versions.get(&version))
            .cloned())
    }
}
