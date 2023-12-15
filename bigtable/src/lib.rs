use async_trait::async_trait;
use std::time::Duration;
use tonic::transport::{Endpoint, Uri};
use tracing::info;

use google::auth::AuthMiddleware;
use google::bigtable::admin::v2::bigtable_table_admin_client::BigtableTableAdminClient as BtAdminClient;
use google::bigtable::v2::bigtable_client::BigtableClient as BtClient;
use google::conn::MaxConnectionLifetime;
use google::GrpcConnectionOptions;
use observability::metrics;

pub mod mutate;
pub mod read;

pub type AuthManager = Option<gcp_auth::AuthenticationManager>;

pub type BigtableTableAdminClient = BtAdminClient<MaxConnectionLifetime<AuthMiddleware>>;

pub type BigtableClient = BtClient<MaxConnectionLifetime<AuthMiddleware>>;

// Bigtable will close connections after one hour, we'll cycle onto a new one
// before then. see https://cloud.google.com/bigtable/docs/connection-pools and
// also the example go code for rotating connections
// https://github.com/GoogleCloudPlatform/cloud-bigtable-examples/blob/main/go/connection-refresh/btrefresh/bigtable_rotator.go
const MAX_CONN_LIFETIME: Duration = Duration::from_secs(55 * 60);

pub async fn new_admin_client(
    url: Uri,
    auth_manager: AuthManager,
    options: GrpcConnectionOptions,
    metrics: metrics::Client,
) -> Result<BigtableTableAdminClient, tonic::transport::Error> {
    let channel = MaxConnectionLifetime::new(MAX_CONN_LIFETIME, move || {
        let url = url.clone();
        let auth_manager = auth_manager.clone();
        let options = options.clone();
        let metrics = metrics.clone();

        async move {
            let channel = options.apply(Endpoint::from(url)).connect().await?;
            let channel = AuthMiddleware::new(
                channel,
                auth_manager,
                &["https://www.googleapis.com/auth/bigtable.admin.table"],
                metrics,
            );
            info!("created new bigdata admin connection");
            Ok(channel)
        }
    })
    .await?;
    Ok(BtAdminClient::new(channel))
}

pub async fn new_data_client<W: ConnWarmer>(
    inst: Instance,
    url: Uri,
    auth_manager: AuthManager,
    options: GrpcConnectionOptions,
    metrics: metrics::Client,
    warmer: W,
) -> Result<BigtableClient, tonic::transport::Error> {
    let channel = MaxConnectionLifetime::new(MAX_CONN_LIFETIME, move || {
        let url = url.clone();
        let auth_manager = auth_manager.clone();
        let options = options.clone();
        let metrics = metrics.clone();
        let inst = inst.clone();
        let warmer = warmer.clone();

        async move {
            let channel = options.apply(Endpoint::from(url)).connect().await?;
            let channel = AuthMiddleware::new(
                channel,
                auth_manager,
                &["https://www.googleapis.com/auth/bigtable.data"],
                metrics,
            );
            let c = BtClient::new(channel.clone());
            warmer.warm(inst, c).await;
            info!("returning new bigdata data connection {channel:?}");
            Ok(channel)
        }
    })
    .await?;

    let bigtable = BtClient::new(channel)
        // These are based on the 1 << 28 = 256 MiB limits from
        // <https://github.com/googleapis/google-cloud-go/blob/fbe78a2/bigtable/bigtable.go#L86>.
        // They don't appear to set similar limits for the admin client,
        // probably because those messages should fit within gRPC's default
        // 4 MiB limit.
        .max_decoding_message_size(256 * 1024 * 1024)
        .max_encoding_message_size(256 * 1024 * 1024);
    Ok(bigtable)
}

#[async_trait]
pub trait ConnWarmer: Send + Clone + 'static {
    async fn warm(&self, inst: Instance, conn: BtClient<AuthMiddleware>);
}

#[derive(Clone)]
pub struct NoWarmup;

#[async_trait]
impl ConnWarmer for NoWarmup {
    async fn warm(&self, _inst: Instance, _conn: BtClient<AuthMiddleware>) {}
}

#[derive(Clone, Debug)]
pub struct Instance {
    pub project: String,
    pub instance: String,
}

impl Instance {
    pub fn path(&self) -> String {
        format!(
            "projects/{project}/instances/{instance}",
            project = self.project,
            instance = self.instance,
        )
    }
}
