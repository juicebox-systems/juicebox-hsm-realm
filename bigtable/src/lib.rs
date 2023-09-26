use google::GrpcConnectionOptions;
use std::sync::Arc;
use tonic::transport::{Endpoint, Uri};

use google::auth::AuthMiddleware;
use google::bigtable::admin::v2::bigtable_table_admin_client::BigtableTableAdminClient as BtAdminClient;
use google::bigtable::v2::bigtable_client::BigtableClient as BtClient;

pub mod mutate;
pub mod read;

pub type AuthManager = Option<Arc<gcp_auth::AuthenticationManager>>;

pub type BigtableTableAdminClient = BtAdminClient<AuthMiddleware>;

pub type BigtableClient = BtClient<AuthMiddleware>;

pub async fn new_admin_client(
    url: Uri,
    auth_manager: AuthManager,
    options: GrpcConnectionOptions,
) -> Result<BigtableTableAdminClient, tonic::transport::Error> {
    let channel = options.apply(Endpoint::from(url)).connect().await?;
    let channel = AuthMiddleware::new(
        channel,
        auth_manager,
        &["https://www.googleapis.com/auth/bigtable.admin.table"],
    );
    Ok(BtAdminClient::new(channel))
}

pub async fn new_data_client(
    url: Uri,
    auth_manager: AuthManager,
    options: GrpcConnectionOptions,
) -> Result<BigtableClient, tonic::transport::Error> {
    let channel = options.apply(Endpoint::from(url)).connect().await?;
    let channel = AuthMiddleware::new(
        channel,
        auth_manager,
        &["https://www.googleapis.com/auth/bigtable.data"],
    );
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
