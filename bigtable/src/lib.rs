use std::sync::Arc;
use std::time::Duration;
use tonic::transport::{Endpoint, Uri};
use tracing::{debug, info, warn};

use google::auth::AuthMiddleware;
use google::bigtable::admin::v2::bigtable_table_admin_client::BigtableTableAdminClient as BtAdminClient;
use google::bigtable::v2::bigtable_client::BigtableClient as BtClient;
use google::bigtable::v2::{read_rows_request, PingAndWarmRequest, ReadRowsRequest};
use google::conn::MaxConnectionLifetime;
use google::GrpcConnectionOptions;
use observability::metrics;

use crate::read::Reader;

pub mod mutate;
pub mod read;

pub type AuthManager = Option<Arc<gcp_auth::AuthenticationManager>>;

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

pub async fn new_data_client(
    inst: Instance,
    url: Uri,
    auth_manager: AuthManager,
    options: GrpcConnectionOptions,
    metrics: metrics::Client,
) -> Result<BigtableClient, tonic::transport::Error> {
    let channel = MaxConnectionLifetime::new(MAX_CONN_LIFETIME, move || {
        let url = url.clone();
        let auth_manager = auth_manager.clone();
        let options = options.clone();
        let metrics = metrics.clone();
        let inst = inst.clone();

        async move {
            let channel = options.apply(Endpoint::from(url)).connect().await?;
            let channel = AuthMiddleware::new(
                channel,
                auth_manager,
                &["https://www.googleapis.com/auth/bigtable.data"],
                metrics,
            );
            let mut c = BtClient::new(channel.clone());
            let r = c
                .ping_and_warm(PingAndWarmRequest {
                    name: inst.path(),
                    app_profile_id: String::from(""),
                })
                .await;
            debug!(?r, "ping_and_warm result");
            // Just ping_and_warm doesn't seem to particularly warm the connection, do some more work on it.
            for _ in 0..3 {
                if let Err(err) = Reader::read_rows(
                    &mut c,
                    ReadRowsRequest {
                        table_name: format!("{}/tables/discovery", inst.path()),
                        app_profile_id: "".into(),
                        rows: None,
                        filter: None,
                        rows_limit: 0,
                        request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone
                            .into(),
                        reversed: false,
                    },
                )
                .await
                {
                    warn!(?err, "warmup read request failed");
                }
            }
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
