use google::GrpcConnectionOptions;
use http::Uri;
use std::fmt;
use std::future::Future;
use std::ops::Deref;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{info, instrument, trace};
use url::Url;

use bigtable::mutate::MutateRowsError;
use bigtable::read::RowKey;
use bigtable::{
    new_admin_client, new_data_client, AuthManager, BigtableClient, BigtableTableAdminClient,
    Instance,
};
use hsm_api::merkle::StoreDelta;
use hsm_api::{DataHash, EntryMac, GroupId, LogEntry, LogIndex};
use juicebox_realm_api::types::RealmId;
use observability::metrics;
use observability::metrics_tag as tag;
use service_core::clap_parsers::parse_duration;

mod base128;
pub mod discovery;
mod lease;
mod log;
mod merkle;
pub mod tenants;

pub use log::LogEntriesIter;

#[derive(clap::Args, Clone, Debug)]
pub struct BigtableArgs {
    /// The name of the GCP project that contains the bigtable instance.
    #[arg(long = "bigtable-project", default_value = "prj")]
    pub project: String,

    /// The name of the bigtable instance to connect to.
    #[arg(long = "bigtable-instance", default_value = "instance")]
    pub instance: String,

    /// The url to the bigtable emulator [default uses GCP endpoints].
    #[arg(long = "bigtable-url")]
    pub url: Option<Uri>,

    /// The bigtable gRPC request timeout setting.
    #[arg(long = "bigtable-timeout",
            value_parser=parse_duration,
            default_value=format!("{:?}", GrpcConnectionOptions::default().timeout))]
    pub timeout: Duration,

    /// The bigtable gRPC connection timeout setting.
    #[arg(long ="bigtable-connect-timeout",
            value_parser=parse_duration,
            default_value=format!("{:?}", GrpcConnectionOptions::default().connect_timeout))]
    pub connect_timeout: Duration,

    /// The bigtable gRPC http2 Keep-alive interval setting.
    ///
    /// Interval between sending http2 keep-alive ping messages.
    #[arg(long = "bigtable-http-keepalive-interval",
            value_parser=parse_duration,
            default_value=format!("{:?}", GrpcConnectionOptions::default().http2_keepalive_interval))]
    pub http2_keepalive_interval: Duration,

    /// The bigtable gRPC http2 Keep-alive timeout setting.
    ///
    /// The timeout duration waiting for a http2 keep-alive ping response.
    #[arg(long = "bigtable-http-keepalive-timeout",
        value_parser=parse_duration,
        default_value=format!("{:?}", GrpcConnectionOptions::default().http2_keepalive_timeout))]
    pub http2_keepalive_timeout: Duration,

    /// The bigtable gRPC http2 Keep-alive while idle setting.
    ///
    /// If true http2 keep alive messages will continue to be sent when the connection would otherwise be idle
    #[arg(long = "bigtable-http-keepalive-while-idle",
        default_value_t=GrpcConnectionOptions::default().http2_keepalive_while_idle)]
    pub http2_keepalive_while_idle: bool,
}

impl BigtableArgs {
    pub fn needs_auth(&self) -> bool {
        match &self.url {
            Some(url) => {
                let host = url.host().expect("url should specify host");
                host == "googleapis.com" || host.ends_with(".googleapis.com")
            }
            None => true,
        }
    }

    pub async fn connect_data(
        &self,
        auth_manager: AuthManager,
        options: Options,
    ) -> Result<StoreClient, tonic::transport::Error> {
        let data_url = match &self.url {
            Some(u) => u.clone(),
            None => Uri::from_static("https://bigtable.googleapis.com"),
        };
        info!(
            instance = self.instance,
            project = self.project,
            %data_url,
            "Connecting to Bigtable Data"
        );
        let instance = Instance {
            project: self.project.clone(),
            instance: self.instance.clone(),
        };
        let conn_options = GrpcConnectionOptions {
            timeout: self.timeout,
            connect_timeout: self.connect_timeout,
            http2_keepalive_interval: self.http2_keepalive_interval,
            http2_keepalive_timeout: self.http2_keepalive_timeout,
            http2_keepalive_while_idle: self.http2_keepalive_while_idle,
        };
        StoreClient::new(
            data_url.clone(),
            instance,
            auth_manager,
            options,
            conn_options,
        )
        .await
    }

    pub async fn connect_admin(
        &self,
        auth_manager: AuthManager,
        metrics: metrics::Client,
    ) -> Result<StoreAdminClient, tonic::transport::Error> {
        let admin_url = match &self.url {
            Some(u) => u.clone(),
            None => Uri::from_static("https://bigtableadmin.googleapis.com"),
        };
        info!(
            inst = self.instance,
            project = self.project,
             %admin_url,
            "Connecting to Bigtable Admin"
        );
        let instance = Instance {
            project: self.project.clone(),
            instance: self.instance.clone(),
        };
        let options = GrpcConnectionOptions {
            timeout: self.timeout,
            connect_timeout: self.connect_timeout,
            http2_keepalive_interval: self.http2_keepalive_interval,
            http2_keepalive_timeout: self.http2_keepalive_timeout,
            http2_keepalive_while_idle: self.http2_keepalive_while_idle,
        };
        StoreAdminClient::new(admin_url.clone(), instance, auth_manager, options, metrics).await
    }

    pub fn add_to_cmd(&self, cmd: &mut Command) {
        cmd.arg("--bigtable-instance")
            .arg(&self.instance)
            .arg("--bigtable-project")
            .arg(&self.project);
        if let Some(u) = &self.url {
            cmd.arg("--bigtable-url").arg(u.to_string());
        }
    }
}

#[derive(Clone)]
pub struct StoreAdminClient {
    bigtable: BigtableTableAdminClient,
    instance: Instance,
}

impl fmt::Debug for StoreAdminClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreAdminClient")
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

impl StoreAdminClient {
    pub async fn new(
        url: Uri,
        instance: Instance,
        auth_manager: AuthManager,
        options: GrpcConnectionOptions,
        metrics: metrics::Client,
    ) -> Result<Self, tonic::transport::Error> {
        let bigtable = new_admin_client(url, auth_manager, options, metrics).await?;
        Ok(Self { bigtable, instance })
    }

    /// Creates a little Bigtable table for service discovery.
    pub async fn initialize_discovery(&self) -> Result<(), tonic::Status> {
        discovery::initialize(self.bigtable.clone(), &self.instance).await
    }

    pub async fn initialize_leases(&self) -> Result<(), tonic::Status> {
        lease::initialize(self.bigtable.clone(), &self.instance).await
    }

    pub async fn initialize_realm(&self, realm: &RealmId) -> Result<(), tonic::Status> {
        let mut bigtable = self.bigtable.clone();
        merkle::initialize(&mut bigtable, &self.instance, realm).await?;
        log::initialize(&mut bigtable, &self.instance, realm).await?;
        tenants::initialize(&mut bigtable, &self.instance, realm).await?;
        Ok(())
    }
}

pub struct StoreClient {
    // https://cloud.google.com/bigtable/docs/reference/data/rpc/google.bigtable.v2
    bigtable: BigtableClient,
    instance: Instance,
    last_write: Mutex<Option<(RealmId, GroupId, LogIndex, EntryMac)>>,
    metrics: metrics::Client,
    merkle_cache: merkle::Cache,
}

impl Clone for StoreClient {
    fn clone(&self) -> Self {
        // StoreClient is cloned during append to handle the delayed merkle node delete.
        Self {
            bigtable: self.bigtable.clone(),
            instance: self.instance.clone(),
            last_write: Mutex::new(None),
            metrics: self.metrics.clone(),
            merkle_cache: self.merkle_cache.clone(),
        }
    }
}

impl fmt::Debug for StoreClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreClient")
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum AppendError {
    Grpc(tonic::Status),
    MerkleWrites(google::rpc::Status),
    LogPrecondition,
    MerkleDeletes(google::rpc::Status),
}

impl From<tonic::Status> for AppendError {
    fn from(value: tonic::Status) -> Self {
        AppendError::Grpc(value)
    }
}

pub struct Options {
    pub metrics: metrics::Client,

    /// The maximum size of the agent's LRU Merkle tree cache, in number of
    /// nodes. This is unused for non-agents, since only agents access Merkle
    /// trees.
    ///
    /// Set this to at least the expected number of concurrent requests times
    /// the depth of the Merkle tree(s). For example, if you have a Merkle tree
    /// with 1 million records, its depth (base-2 logarithm) is about 20. If
    /// you expect 1000 concurrent requests, you should set this limit to be
    /// greater than 20,000.
    ///
    /// If unset, this will basically disable the cache (but the cache
    /// implementation insists on a limit of at least 1 entry).
    pub merkle_cache_nodes_limit: Option<usize>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            metrics: metrics::Client::NONE,
            merkle_cache_nodes_limit: None,
        }
    }
}

impl StoreClient {
    pub async fn new(
        url: Uri,
        instance: Instance,
        auth_manager: AuthManager,
        options: Options,
        conn_options: GrpcConnectionOptions,
    ) -> Result<Self, tonic::transport::Error> {
        let bigtable =
            new_data_client(url, auth_manager, conn_options, options.metrics.clone()).await?;
        Ok(Self {
            bigtable,
            instance,
            last_write: Mutex::new(None),
            metrics: options.metrics,
            merkle_cache: merkle::Cache::new(options.merkle_cache_nodes_limit.unwrap_or(1)),
        })
    }

    #[instrument(
        level = "trace",
        name = "append_log_entries_and_update_merkle_tree",
        skip(self)
    )]
    pub async fn append(
        &self,
        realm: &RealmId,
        group: &GroupId,
        entries: &[LogEntry],
        delta: StoreDelta<DataHash>,
    ) -> Result<(), AppendError> {
        self.append_inner(realm, group, entries, delta, sleep(Duration::from_secs(5)))
            .await?;
        Ok(())
    }

    // Helper for `append` that's broken out for testing. Returns the join
    // handle of the delete task if one was started.
    pub async fn append_inner<F: Future + Send + 'static>(
        &self,
        realm: &RealmId,
        group: &GroupId,
        entries: &[LogEntry],
        delta: StoreDelta<DataHash>,
        delete_waiter: F,
    ) -> Result<Option<JoinHandle<()>>, AppendError> {
        assert!(
            !entries.is_empty(),
            "append passed empty list of things to append."
        );
        trace!(
            realm = ?realm,
            group = ?group,
            first_index = ?entries[0].index,
            entries = entries.len(),
            merkle_nodes_new = delta.adds().len(),
            merkle_nodes_remove = delta.removes().len(),
            "append starting",
        );
        let start = Instant::now();

        // Make sure the previous log entry exists and matches the expected value.
        if entries[0].index != LogIndex::FIRST {
            let prev_index = entries[0].index.prev().unwrap();
            let read_log_entry = {
                let last_write = self.last_write.lock().unwrap();
                match last_write.deref() {
                    Some((last_realm, last_group, last_index, last_mac))
                        if last_realm == realm
                            && last_group == group
                            && *last_index == prev_index =>
                    {
                        if *last_mac != entries[0].prev_mac {
                            return Err(AppendError::LogPrecondition);
                        }
                        false
                    }
                    _ => true,
                }
            };
            if read_log_entry {
                if let Some(prev) = self
                    .read_log_entry(realm, group, prev_index)
                    .await
                    .expect("TODO")
                {
                    if prev.entry_mac != entries[0].prev_mac {
                        return Err(AppendError::LogPrecondition);
                    }
                } else {
                    return Err(AppendError::LogPrecondition);
                };
            }
        }

        // Make sure the batch of entries have the expected indexes & macs
        let mut prev = &entries[0];
        for e in &entries[1..] {
            assert_eq!(e.index, prev.index.next());
            assert_eq!(e.prev_mac, prev.entry_mac);
            prev = e;
        }

        // Write new Merkle nodes.
        self.write_merkle_nodes(realm, group, delta.adds())
            .await
            .map_err(|e| match e {
                MutateRowsError::Tonic(e) => AppendError::Grpc(e),
                MutateRowsError::Mutation(e) => AppendError::MerkleWrites(e),
            })?;

        // Append the new entries but only if no other writer has appended.
        let append_start = Instant::now();
        let mut bigtable = self.bigtable.clone();
        self.log_append(&mut bigtable, realm, group, entries)
            .await?;
        self.metrics.timing(
            "store_client.append_log.time",
            append_start.elapsed(),
            [tag!(?realm), tag!(?group)],
        );

        // append is supposed to be called sequentially, so this isn't racy.
        // Even if its not called sequentially last_write is purely a
        // performance improvement (it can save a log read), its not a
        // correctness thing. The code above that uses last_write to check the
        // mac chain will fallback to reading the log entry from the store if
        // the last_write info doesn't apply to that append.
        let last = entries.last().unwrap();
        *self.last_write.lock().unwrap() =
            Some((*realm, *group, last.index, last.entry_mac.clone()));

        // Delete obsolete Merkle nodes. These deletes are deferred a bit so
        // that slow concurrent readers can still access them.
        let delete_handle = if !delta.removes().is_empty() {
            let store = self.clone();
            let realm = *realm;
            let group = *group;
            Some(tokio::spawn(async move {
                delete_waiter.await;
                store
                    .remove_merkle_nodes(&realm, &group, delta.removes())
                    .await
                    .expect("TODO");
            }))
        } else {
            None
        };

        let dur = start.elapsed();
        self.metrics.timing(
            "store_client.append_inner.time",
            dur,
            [tag!(?realm), tag!(?group)],
        );
        trace!(
            realm = ?realm,
            group = ?group,
            ?dur,
            entries = entries.len(),
            "append succeeded"
        );
        Ok(delete_handle)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceKind {
    Agent,
    LoadBalancer,
    ClusterManager,
}

impl StoreClient {
    #[instrument(level = "trace", skip(self))]
    pub async fn get_addresses(
        &self,
        kind: Option<ServiceKind>,
    ) -> Result<Vec<(Url, ServiceKind)>, tonic::Status> {
        discovery::get_addresses(self.bigtable.clone(), &self.instance, kind).await
    }

    #[instrument(level = "trace", skip(self, address), fields(address = %address))]
    pub async fn set_address(
        &self,
        address: &Url,
        kind: ServiceKind,
        // timestamp of the registration, typically SystemTime::now()
        timestamp: SystemTime,
    ) -> Result<(), tonic::Status> {
        discovery::set_address(
            self.bigtable.clone(),
            &self.instance,
            address,
            kind,
            timestamp,
        )
        .await
    }

    // Obtain a lease for the specified duration. Only one lease is available at
    // any one time for a given key. Owner is recorded in the lease table only
    // for diagnostic purposes.
    pub async fn obtain_lease(
        &self,
        key: impl Into<LeaseKey>,
        owner: String,
        dur: Duration,
        timestamp: SystemTime,
    ) -> Result<Option<Lease>, tonic::Status> {
        lease::obtain(
            self.bigtable.clone(),
            &self.instance,
            key.into(),
            owner,
            dur,
            timestamp,
        )
        .await
    }

    pub async fn extend_lease(
        &self,
        lease: Lease,
        dur: Duration,
        timestamp: SystemTime,
    ) -> Result<Lease, ExtendLeaseError> {
        lease::extend(self.bigtable.clone(), &self.instance, lease, dur, timestamp).await
    }

    pub async fn terminate_lease(&self, lease: Lease) -> Result<(), tonic::Status> {
        lease::terminate(self.bigtable.clone(), &self.instance, lease).await
    }
}

#[derive(Debug)]
pub enum ExtendLeaseError {
    Rpc(tonic::Status),
    NotOwner,
}

impl From<tonic::Status> for ExtendLeaseError {
    fn from(value: tonic::Status) -> Self {
        ExtendLeaseError::Rpc(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseType {
    ClusterManagement,
}

pub struct LeaseKey(pub LeaseType, pub String);

impl LeaseKey {
    fn into_bigtable_key(self) -> Vec<u8> {
        let t = match self.0 {
            LeaseType::ClusterManagement => b"-cm",
        };
        let mut k = self.1.into_bytes();
        k.extend(t);
        k
    }
}

#[derive(Clone)]
pub struct Lease {
    key: Vec<u8>,
    id: Vec<u8>,
    owner: String,
    expires: u64, //Microseconds since EPOCH.
}

impl Lease {
    // The lease is held until this time.
    pub fn until(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_micros(self.expires)
    }
}

// Timestamps are in microseconds, but need to be rounded to milliseconds
// (or coarser depending on table schema).
pub(crate) fn to_micros(d: Duration) -> i64 {
    (d.as_millis() * 1000).try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_key_into_bigtable_key() {
        let k = LeaseKey(LeaseType::ClusterManagement, "abc".to_string());
        assert_eq!(b"abc-cm".to_vec(), k.into_bigtable_key());
    }
}
