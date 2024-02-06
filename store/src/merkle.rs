use google::bigtable::admin::v2::table::TimestampGranularity;
use google::bigtable::admin::v2::{ColumnFamily, CreateTableRequest, GcRule, Table};
use google::bigtable::v2::row_filter::Chain;
use google::bigtable::v2::row_range::{EndKey::EndKeyOpen, StartKey::StartKeyClosed};
use google::bigtable::v2::{
    mutate_rows_request, mutation, read_rows_request, row_filter, MutateRowsRequest, Mutation,
    ReadRowsRequest, RowFilter, RowRange, RowSet,
};
use rand_core::{OsRng, RngCore};
use std::collections::{hash_map, BTreeMap, HashMap};
use std::fmt::{Debug, Write};
use std::future::Future;
use std::iter;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, instrument, trace, warn, Span};

use super::{base128, StoreClient, StoreClientMerkleDeleter};
use agent_api::merkle::{TreeStoreError, TreeStoreReader};
use async_util::ScopedTask;
use bigtable::mutate::{mutate_rows, MutateRowsError};
use bigtable::read::Reader;
use bigtable::{bigtable_retries, BigtableTableAdminClient, Instance};
use bitvec::Bits;
use hsm_api::merkle::{Dir, HashOutput, KeyVec, Node, NodeKey, NodeKeySet};
use hsm_api::{DataHash, GroupId, RecordId};
use juicebox_marshalling as marshalling;
use juicebox_realm_api::types::RealmId;
use observability::{metrics, metrics_tag as tag};
use retry_loop::{retry_logging, Retry, RetryError};

/// Wrapper for [`Instant`] used in the Merkle node cache.
///
/// The cache can operate using a simple counter as a clock, but using a real
/// clock is useful for metrics. It gives the cache entries ages that are
/// meaningful to humans.
#[derive(Default)]
struct MonotonicClock;

impl lru_cache::Clock for MonotonicClock {
    type Time = Instant;

    fn time(&mut self) -> Self::Time {
        Instant::now()
    }
}

/// Statistics for [`NodeCache`].
type CacheStats = lru_cache::Stats<Instant>;

/// Non-threadsafe Merkle node cache.
type NodeCache =
    lru_cache::Cache<StoreKey, NodeWithInstanceId, MonotonicClock, hash_map::RandomState>;

/// Sharable and cheaply cloneable Merkle node cache.
#[derive(Clone)]
pub struct Cache(Arc<Mutex<NodeCache>>);

impl Cache {
    pub fn new(limit: usize) -> Self {
        Self(Arc::new(Mutex::new(NodeCache::new(limit))))
    }
}

pub fn merkle_table(instance: &Instance, realm: &RealmId) -> String {
    let mut buf = String::new();
    write!(
        buf,
        "projects/{project}/instances/{instance}/tables/",
        project = instance.project,
        instance = instance.instance
    )
    .unwrap();
    for byte in realm.0 {
        write!(buf, "{byte:02x}").unwrap();
    }
    write!(buf, "-merkle").unwrap();
    buf
}

fn merkle_table_brief(realm: &RealmId) -> String {
    let mut buf = String::new();
    for byte in realm.0 {
        write!(buf, "{byte:02x}").unwrap();
    }
    write!(buf, "-merkle").unwrap();
    buf
}

/// Create table for Merkle trees.
pub(super) async fn initialize(
    bigtable: &mut BigtableTableAdminClient,
    instance: &Instance,
    realm: &RealmId,
) -> Result<(), tonic::Status> {
    bigtable
        .create_table(CreateTableRequest {
            parent: instance.path(),
            table_id: merkle_table_brief(realm),
            table: Some(Table {
                name: String::from(""),
                cluster_states: HashMap::new(),
                column_families: HashMap::from([(
                    String::from("f"),
                    ColumnFamily {
                        gc_rule: Some(GcRule { rule: None }),
                    },
                )]),
                granularity: TimestampGranularity::Unspecified.into(),
                restore_info: None,
                change_stream_config: None,
                deletion_protection: false,
            }),
            initial_splits: Vec::new(),
        })
        .await?;
    Ok(())
}

impl StoreClient {
    #[instrument(level = "trace", skip(self, add))]
    pub(super) async fn write_merkle_nodes(
        &self,
        realm: &RealmId,
        group: &GroupId,
        add: &BTreeMap<NodeKey<DataHash>, Node<DataHash>>,
    ) -> Result<(), RetryError<MutateRowsError>> {
        if add.is_empty() {
            return Ok(());
        }

        let items: Vec<(StoreKey, NodeWithInstanceId)> =
            iter::zip(add, self.0.merkle_ids.chunk(add.len()))
                .map(|((key, value), instance_id)| {
                    (
                        StoreKey::from(key),
                        NodeWithInstanceId {
                            node: marshalling::to_vec(value).expect("TODO"),
                            instance_id,
                        },
                    )
                })
                .collect();
        assert_eq!(items.len(), add.len());

        let run = |_| async {
            let entries = items
                .iter()
                .map(|(key, value)| mutate_rows_request::Entry {
                    row_key: key.0.clone(),
                    mutations: vec![Mutation {
                        mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                            family_name: String::from("f"),
                            column_qualifier: value.instance_id.0.clone(),
                            timestamp_micros: -1,
                            value: value.node.clone(),
                        })),
                    }],
                })
                .collect::<Vec<_>>();
            let mut bigtable = self.0.bigtable.clone();
            mutate_rows(
                &mut bigtable,
                MutateRowsRequest {
                    table_name: merkle_table(&self.0.instance, realm),
                    app_profile_id: String::new(),
                    entries,
                },
            )
            .await?;
            Ok(())
        };

        let tags = [tag!(?realm), tag!(?group)];

        Retry::new("writing merkle tree nodes")
            .with(bigtable_retries)
            .with_metrics(&self.0.metrics, "store_client.write_merkle_nodes", &tags)
            .retry(run, retry_logging!())
            .await?;

        let cache_stats = {
            let mut locked_cache = self.0.merkle_cache.0.lock().unwrap();
            for (key, value) in items {
                locked_cache.insert(key, value)
            }
            locked_cache.stats()
        };
        report_cache_stats(&self.0.metrics, &tags, cache_stats);
        Ok(())
    }
}

impl StoreClientMerkleDeleter {
    #[instrument(level = "trace", skip(self, keyset))]
    pub(super) async fn remove_merkle_nodes(
        &self,
        keyset: DeleteKeySet,
    ) -> Result<(), RetryError<MutateRowsError>> {
        if keyset.keys.is_empty() {
            return Ok(());
        }

        let tags = [tag!("realm":?keyset.realm)];
        let start = Instant::now();
        let mut to_fetch: HashMap<&StoreKey, &mut Option<InstanceId>> = HashMap::new();
        let mut nodes_to_delete: Vec<(&NodeKey<DataHash>, StoreKey, Option<InstanceId>)> = keyset
            .keys
            .iter()
            .map(|nk| (nk, StoreKey::from(nk), None))
            .collect();

        {
            // Grab the instance ids from the cache for the nodes we're going to delete.
            let mut locked_cache = self.merkle_cache.0.lock().unwrap();
            for (nk, sk, id) in nodes_to_delete.iter_mut() {
                match locked_cache.get(sk) {
                    Some(cached) => *id = Some(cached.instance_id.clone()),
                    None => {
                        // During transfer_in a HSM will learn about a root hash
                        // that its agent didn't read, and so it won't be in the
                        // cache. Otherwise as long as the agent's cache is
                        // larger than the HSM tree overlay, it should find
                        // everything in the cache.
                        warn!(
                            ?nk,
                            realm=?keyset.realm,
                            "merkle node not in cache, will read version from bigtable"
                        );
                        to_fetch.insert(sk, id);
                    }
                }
            }
        }
        self.metrics.distribution(
            "store_client.remove_merkle_nodes.versions_to_read",
            to_fetch.len(),
            &tags,
        );

        if !to_fetch.is_empty() {
            // Read any missing instance ids from bigtable
            let rows = Reader::read_rows(
                &mut self.bigtable.clone(),
                Retry::new("read merkle nodes instance_ids to delete")
                    .with(bigtable_retries)
                    .with_metrics(
                        &self.metrics,
                        "store_client.remove_merkle_nodes.read_versions",
                        &tags,
                    ),
                ReadRowsRequest {
                    table_name: merkle_table(&self.instance, &keyset.realm),
                    app_profile_id: String::new(),
                    rows: Some(RowSet {
                        row_keys: to_fetch.keys().map(|sk| sk.0.clone()).collect(),
                        row_ranges: Vec::new(),
                    }),
                    filter: Some(RowFilter {
                        filter: Some(row_filter::Filter::Chain(Chain {
                            filters: vec![
                                row_filter::Filter::CellsPerRowLimitFilter(1),
                                row_filter::Filter::StripValueTransformer(true),
                            ]
                            .into_iter()
                            .map(|f| RowFilter { filter: Some(f) })
                            .collect(),
                        })),
                    }),
                    rows_limit: 0,
                    request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone
                        .into(),
                    reversed: false,
                },
            )
            .await
            .map_err(|err| err.map_err(MutateRowsError::Tonic))?;

            // Extract the instance ids from the returned rows, and update the nodes_to_delete with it.
            for (row_key, cells) in rows {
                let sk = StoreKey::from(row_key.0);
                let id = cells
                    .into_iter()
                    .find(|cell| cell.family == "f")
                    .map(|cell| InstanceId(cell.qualifier))
                    .expect("every Merkle row should contain at least one node cell");
                let v = to_fetch
                    .get_mut(&sk)
                    .expect("shouldn't get rows we didn't ask for");
                **v = Some(id);
            }
        }

        let run_delete = |_| {
            let mut bigtable = self.bigtable.clone();
            let rows = nodes_to_delete.clone();
            async move {
                mutate_rows(
                    &mut bigtable,
                    MutateRowsRequest {
                        table_name: merkle_table(&self.instance, &keyset.realm),
                        app_profile_id: String::new(),
                        entries: rows
                            .into_iter()
                            .map(|(_, sk, v)| mutate_rows_request::Entry {
                                row_key: sk.into_bytes(),
                                mutations: vec![Mutation {
                                    mutation: Some(mutation::Mutation::DeleteFromColumn(
                                        mutation::DeleteFromColumn {
                                            family_name: String::from("f"),
                                            column_qualifier: v.unwrap().0,
                                            time_range: None,
                                        },
                                    )),
                                }],
                            })
                            .collect(),
                    },
                )
                .await?;
                Ok(())
            }
        };

        let result = Retry::new("deleting merkle nodes")
            .with(bigtable_retries)
            .with_metrics(
                &self.metrics,
                "store_client.remove_merkle_nodes.delete",
                &tags,
            )
            .retry(run_delete, retry_logging!())
            .await;

        let cache_stats = {
            let mut locked_cache = self.merkle_cache.0.lock().unwrap();
            for (_, key, _) in nodes_to_delete {
                locked_cache.remove(&key);
            }
            locked_cache.stats()
        };

        report_cache_stats(&self.metrics, &tags, cache_stats);
        self.metrics.timing(
            "store_client.remove_merkle_nodes.time",
            start.elapsed(),
            &tags,
        );
        result
    }
}

#[derive(Clone)]
struct InstanceId(Vec<u8>);

pub(super) struct InstanceIds {
    rnd_term: [u8; 16],
    seq: AtomicU64,
}

impl InstanceIds {
    pub(super) fn new() -> InstanceIds {
        let mut t = [0u8; 16];
        OsRng.fill_bytes(&mut t);
        Self {
            rnd_term: t,
            seq: AtomicU64::new(1),
        }
    }

    fn chunk(&self, len: usize) -> impl Iterator<Item = InstanceId> + '_ {
        assert!(len != 0);
        let len = len.try_into().unwrap();
        let base = self.seq.fetch_add(len, Ordering::Relaxed);
        (0..len).map(move |i| {
            let mut id = Vec::with_capacity(24);
            id.extend_from_slice(&self.rnd_term);
            id.extend_from_slice(&(base + i).to_be_bytes());
            InstanceId(id)
        })
    }
}

#[derive(Clone)]
struct NodeWithInstanceId {
    node: Vec<u8>,
    instance_id: InstanceId,
}

impl NodeWithInstanceId {
    fn node(&self) -> Node<DataHash> {
        marshalling::from_slice(&self.node).expect("TODO")
    }
}

struct PathLookupResult {
    /// Nodes read along the path.
    nodes: Vec<(NodeKey<DataHash>, Node<DataHash>)>,
    /// - If None, the entire path was found. The returned `nodes` either prove
    /// the existence of the record and contain the leaf record, or they prove
    /// the non-existence of the record.
    /// - If Some, a necessary node was not found.
    next: Option<NodeKey<DataHash>>,
}

trait NodeLookup {
    fn get(&mut self, k: &NodeKey<DataHash>) -> Option<Node<DataHash>>;
}

impl NodeLookup for NodeCache {
    fn get(&mut self, k: &NodeKey<DataHash>) -> Option<Node<DataHash>> {
        self.get(&StoreKey::from(k)).map(|v| v.node())
    }
}

struct HashMapNodeLookup<'a> {
    nodes: &'a HashMap<StoreKey, NodeWithInstanceId>,
    used: Vec<(DataHash, StoreKey, NodeWithInstanceId)>,
}
impl<'a> HashMapNodeLookup<'a> {
    fn new(n: &'a HashMap<StoreKey, NodeWithInstanceId>) -> Self {
        Self {
            nodes: n,
            used: Vec::new(),
        }
    }
}
impl<'a> NodeLookup for HashMapNodeLookup<'a> {
    fn get(&mut self, k: &NodeKey<DataHash>) -> Option<Node<DataHash>> {
        let sk = StoreKey::from(k);
        self.nodes.get(&sk).map(|v| {
            self.used.push((k.hash, sk, v.clone()));
            marshalling::from_slice(&v.node).expect("TODO")
        })
    }
}

/// Read from a given root towards a record in a Merkle tree.
fn merkle_path_lookup(
    record_id: &RecordId,
    root_hash: &DataHash,
    lookup_node: &mut impl NodeLookup,
) -> PathLookupResult {
    merkle_path_lookup_from(record_id, root_hash, 0, lookup_node)
}

/// Read from part way down a tree towards a record in a Merkle tree.
fn merkle_path_lookup_from(
    record_id: &RecordId,
    next: &DataHash,
    mut key_pos: usize,
    lookup_node: &mut impl NodeLookup,
) -> PathLookupResult {
    let mut nodes = Vec::new();

    let full_key = record_id.to_bitvec();
    let mut next_hash = next.to_owned();

    loop {
        let key = NodeKey::new(full_key.slice(..key_pos).to_bitvec(), next_hash);

        match lookup_node.get(&key) {
            None => {
                // Reached a miss.
                return PathLookupResult {
                    nodes,
                    next: Some(key),
                };
            }

            Some(node) => {
                if let Node::Interior(int) = &node {
                    if let Some(branch) = int.branch(Dir::from(full_key[key_pos])) {
                        if full_key.slice(key_pos..).starts_with(&branch.prefix) {
                            // Found an interior node and can continue down
                            // this path.
                            key_pos += branch.prefix.len();
                            next_hash = branch.hash;
                            nodes.push((key, node));
                            continue;
                        }
                    }
                }

                // Reached a leaf or proved non-existence.
                nodes.push((key, node));
                return PathLookupResult { nodes, next: None };
            }
        }
    }
}

impl TreeStoreReader<DataHash> for StoreClient {
    #[instrument(level = "trace", skip(self), fields(num_result_nodes))]
    async fn path_lookup(
        &self,
        realm: &RealmId,
        record_id: &RecordId,
        root_hash: &DataHash,
        tags: &[metrics::Tag],
    ) -> Result<HashMap<DataHash, Node<DataHash>>, TreeStoreError> {
        // Read as much as possible from the cache.
        let (cached_nodes, next) = {
            let result = {
                let mut locked_cache = self.0.merkle_cache.0.lock().unwrap();
                merkle_path_lookup(record_id, root_hash, locked_cache.deref_mut())
            };
            self.0.metrics.distribution(
                "store_client.path_lookup.cached_nodes_read",
                result.nodes.len() as i64,
                tags,
            );
            self.0.metrics.distribution(
                "store_client.path_lookup.full_path_cache_hits",
                result.next.is_none() as i64,
                tags,
            );
            let cached_nodes = result.nodes.into_iter().map(|(k, v)| (k.hash, v));
            match result.next {
                None => {
                    // This was a full path cache hit. For `bigtable_nodes_read`
                    // to be comparable with `cached_nodes_read`, it seems more
                    // fair to record a zero value here.
                    self.0.metrics.distribution(
                        "store_client.path_lookup.bigtable_nodes_read",
                        0,
                        tags,
                    );
                    return Ok(cached_nodes.collect());
                }
                Some(next) => (cached_nodes, next),
            }
        };

        // Read the rest from Bigtable.
        let read_req = ReadRowsRequest {
            table_name: merkle_table(&self.0.instance, realm),
            app_profile_id: String::new(),
            rows: Some(RowSet {
                row_keys: Vec::new(),
                row_ranges: all_store_key_starts(record_id)
                    // The first "key start" is 0 bits long, the second is
                    // 1 bit long, etc. By skipping `next.prefix.len()`,
                    // the Bigtable reads will return keys with at least
                    // `next.prefix.len()` bits.
                    .skip(next.prefix.len())
                    .map(|prefix| RowRange {
                        end_key: Some(EndKeyOpen(prefix.next().into_bytes())),
                        start_key: Some(StartKeyClosed(prefix.into_bytes())),
                    })
                    .collect(),
            }),
            filter: Some(RowFilter {
                filter: Some(row_filter::Filter::CellsPerRowLimitFilter(1)),
            }),
            rows_limit: 0,
            request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            reversed: false,
        };
        let mut read_values: HashMap<StoreKey, NodeWithInstanceId> = HashMap::new();
        Reader::read_rows_stream(
            &mut self.0.bigtable.clone(),
            Retry::new("merkle tree path lookup")
                .with(bigtable_retries)
                .with_metrics(&self.0.metrics, "store_client.path_lookup", tags),
            read_req,
            |row_key, cells| {
                let k = StoreKey::from(row_key.0);
                let n = cells
                    .into_iter()
                    .find(|cell| cell.family == "f")
                    .map(|cell| NodeWithInstanceId {
                        node: cell.value,
                        instance_id: InstanceId(cell.qualifier),
                    })
                    .expect("every Merkle row should contain a node value");
                read_values.insert(k, n);
            },
        )
        .await
        .map_err(|e| TreeStoreError::Network(e.to_string()))?;

        self.0.metrics.distribution(
            "store_client.path_lookup.bigtable_nodes_read",
            read_values.len(),
            tags,
        );

        // Collect up the combined superset of nodes to return.
        let mut lookup = HashMapNodeLookup::new(&read_values);
        let nodes: HashMap<DataHash, Node<DataHash>> = if !read_values.is_empty() {
            // read_values may have lots of orphaned nodes, we don't want to spam
            // the cache or the caller with all of them just the ones actually
            // needed to complete the path. [`HashMapLookup`] will keep track of the
            // actual nodes read.
            merkle_path_lookup_from(record_id, &next.hash, next.prefix.len(), &mut lookup);
            self.0.metrics.distribution(
                "store_client.path_lookup.bigtable_nodes_used",
                lookup.used.len(),
                tags,
            );
            cached_nodes
                .chain(lookup.used.iter().map(|(hash, _sk, n)| (*hash, n.node())))
                .collect()
        } else {
            cached_nodes.collect()
        };

        // Update the cache with actually used newly read values.
        if !lookup.used.is_empty() {
            let cache_stats = {
                let mut locked_cache = self.0.merkle_cache.0.lock().unwrap();
                for (_nk, store_key, value) in lookup.used.into_iter() {
                    locked_cache.insert(store_key, value);
                }
                locked_cache.stats()
            };
            report_cache_stats(&self.0.metrics, tags, cache_stats);
        }

        Span::current().record("num_result_nodes", nodes.len());
        Ok(nodes)
    }

    #[instrument(level = "trace", skip(self))]
    async fn read_node(
        &self,
        realm: &RealmId,
        key: NodeKey<DataHash>,
        tags: &[metrics::Tag],
    ) -> Result<Node<DataHash>, TreeStoreError> {
        trace!(realm = ?realm, key = ?key, "read_node starting");
        let store_key = StoreKey::from(&key);

        // Check the Merkle node cache first.
        {
            let mut locked_cache = self.0.merkle_cache.0.lock().unwrap();
            if let Some(value) = locked_cache.get(&store_key) {
                let node: Node<DataHash> = marshalling::from_slice(&value.node).expect("TODO");
                return Ok(node);
            }
        }

        // Read from Bigtable.
        let rows = Reader::read_rows(
            &mut self.0.bigtable.clone(),
            Retry::new("read merkle tree node")
                .with(bigtable_retries)
                .with_metrics(&self.0.metrics, "store_client.read_node", tags),
            ReadRowsRequest {
                table_name: merkle_table(&self.0.instance, realm),
                app_profile_id: String::new(),
                rows: Some(RowSet {
                    row_keys: vec![store_key.clone().into_bytes()],
                    row_ranges: Vec::new(),
                }),
                filter: Some(RowFilter {
                    filter: Some(row_filter::Filter::CellsPerRowLimitFilter(1)),
                }),
                rows_limit: 0,
                request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
                reversed: false,
            },
        )
        .await
        .map_err(|e| TreeStoreError::Network(e.to_string()))?;

        match rows.into_iter().next().map(|(_key, cells)| {
            cells
                .into_iter()
                .find(|cell| cell.family == "f")
                .expect("every Merkle row should contain a node value")
        }) {
            Some(cell) => {
                let node: Node<DataHash> = marshalling::from_slice(&cell.value).expect("TODO");
                let to_cache = NodeWithInstanceId {
                    node: cell.value,
                    instance_id: InstanceId(cell.qualifier),
                };

                trace!(?realm, ?key, "read_node completed");
                let cache_stats = {
                    let mut locked_cache = self.0.merkle_cache.0.lock().unwrap();
                    locked_cache.insert(store_key, to_cache);
                    locked_cache.stats()
                };
                report_cache_stats(&self.0.metrics, tags, cache_stats);
                Ok(node)
            }

            None => {
                let err = Err(TreeStoreError::MissingNode);
                trace!(?realm, ?key, ?err, "read_node failed");
                err
            }
        }
    }
}

/// Call this to report metrics after inserting or deleting from the Merkle
/// node cache.
fn report_cache_stats(metrics: &metrics::Client, tags: &[metrics::Tag], stats: CacheStats) {
    metrics.gauge("store_client.merkle_cache.nodes", stats.entries, tags);
    metrics.gauge("store_client.merkle_cache.limit", stats.limit, tags);
    metrics.timing(
        "store_client.merkle_cache.lru_age",
        match stats.lru_time {
            Some(instant) => instant.elapsed(),
            None => Duration::MAX,
        },
        tags,
    );
}

// The key value for a row in the key value store. Nodes are stored in the Store
// using these keys.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StoreKey(Vec<u8>);

impl<HO: HashOutput> From<NodeKey<HO>> for StoreKey {
    fn from(value: NodeKey<HO>) -> Self {
        StoreKey::new(&value.prefix, &value.hash)
    }
}

impl<HO: HashOutput> From<&NodeKey<HO>> for StoreKey {
    fn from(value: &NodeKey<HO>) -> Self {
        StoreKey::new(&value.prefix, &value.hash)
    }
}

impl Debug for StoreKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl From<Vec<u8>> for StoreKey {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

#[allow(dead_code)]
impl StoreKey {
    pub fn new<HO: HashOutput>(prefix: &KeyVec, hash: &HO) -> StoreKey {
        // encoded key consists of
        //   the prefix base128 encoded
        //   a delimiter which has Msb set and the lower 4 bits indicate the
        //   number of bits used in the last byte of the prefix (this is part of
        //   the base128 encoding)
        //   the hash
        let prefix_len_bytes = base128::encoded_len(prefix.len());
        let mut out: Vec<u8> = Vec::with_capacity(prefix_len_bytes + hash.as_slice().len());
        encode_prefix_into(prefix, &mut out);
        out.extend(hash.as_slice());
        StoreKey(out)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn parse<HO: HashOutput>(bytes: &[u8]) -> Option<(EncodedRecordPrefix, HO)> {
        match bytes.iter().position(|b| b & 128 != 0) {
            None => None,
            Some(p) => {
                let ep = EncodedRecordPrefix(&bytes[..=p]);
                HO::from_slice(&bytes[p + 1..]).map(|h| (ep, h))
            }
        }
    }
}

pub struct EncodedRecordPrefix<'a>(&'a [u8]);
// When/If we have a need to decode this back to the prefix, we can write the base128 decoder.

// The beginning part of a StoreKey
#[derive(Clone)]
pub struct StoreKeyStart(Vec<u8>);
impl StoreKeyStart {
    pub fn next(&self) -> Self {
        let mut c = self.0.clone();
        for i in (0..c.len()).rev() {
            if c[i] < 255 {
                c[i] += 1;
                return StoreKeyStart(c);
            } else {
                c[i] = 0;
            }
        }
        // The encoding of the recordId prefix means that its impossible to have
        // a StoreKeyStart value that leads with 0xFF, and so this is unreachable.
        // The base128 encoding of the prefix leaves the MSB clear. For the empty
        // prefix the encoding will have the single byte of the terminator, which'll
        // have the value 128.
        unreachable!()
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

// Generates the encoded version of each prefix for this recordId. starts at
// prefix[..0] and end with at prefix[..=RecordId::NUM_BITS]
pub fn all_store_key_starts(
    k: &RecordId,
) -> impl Iterator<Item = StoreKeyStart> + ExactSizeIterator + '_ {
    // `ExactSizeIterator` is not implemented for `RangeInclusive<usize>`, so
    // awkwardly cast back and forth.
    let range = 0..=u16::try_from(RecordId::NUM_BITS).unwrap();
    range.map(|i| {
        let mut enc = Vec::new();
        base128::encode(&k.0, usize::from(i), &mut enc);
        StoreKeyStart(enc)
    })
}

// Encode the prefix and delimiter into the supplied buffer.
fn encode_prefix_into(prefix: &KeyVec, dest: &mut Vec<u8>) {
    base128::encode(prefix.as_bytes(), prefix.len(), dest);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DeleteKeySet {
    pub realm: RealmId,
    pub keys: NodeKeySet<DataHash>,
}

type DeleteKeySetFuture = Pin<Box<dyn Future<Output = DeleteKeySet> + Send>>;

pub(super) struct MerkleDeleteQueue {
    tx: mpsc::Sender<PendingQueueItem>,
    shutting_down: AtomicBool,
    metrics: metrics::Client,
    // Will abort the worker task when dropped.
    _worker: ScopedTask<()>,
}

enum PendingQueueItem {
    Work {
        f: DeleteKeySetFuture,
        fin_tx: oneshot::Sender<()>,
    },
    Shutdown {
        fin_tx: oneshot::Sender<()>,
    },
}
enum ReadyQueueItem {
    Work {
        keys: DeleteKeySet,
        fin_tx: oneshot::Sender<()>,
    },
    Shutdown {
        fin_tx: oneshot::Sender<()>,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum DeleteQueueError {
    Shutdown,
}

impl MerkleDeleteQueue {
    // Creates a new MerkleDeleteQueue with the supplied callback function. This
    // callback will be called with a set of keys to delete once its related
    // defer future completes. The queue may coalesce multiple set of keys into
    // a single delete.
    pub(super) fn new<F, CbFut>(metrics: metrics::Client, cb: F) -> Self
    where
        F: Fn(DeleteKeySet) -> CbFut + Send + 'static,
        CbFut: Future<Output = ()> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel(128);
        let worker = ScopedTask::spawn(Self::queue_worker(rx, metrics.clone(), cb));
        Self {
            tx,
            shutting_down: AtomicBool::new(false),
            _worker: worker,
            metrics,
        }
    }

    // Shutdown the queue. All queued work will continue to completion. The
    // returned Receiver will block until all the queued work is complete and
    // the shutdown operation completed.
    pub(super) async fn shutdown(&self) -> Result<oneshot::Receiver<()>, DeleteQueueError> {
        if self.shutting_down.fetch_or(true, Ordering::Relaxed) {
            return Err(DeleteQueueError::Shutdown);
        }
        let (fin_tx, fin_rx) = oneshot::channel();
        self.tx
            .send(PendingQueueItem::Shutdown { fin_tx })
            .await
            .map_err(|_| DeleteQueueError::Shutdown)?;
        Ok(fin_rx)
    }

    // Queue a set of keys for deletion. `keys_fut` should sleep for the
    // required amount of time that deletes should be deferred for. Note that
    // items are processed in the ordered added to the queue, the futures should
    // use a consistent amount of time for the sleep. The returned Receiver will
    // block until the actual delete operation has been performed.
    pub(super) async fn queue(
        &self,
        keys_fut: DeleteKeySetFuture,
    ) -> Result<oneshot::Receiver<()>, DeleteQueueError> {
        if self.shutting_down.load(Ordering::Relaxed) {
            return Err(DeleteQueueError::Shutdown);
        }
        let (fin_tx, fin_rx) = oneshot::channel();
        self.tx
            .send(PendingQueueItem::Work {
                f: keys_fut,
                fin_tx,
            })
            .await
            .map_err(|_| DeleteQueueError::Shutdown)?;

        self.metrics.gauge(
            "store_client.merkle_delete.waiting_queue.len",
            self.tx.max_capacity() - self.tx.capacity(),
            metrics::NO_TAGS,
        );
        Ok(fin_rx)
    }

    async fn queue_worker<F, CbFut>(
        mut rx: mpsc::Receiver<PendingQueueItem>,
        metrics: metrics::Client,
        cb: F,
    ) where
        F: Fn(DeleteKeySet) -> CbFut + Send + 'static,
        CbFut: Future<Output = ()> + Send + 'static,
    {
        info!("delete queue: worker starting");
        let (ready_tx, mut ready_rx) = mpsc::channel(64);
        let metrics2 = metrics.clone();
        // The pending queue has the queued futures in it. When the future at
        // the head of the queue completes, its results are added to a ready
        // queue, and the next future awaited.
        let _ready_handle = ScopedTask::spawn(async move {
            while let Some(item) = rx.recv().await {
                match item {
                    PendingQueueItem::Work { f, fin_tx } => {
                        let keys = f.await;
                        if ready_tx
                            .send(ReadyQueueItem::Work { keys, fin_tx })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    PendingQueueItem::Shutdown { fin_tx } => {
                        let _ = ready_tx.send(ReadyQueueItem::Shutdown { fin_tx }).await;
                        return;
                    }
                }
                metrics2.gauge(
                    "store_client.merkle_delete.ready_queue_len",
                    ready_tx.max_capacity() - ready_tx.capacity(),
                    metrics::NO_TAGS,
                );
            }
        });
        const MAX_BATCH_SIZE: usize = 1024;

        while let Some(item) = ready_rx.recv().await {
            let mut shutdown = None;
            match item {
                ReadyQueueItem::Shutdown { fin_tx } => {
                    shutdown = Some(fin_tx);
                }
                ReadyQueueItem::Work {
                    keys: mut next,
                    fin_tx,
                } => {
                    // see if there are more that are ready.
                    let mut fin_txs = vec![fin_tx];
                    loop {
                        if let Ok(next_item) = ready_rx.try_recv() {
                            match next_item {
                                ReadyQueueItem::Shutdown { fin_tx } => {
                                    shutdown = Some(fin_tx);
                                }
                                ReadyQueueItem::Work {
                                    keys: more_keys,
                                    fin_tx,
                                } => {
                                    assert_eq!(next.realm, more_keys.realm);
                                    next.keys.extend(more_keys.keys);
                                    fin_txs.push(fin_tx);
                                    if next.keys.len() < MAX_BATCH_SIZE {
                                        continue;
                                    }
                                }
                            }
                        }
                        break;
                    }
                    metrics.gauge(
                        "store_client.merkle_delete.coalesced_num_batches",
                        fin_txs.len(),
                        [tag!("realm":?next.realm)],
                    );
                    metrics.gauge(
                        "store_client.merkle_delete.coalesced_num_keys",
                        next.keys.len(),
                        [tag!("realm":?next.realm)],
                    );
                    cb(next).await;
                    for fin_tx in fin_txs {
                        // This returns err if the receiver was already dropped, but we
                        // don't care.
                        let _ = fin_tx.send(());
                    }
                }
            }
            if let Some(fin_tx) = shutdown {
                info!("delete queue completed graceful shutdown");
                let _ = fin_tx.send(());
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;
    use std::collections::BTreeSet;
    use std::future;
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::{mpsc, oneshot};

    use super::*;
    use bitvec::bitvec;
    use hsm_core::hsm::MerkleHasher;
    use hsm_core::merkle::testing::{rec_id, TestHash};
    use hsm_core::merkle::NodeHashBuilder;

    #[test]
    fn store_key_starts_next() {
        let k = StoreKeyStart(vec![1, 3, 129]);
        assert_eq!(vec![1, 3, 130], k.next().0);
        assert_eq!(vec![1, 3, 131], k.next().next().0);

        let k = StoreKeyStart(vec![1, 2, 254]);
        assert_eq!(vec![1, 2, 255], k.next().0);
        assert_eq!(vec![1, 3, 0], k.next().next().0);

        let k = StoreKeyStart(vec![1, 255, 255, 255]);
        assert_eq!(vec![2, 0, 0, 0], k.next().0);
    }

    #[test]
    fn store_key_encoding() {
        let k = NodeKey::new(KeyVec::new(), TestHash([1u8; 8]));
        assert_eq!(
            [128u8, 1, 1, 1, 1, 1, 1, 1, 1].to_vec(),
            StoreKey::from(k).0
        );

        let k = NodeKey::new(bitvec![0], TestHash([1u8; 8]));
        assert_eq!(
            [0u8, 129, 1, 1, 1, 1, 1, 1, 1, 1].to_vec(),
            StoreKey::from(k).0
        );
        let k = NodeKey::new(bitvec![1], TestHash([4u8; 8]));
        assert_eq!(
            [64u8, 129, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            StoreKey::from(k).0
        );

        let k = NodeKey::new(bitvec![0, 1], TestHash([4u8; 8]));
        assert_eq!(
            [32u8, 130, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            StoreKey::from(k).0
        );

        let k = NodeKey::new(bitvec![1, 1, 1, 1, 1, 1, 1], TestHash([4u8; 8]));
        assert_eq!(
            [127u8, 135, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            StoreKey::from(k).0
        );
        let k = NodeKey::new(bitvec![1, 1, 1, 1, 1, 1, 1, 1], TestHash([4u8; 8]));
        assert_eq!(
            [127u8, 64, 129, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            StoreKey::from(k).0
        );
        let k = NodeKey::new(bitvec![1, 1, 1, 1, 1, 1, 1, 1, 1], TestHash([4u8; 8]));
        assert_eq!(
            [127u8, 96, 130, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            StoreKey::from(k).0
        );
    }

    #[test]
    fn bulk_prefix_encoding() {
        // cross check the bulk & single encoders
        let test = |r| {
            let prefixes = all_store_key_starts(&r);
            assert_eq!(257, prefixes.len());
            let k = r.to_bitvec();
            let mut buff = Vec::with_capacity(64);
            for (i, prefix) in prefixes.enumerate() {
                buff.clear();
                encode_prefix_into(&k.slice(..i).to_bitvec(), &mut buff);
                assert_eq!(buff, prefix.0, "with prefix len {i}");
            }
        };
        test(RecordId([0x00; RecordId::NUM_BYTES]));
        test(RecordId([0x01; RecordId::NUM_BYTES]));
        test(RecordId([0x5a; RecordId::NUM_BYTES]));
        test(RecordId([0xa5; RecordId::NUM_BYTES]));
        test(RecordId([0x7F; RecordId::NUM_BYTES]));
        test(RecordId([0x80; RecordId::NUM_BYTES]));
        test(RecordId([0xFE; RecordId::NUM_BYTES]));
        test(RecordId([0xFF; RecordId::NUM_BYTES]));
    }

    #[test]
    fn test_store_key_parse() {
        let prefix = bitvec![1, 0, 1];
        let hash = TestHash([1, 2, 3, 4, 5, 6, 7, 8]);
        let sk = StoreKey::new(&prefix, &hash);
        assert_eq!(vec![0b01010000, 128 | 3, 1, 2, 3, 4, 5, 6, 7, 8], sk.0);
        match StoreKey::parse::<TestHash>(&sk.0) {
            None => panic!("should have decoded store key"),
            Some((p, h)) => {
                assert_eq!(h, hash);
                assert_eq!(&[0b01010000, 128 | 3], p.0);
            }
        }
    }

    #[test]
    fn test_store_key_parse_empty_prefix() {
        let prefix = bitvec![];
        let hash = TestHash([1, 2, 3, 4, 5, 6, 7, 8]);
        let sk = StoreKey::new(&prefix, &hash);
        assert_eq!(vec![128, 1, 2, 3, 4, 5, 6, 7, 8], sk.0);
        match StoreKey::parse::<TestHash>(&sk.0) {
            None => panic!("should have decoded store key"),
            Some((p, h)) => {
                assert_eq!(h, hash);
                assert_eq!(&[128], p.0);
            }
        }
    }

    #[test]
    fn test_store_key_parse_bad_input() {
        assert!(StoreKey::parse::<TestHash>(&[0, 0, 128, 1, 2, 3, 4]).is_none());
        assert!(StoreKey::parse::<TestHash>(&[]).is_none());
        assert!(StoreKey::parse::<TestHash>(&[1, 2]).is_none());
        assert!(StoreKey::parse::<TestHash>(&[1, 2, 128 | 1]).is_none());
    }

    #[test]
    fn test_store_key_parse_data_hash() {
        let prefix = bitvec![0, 1, 1, 1];
        let hash = NodeHashBuilder::<MerkleHasher>::Leaf(&rec_id(&[1]), &[1, 2, 3, 4]).build();

        let sk = StoreKey::new(&prefix, &hash);
        match StoreKey::parse::<DataHash>(&sk.into_bytes()) {
            None => panic!("should have decoded store key"),
            Some((_p, h)) => {
                assert_eq!(h, hash);
            }
        }
    }

    const REALM1: RealmId = RealmId([
        0x66, 0x80, 0x13, 0x4b, 0xf4, 0x5d, 0xc9, 0x3f, 0xce, 0xee, 0xcd, 0x03, 0xe5, 0x38, 0xc8,
        0x9f,
    ]);

    #[test]
    fn test_merkle_table() {
        let instance = Instance {
            project: String::from("prj1"),
            instance: String::from("inst2"),
        };
        let expected =
            "projects/prj1/instances/inst2/tables/6680134bf45dc93fceeecd03e538c89f-merkle";
        assert_eq!(merkle_table(&instance, &REALM1), expected);
        assert_eq!(
            format!("{}/tables/{}", instance.path(), merkle_table_brief(&REALM1)),
            expected
        );
    }

    #[tokio::test]
    async fn test_delete_queue() {
        let (res_tx, mut res_rx) = mpsc::channel(1);
        let cb = move |keys: DeleteKeySet| {
            let res_tx = res_tx.clone();
            async move {
                res_tx.send(keys).await.unwrap();
            }
        };

        let keysets: Vec<DeleteKeySet> = (0..50)
            .map(|i| DeleteKeySet {
                realm: RealmId([1; 16]),
                keys: BTreeSet::from([NodeKey::new(bitvec![1], DataHash([i; 32]))]),
            })
            .collect();
        let q = MerkleDeleteQueue::new(metrics::Client::NONE, cb);
        let (tx, rx) = oneshot::channel();
        q.queue(rx.map(|r| r.unwrap()).boxed()).await.unwrap();

        let (tx2, rx2) = oneshot::channel();
        q.queue(rx2.map(|r| r.unwrap()).boxed()).await.unwrap();

        // flag the first one as ready
        assert_eq!(Err(TryRecvError::Empty), res_rx.try_recv());
        tx.send(keysets[0].clone()).unwrap();
        assert_eq!(keysets[0], res_rx.recv().await.unwrap());

        // now the 2nd one.
        tx2.send(keysets[1].clone()).unwrap();
        assert_eq!(keysets[1], res_rx.recv().await.unwrap());

        // check that it batches up ready ones.
        for keyset in &keysets {
            q.queue(future::ready(keyset.clone()).boxed())
                .await
                .unwrap();
        }
        // some number of these will end up in the first callback, which fills the res_rx channel.
        // some number of these will end up a 2nd callback which is then blocked on res_tx.send().
        // the remaining should end up in the ready channel and get bundled into a single callback.
        // depend on the scheduling, we may end up with these being split across 1, 2 or 3 callbacks.
        let mut cb1 = res_rx.recv().await.unwrap();
        if cb1.keys.len() < keysets.len() {
            let cb2 = res_rx.recv().await.unwrap();
            cb1.keys.extend(cb2.keys);
            if cb1.keys.len() < keysets.len() {
                let cb3 = res_rx.recv().await.unwrap();
                cb1.keys.extend(cb3.keys);
            }
        }
        let all: NodeKeySet<DataHash> = keysets
            .iter()
            .flat_map(|ks| ks.keys.iter().cloned())
            .collect();
        assert_eq!(all, cb1.keys);

        // put some pending working in the queue
        let (tx, rx) = oneshot::channel();
        q.queue(rx.map(|r| r.unwrap()).boxed()).await.unwrap();
        // ask the queue to shutdown
        let mut shutdown_handle = q.shutdown().await.unwrap();
        // the shutdown shouldn't complete yet
        assert_eq!(
            Err(oneshot::error::TryRecvError::Empty),
            shutdown_handle.try_recv()
        );
        // can't queue more work after starting shutdown
        let (_tx2, rx2) = oneshot::channel();
        assert_eq!(
            DeleteQueueError::Shutdown,
            q.queue(rx2.map(|r| r.unwrap()).boxed()).await.unwrap_err()
        );

        // let the pending item complete
        tx.send(keysets[0].clone()).unwrap();
        assert_eq!(keysets[0], res_rx.recv().await.unwrap());
        assert_eq!(Ok(()), shutdown_handle.await);
    }
}
