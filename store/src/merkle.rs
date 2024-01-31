use google::bigtable::admin::v2::table::TimestampGranularity;
use google::bigtable::admin::v2::{ColumnFamily, CreateTableRequest, GcRule, Table};
use google::bigtable::v2::row_filter::Chain;
use google::bigtable::v2::row_range::{EndKey::EndKeyOpen, StartKey::StartKeyClosed};
use google::bigtable::v2::{
    mutate_rows_request, mutation, read_rows_request, row_filter, MutateRowsRequest, Mutation,
    ReadRowsRequest, RowFilter, RowRange, RowSet,
};
use rand_core::OsRng;
use rand_core::RngCore;
use std::collections::{hash_map, BTreeMap, BTreeSet, HashMap};
use std::fmt::{Debug, Write};
use std::iter;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{instrument, trace, warn, Span};

use super::{base128, StoreClient};
use agent_api::merkle::{TreeStoreError, TreeStoreReader};
use bigtable::bigtable_retries;
use bigtable::mutate::{mutate_rows, MutateRowsError};
use bigtable::read::Reader;
use bigtable::{BigtableTableAdminClient, Instance};
use bitvec::Bits;
use hsm_api::merkle::{Dir, HashOutput, KeyVec, Node, NodeKey};
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

    #[instrument(level = "trace", skip(self, remove))]
    pub(super) async fn remove_merkle_nodes(
        &self,
        realm: &RealmId,
        group: &GroupId,
        remove: &BTreeSet<NodeKey<DataHash>>,
    ) -> Result<(), RetryError<MutateRowsError>> {
        if remove.is_empty() {
            return Ok(());
        }

        let tags = [tag!(?realm), tag!(?group)];
        let start = Instant::now();
        let mut to_fetch: HashMap<&StoreKey, &mut Option<InstanceId>> = HashMap::new();
        let mut nodes_to_delete: Vec<(&NodeKey<DataHash>, StoreKey, Option<InstanceId>)> = remove
            .iter()
            .map(|nk| (nk, StoreKey::from(nk), None))
            .collect();

        {
            // Grab the instance ids from the cache for the nodes we're going to delete.
            let mut locked_cache = self.0.merkle_cache.0.lock().unwrap();
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
                            ?realm,
                            ?group,
                            "merkle node not in cache, will read version from bigtable"
                        );
                        to_fetch.insert(sk, id);
                    }
                }
            }
        }
        self.0.metrics.distribution(
            "store_client.remove_merkle_nodes.versions_to_read",
            to_fetch.len(),
            &tags,
        );

        if !to_fetch.is_empty() {
            // Read any missing instance ids from bigtable
            let rows = Reader::read_rows(
                &mut self.0.bigtable.clone(),
                Retry::new("read merkle nodes instance_ids to delete")
                    .with(bigtable_retries)
                    .with_metrics(
                        &self.0.metrics,
                        "store_client.remove_merkle_nodes.read_versions",
                        &tags,
                    ),
                ReadRowsRequest {
                    table_name: merkle_table(&self.0.instance, realm),
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
            let mut bigtable = self.0.bigtable.clone();
            let rows = nodes_to_delete.clone();
            async move {
                mutate_rows(
                    &mut bigtable,
                    MutateRowsRequest {
                        table_name: merkle_table(&self.0.instance, realm),
                        app_profile_id: String::new(),
                        entries: rows
                            .into_iter()
                            .map(|(_, sk, v)| mutate_rows_request::Entry {
                                row_key: sk.into_bytes(),
                                mutations: vec![Mutation {
                                    mutation: Some(mutation::Mutation::DeleteFromColumn(
                                        mutation::DeleteFromColumn {
                                            family_name: String::from("f"),
                                            column_qualifier: v.unwrap().0.clone(),
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
                &self.0.metrics,
                "store_client.remove_merkle_nodes.delete",
                &tags,
            )
            .retry(run_delete, retry_logging!())
            .await;

        let cache_stats = {
            let mut locked_cache = self.0.merkle_cache.0.lock().unwrap();
            for (_, key, _) in nodes_to_delete {
                locked_cache.remove(&key);
            }
            locked_cache.stats()
        };

        report_cache_stats(&self.0.metrics, &tags, cache_stats);
        self.0.metrics.timing(
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

struct NodeWithInstanceId {
    node: Vec<u8>,
    instance_id: InstanceId,
}

struct CachedPathLookupResult {
    /// Cached nodes read along the path.
    nodes: Vec<(NodeKey<DataHash>, Node<DataHash>)>,
    /// - If None, the entire path was found in the cache. The returned `nodes`
    /// either prove the existence of the record and contain the leaf record,
    /// or they prove the non-existence of the record.
    /// - If Some, a necessary node was not found in the cache. The record may
    /// or may not exist in Bigtable.
    next: Option<NodeKey<DataHash>>,
}

/// Read from a given root towards a record in a Merkle node cache.
fn cached_path_lookup(
    record_id: &RecordId,
    root_hash: &DataHash,
    cache: &mut NodeCache,
) -> CachedPathLookupResult {
    let mut nodes = Vec::new();

    let full_key = record_id.to_bitvec();
    let mut key_pos = 0;

    let mut next_hash = root_hash.to_owned();

    loop {
        let key = NodeKey::new(full_key.slice(..key_pos).to_bitvec(), next_hash);

        match cache.get(&StoreKey::from(&key)) {
            None => {
                // Reached a cache miss.
                return CachedPathLookupResult {
                    nodes,
                    next: Some(key),
                };
            }

            Some(value) => {
                let node: Node<DataHash> = marshalling::from_slice(&value.node).expect("TODO");

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
                return CachedPathLookupResult { nodes, next: None };
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
                cached_path_lookup(record_id, root_hash, &mut locked_cache)
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
        let rows = Reader::read_rows(
            &mut self.0.bigtable.clone(),
            Retry::new("merkle tree path lookup")
                .with(bigtable_retries)
                .with_metrics(&self.0.metrics, "store_client.path_lookup", tags),
            ReadRowsRequest {
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
            },
        )
        .await
        .map_err(|e| TreeStoreError::Network(e.to_string()))?;

        // Extract the serialized key-value pairs from the rows.
        let read_values: Vec<(StoreKey, NodeWithInstanceId)> = rows
            .into_iter()
            .map(|(row_key, cells)| {
                (
                    StoreKey::from(row_key.0),
                    cells
                        .into_iter()
                        .find(|cell| cell.family == "f")
                        .map(|cell| NodeWithInstanceId {
                            node: cell.value,
                            instance_id: InstanceId(cell.qualifier),
                        })
                        .expect("every Merkle row should contain a node value"),
                )
            })
            .collect();

        self.0.metrics.distribution(
            "store_client.path_lookup.bigtable_nodes_read",
            read_values.len(),
            tags,
        );

        // This is heavy-weight but useful for understanding how deep into the
        // tree extraneous reads are occurring.
        for (key, _) in &read_values {
            self.0.metrics.distribution(
                "store_client.path_lookup.bigtable_node.key_len",
                key.as_slice().len(),
                tags,
            );
        }

        // Collect up the combined superset of nodes to return.
        let nodes: HashMap<DataHash, Node<DataHash>> = cached_nodes
            .chain(read_values.iter().map(|(key, value)| {
                let (_, hash) = StoreKey::parse(key.as_slice()).expect("TODO");
                let node: Node<DataHash> = marshalling::from_slice(&value.node).expect("TODO");
                (hash, node)
            }))
            .collect();

        // Update the cache with newly read values.
        if !read_values.is_empty() {
            let cache_stats = {
                let mut locked_cache = self.0.merkle_cache.0.lock().unwrap();
                for (key, value) in read_values {
                    locked_cache.insert(key, value);
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

#[cfg(test)]
mod tests {
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
}
