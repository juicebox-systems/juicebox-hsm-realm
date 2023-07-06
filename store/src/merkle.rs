use async_trait::async_trait;
use google::bigtable::v2::row_range::{EndKey::EndKeyOpen, StartKey::StartKeyClosed};
use google::bigtable::v2::{
    mutate_rows_request, mutation, read_rows_request, row_filter, MutateRowsRequest, Mutation,
    ReadRowsRequest, RowFilter, RowRange, RowSet,
};
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tonic::Code;
use tracing::{instrument, trace, warn, Span};

use super::{mutate_rows, read_rows, Instance, MutateRowsError, StoreClient};
use agent_api::merkle::TreeStoreReader;
use hsmcore::bitvec::Bits;
use hsmcore::hash::{HashMap as HsmHashMap, HashSet as HsmHashSet, NotRandomized};
use hsmcore::hsm::cache;
use hsmcore::hsm::types::{DataHash, GroupId, RecordId};
use hsmcore::merkle::agent::{all_store_key_starts, Node, NodeKey, StoreKey, TreeStoreError};
use hsmcore::merkle::Dir;
use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_marshalling as marshalling;
use observability::metrics;
use observability::metrics_tag as tag;

/// Wrapper for [`Instant`] used in the Merkle node cache.
///
/// The cache can operate using a simple counter as a clock, but using a real
/// clock is useful for metrics. It gives the cache entries ages that are
/// meaningful to humans.
#[derive(Default)]
struct MonotonicClock;

impl cache::Clock for MonotonicClock {
    type Time = Instant;

    fn time(&mut self) -> Self::Time {
        Instant::now()
    }
}

/// Statistics for [`NodeCache`].
type CacheStats = cache::Stats<Instant>;

/// Non-threadsafe Merkle node cache.
type NodeCache =
    cache::Cache<StoreKey, Vec<u8>, MonotonicClock, std::collections::hash_map::RandomState>;

/// Sharable and cheaply cloneable Merkle node cache.
#[derive(Clone)]
pub struct Cache(Arc<Mutex<NodeCache>>);

impl Cache {
    pub fn new(limit: usize) -> Self {
        Self(Arc::new(Mutex::new(NodeCache::new(limit))))
    }
}

fn merkle_table(instance: &Instance, realm: &RealmId) -> String {
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

pub fn merkle_table_brief(realm: &RealmId) -> String {
    let mut buf = String::new();
    for byte in realm.0 {
        write!(buf, "{byte:02x}").unwrap();
    }
    write!(buf, "-merkle").unwrap();
    buf
}

impl StoreClient {
    #[instrument(level = "trace", skip(self, add), fields(retries))]
    pub(super) async fn write_merkle_nodes(
        &self,
        realm: &RealmId,
        group: &GroupId,
        add: &HsmHashMap<NodeKey<DataHash>, Node<DataHash>, NotRandomized>,
    ) -> Result<(), MutateRowsError> {
        if add.is_empty() {
            return Ok(());
        }

        let start = Instant::now();

        let make_new_merkle_entries = || {
            add.iter()
                .map(|(key, value)| mutate_rows_request::Entry {
                    row_key: key.store_key().into_bytes(),
                    mutations: vec![Mutation {
                        mutation: Some(mutation::Mutation::SetCell(mutation::SetCell {
                            family_name: String::from("f"),
                            column_qualifier: b"n".to_vec(),
                            timestamp_micros: -1,
                            value: marshalling::to_vec(value).expect("TODO"),
                        })),
                    }],
                })
                .collect::<Vec<_>>()
        };

        const MAX_RETRIES: usize = 3;
        for retries in 0.. {
            Span::current().record("retries", retries);
            let mut bigtable = self.bigtable.clone();
            match mutate_rows(
                &mut bigtable,
                MutateRowsRequest {
                    table_name: merkle_table(&self.instance, realm),
                    app_profile_id: String::new(),
                    entries: make_new_merkle_entries(),
                },
            )
            .await
            {
                Ok(_) => break,
                // Disconnect errors are buried under 'Unknown'. We'll only retry those.
                Err(MutateRowsError::Tonic(status)) if status.code() == Code::Unknown => {
                    warn!(
                        ?realm,
                        ?group,
                        ?status,
                        ?retries,
                        "Tonic error writing new merkle nodes"
                    );
                    self.metrics.incr(
                        "store_client.merkle_write.unknown_error",
                        [tag!(?realm), tag!(?group)],
                    );
                    if retries >= MAX_RETRIES {
                        return Err(MutateRowsError::Tonic(status));
                    }
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }

        let cache_stats = {
            let mut locked_cache = self.merkle_cache.0.lock().unwrap();
            for (key, value) in add {
                locked_cache.insert(key.store_key(), marshalling::to_vec(&value).expect("TODO"))
            }
            locked_cache.stats()
        };

        let tags = [tag!(?realm), tag!(?group)];
        report_cache_stats(&self.metrics, &tags, cache_stats);
        self.metrics.timing(
            "store_client.write_merkle_nodes.time",
            start.elapsed(),
            &tags,
        );
        Ok(())
    }

    #[instrument(level = "trace", skip(self, remove))]
    pub(super) async fn remove_merkle_nodes(
        &self,
        realm: &RealmId,
        group: &GroupId,
        remove: &HsmHashSet<NodeKey<DataHash>, NotRandomized>,
    ) -> Result<(), MutateRowsError> {
        if remove.is_empty() {
            return Ok(());
        }

        let start = Instant::now();

        let mut bigtable = self.bigtable.clone();
        let result = mutate_rows(
            &mut bigtable,
            MutateRowsRequest {
                table_name: merkle_table(&self.instance, realm),
                app_profile_id: String::new(),
                entries: remove
                    .iter()
                    .map(|k| mutate_rows_request::Entry {
                        row_key: k.store_key().into_bytes(),
                        mutations: vec![Mutation {
                            mutation: Some(mutation::Mutation::DeleteFromRow(
                                mutation::DeleteFromRow {},
                            )),
                        }],
                    })
                    .collect(),
            },
        )
        .await;

        let cache_stats = {
            let mut locked_cache = self.merkle_cache.0.lock().unwrap();
            for key in remove {
                locked_cache.remove(&key.store_key());
            }
            locked_cache.stats()
        };

        let tags = [tag!(?realm), tag!(?group)];
        report_cache_stats(&self.metrics, &tags, cache_stats);
        self.metrics.timing(
            "store_client.remove_merkle_nodes.time",
            start.elapsed(),
            &tags,
        );
        result
    }
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

        match cache.get(&key.store_key()) {
            None => {
                // Reached a cache miss.
                return CachedPathLookupResult {
                    nodes,
                    next: Some(key),
                };
            }

            Some(value) => {
                let node: Node<DataHash> = marshalling::from_slice(value).expect("TODO");

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

#[async_trait]
impl TreeStoreReader<DataHash> for StoreClient {
    #[instrument(level = "trace", skip(self), fields(num_result_nodes))]
    async fn path_lookup(
        &self,
        realm: &RealmId,
        record_id: &RecordId,
        root_hash: &DataHash,
        tags: &[metrics::Tag],
    ) -> Result<HashMap<DataHash, Node<DataHash>>, TreeStoreError> {
        let start = Instant::now();

        // Read as much as possible from the cache.
        let (cached_nodes, next) = {
            let result = {
                let mut locked_cache = self.merkle_cache.0.lock().unwrap();
                cached_path_lookup(record_id, root_hash, &mut locked_cache)
            };
            self.metrics.histogram(
                "store_client.path_lookup.cached_nodes_read",
                result.nodes.len() as i64,
                tags,
            );
            self.metrics.histogram(
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
                    self.metrics
                        .histogram("store_client.path_lookup.bigtable_nodes_read", 0, tags);
                    return Ok(cached_nodes.collect());
                }
                Some(next) => (cached_nodes, next),
            }
        };

        // Read the rest from Bigtable.
        let rows = read_rows(
            &mut self.bigtable.clone(),
            ReadRowsRequest {
                table_name: merkle_table(&self.instance, realm),
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
                    filter: Some(row_filter::Filter::CellsPerColumnLimitFilter(1)),
                }),
                rows_limit: 0,
                request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            },
        )
        .await
        .map_err(|e| TreeStoreError::Network(e.to_string()))?;

        // Extract the serialized key-value pairs from the rows.
        let read_values: Vec<(StoreKey, Vec<u8>)> = rows
            .into_iter()
            .map(|(row_key, cells)| {
                (
                    StoreKey::from(row_key.0),
                    cells
                        .into_iter()
                        .find(|cell| cell.family == "f" && cell.qualifier == b"n")
                        .expect("every Merkle row should contain a node value")
                        .value,
                )
            })
            .collect();

        self.metrics.histogram(
            "store_client.path_lookup.bigtable_nodes_read",
            read_values.len() as i64,
            tags,
        );

        // This is heavy-weight but useful for understanding how deep into the
        // tree extraneous reads are occurring.
        for (key, _) in &read_values {
            self.metrics.histogram(
                "store_client.path_lookup.bigtable_node.key_len",
                key.as_slice().len(),
                tags,
            );
        }

        // Collect up the combined superset of nodes to return.
        let nodes: HashMap<DataHash, Node<DataHash>> = cached_nodes
            .chain(read_values.iter().map(|(key, value)| {
                let (_, hash) = StoreKey::parse(key.as_slice()).expect("TODO");
                let node: Node<DataHash> = marshalling::from_slice(value).expect("TODO");
                (hash, node)
            }))
            .collect();

        // Update the cache with newly read values.
        if !read_values.is_empty() {
            let cache_stats = {
                let mut locked_cache = self.merkle_cache.0.lock().unwrap();
                for (key, value) in read_values {
                    locked_cache.insert(key, value);
                }
                locked_cache.stats()
            };
            report_cache_stats(&self.metrics, tags, cache_stats);
        }

        Span::current().record("num_result_nodes", nodes.len());
        self.metrics
            .timing("store_client.path_lookup.time", start.elapsed(), tags);
        Ok(nodes)
    }

    #[instrument(level = "trace", skip(self))]
    async fn read_node(
        &self,
        realm: &RealmId,
        key: StoreKey,
        tags: &[metrics::Tag],
    ) -> Result<Node<DataHash>, TreeStoreError> {
        trace!(realm = ?realm, key = ?key, "read_node starting");

        // Check the Merkle node cache first.
        {
            let mut locked_cache = self.merkle_cache.0.lock().unwrap();
            if let Some(value) = locked_cache.get(&key) {
                let node: Node<DataHash> = marshalling::from_slice(value).expect("TODO");
                return Ok(node);
            }
        }

        // Read from Bigtable.
        let rows = read_rows(
            &mut self.bigtable.clone(),
            ReadRowsRequest {
                table_name: merkle_table(&self.instance, realm),
                app_profile_id: String::new(),
                rows: Some(RowSet {
                    row_keys: vec![key.clone().into_bytes()],
                    row_ranges: Vec::new(),
                }),
                filter: Some(RowFilter {
                    filter: Some(row_filter::Filter::CellsPerColumnLimitFilter(1)),
                }),
                rows_limit: 0,
                request_stats_view: read_rows_request::RequestStatsView::RequestStatsNone.into(),
            },
        )
        .await
        .map_err(|e| TreeStoreError::Network(e.to_string()))?;

        match rows.into_iter().next().map(|(_key, cells)| {
            cells
                .into_iter()
                .find(|cell| cell.family == "f" && cell.qualifier == b"n")
                .expect("every Merkle row should contain a node value")
        }) {
            Some(cell) => {
                let node: Node<DataHash> = marshalling::from_slice(&cell.value).expect("TODO");
                trace!(?realm, ?key, "read_node completed");
                let cache_stats = {
                    let mut locked_cache = self.merkle_cache.0.lock().unwrap();
                    locked_cache.insert(key, cell.value);
                    locked_cache.stats()
                };
                report_cache_stats(&self.metrics, tags, cache_stats);
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

#[cfg(test)]
mod tests {
    use super::*;

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
