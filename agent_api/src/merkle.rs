use async_trait::async_trait;
use std::collections::HashMap;

use hsmcore::hsm::types::RecordId;
use hsmcore::merkle::agent::{Node, StoreKey, TreeStoreError};
use juicebox_sdk_core::types::RealmId;
use observability::metrics;

/// Interface to read Merkle nodes, primarily used by the functions below. The
/// only implementation is [`crate::realm::store::bigtable::StoreClient`].
#[async_trait]
pub trait TreeStoreReader<HO>: Sync {
    /// Reads and returns all the nodes on the path from the root to
    /// `RecordId`.
    ///
    /// This may return extraneous nodes, including stale versions of nodes.
    async fn path_lookup(
        &self,
        realm_id: &RealmId,
        record_id: &RecordId,
        root_hash: &HO,
        tags: &[metrics::Tag],
    ) -> Result<HashMap<HO, Node<HO>>, TreeStoreError>;

    /// Reads and returns a specific version of a single node.
    ///
    /// This is used for infrequent Merkle tree operations like merge and
    /// split.
    async fn read_node(
        &self,
        realm_id: &RealmId,
        key: StoreKey,
        tags: &[metrics::Tag],
    ) -> Result<Node<HO>, TreeStoreError>;
}
