// We don't have a KV store integrated yet, so this takes its place.

use std::collections::HashMap;

use tracing::{trace, warn};

use super::super::super::realm::hsm::types::DataHash;
use super::super::merkle::agent::{Node, StoreDelta, TreeStoreError, TreeStoreReader};

pub struct MemStore {
    nodes: HashMap<DataHash, Node<DataHash>>,
}
impl MemStore {
    pub fn new() -> MemStore {
        MemStore {
            nodes: HashMap::new(),
        }
    }
    pub fn apply_store_delta(&mut self, d: StoreDelta<DataHash>) {
        trace!(store =?self, delta =?d);
        for n in d.add {
            self.nodes.insert(n.hash(), n);
        }
        for r in d.remove {
            self.nodes.remove(&r);
        }
    }
}
impl std::fmt::Debug for MemStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemStore {} nodes", self.nodes.len())
    }
}

impl TreeStoreReader<DataHash> for MemStore {
    fn fetch(&self, k: &DataHash) -> Result<Node<DataHash>, TreeStoreError> {
        match self.nodes.get(k) {
            None => {
                warn!(hash=?k, "failed to find node");
                Err(TreeStoreError::MissingNode)
            }
            Some(n) => Ok(n.clone()),
        }
    }
}
