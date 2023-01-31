// We don't have a KV store integrated yet, so this takes its place.

use std::collections::HashMap;

use tracing::{trace, warn};

use super::super::hsm::types::{DataHash, RealmId};
use super::super::merkle::agent::{Node, StoreDelta, TreeStoreError, TreeStoreReader};

pub struct MemStore {
    realms: HashMap<RealmId, HashMap<DataHash, Node<DataHash>>>,
}
impl MemStore {
    pub fn new() -> MemStore {
        MemStore {
            realms: HashMap::new(),
        }
    }
    pub fn apply_store_delta(&mut self, realm: &RealmId, d: StoreDelta<DataHash>) {
        trace!(store =?self, ?realm, delta =?d);
        let nodes = self.realms.entry(*realm).or_insert_with(HashMap::new);

        for n in d.add {
            nodes.insert(n.hash(), n);
        }
        for r in d.remove {
            nodes.remove(&r);
        }
    }

    pub fn reader(&self, realm: &RealmId) -> impl TreeStoreReader<DataHash> + '_ {
        match self.realms.get(realm) {
            Some(nodes) => RealmTreeStoreReader { nodes },
            None => todo!(),
        }
    }
}
impl std::fmt::Debug for MemStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemStore {} realms", self.realms.len())
    }
}

struct RealmTreeStoreReader<'a> {
    nodes: &'a HashMap<DataHash, Node<DataHash>>,
}
impl<'a> TreeStoreReader<DataHash> for RealmTreeStoreReader<'a> {
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
