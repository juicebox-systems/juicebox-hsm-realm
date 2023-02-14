// We don't have a KV store integrated yet, so this takes its place.

use std::collections::HashMap;

use tracing::trace;

use super::super::hsm::types::{DataHash, RealmId};
use super::super::merkle::{
    agent::{Node, StoreDelta, StoreKey, StoreKeyStart, TreeStoreError, TreeStoreReader},
    KeyVec,
};

type Row = (StoreKey, Node<DataHash>);

pub struct MemStore {
    realms: HashMap<RealmId, Vec<Row>>,
}
impl MemStore {
    pub fn new() -> MemStore {
        MemStore {
            realms: HashMap::new(),
        }
    }
    pub fn apply_store_delta(&mut self, realm: &RealmId, d: StoreDelta<DataHash>) {
        trace!(store =?self, ?realm, delta =?d);
        let nodes = self.realms.entry(*realm).or_insert_with(Vec::new);
        for n in d.add {
            assert_eq!(n.0.hash, n.1.hash());
            let enc = n.0.store_key();
            match nodes.binary_search_by(|i| i.0.cmp(&enc)) {
                Ok(idx) => nodes[idx] = (enc, n.1),
                Err(idx) => nodes.insert(idx, (enc, n.1)),
            }
        }
        for r in d.remove {
            let enc = r.store_key();
            if let Ok(idx) = nodes.binary_search_by(|i| i.0.cmp(&enc)) {
                nodes.remove(idx);
            }
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
    nodes: &'a Vec<Row>,
}
impl<'a> TreeStoreReader<DataHash> for RealmTreeStoreReader<'a> {
    fn range(&self, key_start: &StoreKeyStart) -> Result<Vec<Node<DataHash>>, TreeStoreError> {
        let mut start = match self
            .nodes
            .binary_search_by(|item| item.0.cmp_start(key_start))
        {
            Ok(idx) => idx,
            Err(idx) => idx,
        };
        while start > 0 && self.nodes[start - 1].0.starts_with(key_start) {
            start -= 1;
        }
        let mut end = start;
        while end < self.nodes.len() - 1 && self.nodes[end + 1].0.starts_with(key_start) {
            end += 1;
        }
        Ok(self.nodes[start..=end]
            .iter()
            .map(|i| i.1.clone())
            .collect())
    }
    fn fetch(&self, prefix: KeyVec, hash: DataHash) -> Result<Node<DataHash>, TreeStoreError> {
        let k = StoreKey::new(prefix, hash);
        match self.nodes.binary_search_by(|item| item.0.cmp(&k)) {
            Ok(idx) => Ok(self.nodes[idx].1.clone()),
            Err(_) => Err(TreeStoreError::MissingNode),
        }
    }
}
