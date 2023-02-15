// We don't have a KV store integrated yet, so this takes its place.

use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use tracing::trace;

use super::super::hsm::types::{DataHash, RealmId};
use super::super::merkle::{
    agent::{Node, StoreDelta, StoreKey, StoreKeyStart, TreeStoreError, TreeStoreReader},
    KeyVec,
};

pub struct MemStore {
    realms: HashMap<RealmId, BTreeMap<Vec<u8>, Node<DataHash>>>,
}
impl MemStore {
    pub fn new() -> MemStore {
        MemStore {
            realms: HashMap::new(),
        }
    }
    pub fn apply_store_delta(&mut self, realm: &RealmId, d: StoreDelta<DataHash>) {
        trace!(store =?self, ?realm, delta =?d);
        let nodes = self.realms.entry(*realm).or_insert_with(BTreeMap::new);
        for n in d.add {
            assert_eq!(n.0.hash, n.1.hash());
            let enc = n.0.store_key();
            nodes.insert(enc.into_bytes(), n.1);
        }
        for r in d.remove {
            let enc = r.store_key().into_bytes();
            nodes.remove(&enc);
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
    nodes: &'a BTreeMap<Vec<u8>, Node<DataHash>>,
}
#[async_trait]
impl<'a> TreeStoreReader<DataHash> for RealmTreeStoreReader<'a> {
    async fn range(&self, key_start: StoreKeyStart) -> Result<Vec<Node<DataHash>>, TreeStoreError> {
        let start = key_start.clone();
        let end = key_start.next();
        Ok(self
            .nodes
            .range(start.into_bytes()..end.into_bytes())
            .map(|i| i.1.clone())
            .collect())
    }
    async fn fetch(
        &self,
        prefix: KeyVec,
        hash: DataHash,
    ) -> Result<Node<DataHash>, TreeStoreError> {
        let k = StoreKey::new(prefix, hash);
        match self.nodes.get(&k.into_bytes()) {
            Some(n) => Ok(n.clone()),
            None => Err(TreeStoreError::MissingNode),
        }
    }
}
