// We don't have a KV store integrated yet, so this takes its place.

use std::collections::HashMap;

use tracing::trace;

use super::super::hsm::types::{DataHash, RealmId};
use super::super::merkle::agent::{Node, StoreDelta, TreeStoreError, TreeStoreReader};

type Row = (Vec<u8>, Node<DataHash>);

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
            let enc = n.0.encoded_key();
            match nodes.binary_search_by(|i| i.0.cmp(&enc)) {
                Ok(idx) => nodes[idx] = (enc, n.1),
                Err(idx) => nodes.insert(idx, (enc, n.1)),
            }
        }
        for r in d.remove {
            let enc = r.encoded_key();
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
    fn fetch(&self, enc_key: &[u8]) -> Result<Vec<Node<DataHash>>, TreeStoreError> {
        let mut start = match self
            .nodes
            .binary_search_by(|item| item.0.as_slice().cmp(enc_key))
        {
            Ok(idx) => idx,
            Err(idx) => idx,
        };
        while start > 0 && self.nodes[start - 1].0.starts_with(enc_key) {
            start -= 1;
        }
        let mut end = start;
        while end < self.nodes.len() - 1 && self.nodes[end + 1].0.starts_with(enc_key) {
            end += 1;
        }
        Ok(self.nodes[start..=end]
            .iter()
            .map(|i| i.1.clone())
            .collect())
    }
}
