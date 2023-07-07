extern crate alloc;

use alloc::string::String;
use serde::{Deserialize, Serialize};

use super::{HashOutput, InteriorNode, KeyVec, LeafNode};
use crate::hash::{HashExt, HashMap, HashSet, NotRandomized};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Node<HO> {
    Interior(InteriorNode<HO>),
    Leaf(LeafNode),
}

#[derive(Debug)]
pub enum TreeStoreError {
    MissingNode,
    Network(String),
}

// This module encapsulates `StoreDelta` so that its invariants are maintained.
mod private {
    use super::{HashExt, HashMap, HashOutput, HashSet, Node, NodeKey, NotRandomized};
    use serde::{Deserialize, Serialize};

    /// A collection of changes to be made to a Merkle tree.
    ///
    /// Correct values of this struct have no overlap between nodes that are added
    /// and nodes that are removed.
    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct StoreDelta<HO: HashOutput> {
        /// New nodes to be added.
        ///
        /// This map doesn't need mitigation from HashDoS attacks because it's
        /// produced by the HSMs from Merkle tree modifications. The agents trust
        /// the HSMs. Plus, the node hashes do not depend on user input, since a
        /// random nonce is rolled up into them.
        ///
        /// It's best to avoid randomization here for performance. This and the
        /// `remove` set are created when processing every tree update.
        add: HashMap<NodeKey<HO>, Node<HO>, NotRandomized>,
        /// Existing nodes to be removed.
        remove: HashSet<NodeKey<HO>, NotRandomized>,
    }

    impl<HO: HashOutput> Default for StoreDelta<HO> {
        fn default() -> Self {
            Self {
                add: HashMap::new(),
                remove: HashSet::new(),
            }
        }
    }

    impl<HO: HashOutput> StoreDelta<HO> {
        pub fn adds(&self) -> &HashMap<NodeKey<HO>, Node<HO>, NotRandomized> {
            &self.add
        }

        pub fn removes(&self) -> &HashSet<NodeKey<HO>, NotRandomized> {
            &self.remove
        }

        /// Updates self with the changes described in other. Nodes that are added
        /// and then deleted by a subsequent squash are removed entirely. Squashing
        /// a number of StoreDelta's and then writing the result to storage is the
        /// same as applying the individual deltas to storage.
        pub fn squash(&mut self, other: StoreDelta<HO>) {
            self.add.extend(other.add);
            for k in other.remove {
                if self.add.remove(&k).is_none() {
                    self.remove.insert(k);
                }
            }
        }

        pub fn is_empty(&self) -> bool {
            self.add.is_empty() && self.remove.is_empty()
        }
    }

    #[derive(Default)]
    pub struct DeltaBuilder<HO> {
        to_add: HashMap<NodeKey<HO>, Node<HO>, NotRandomized>,
        to_remove: HashSet<NodeKey<HO>, NotRandomized>,
    }
    impl<HO: HashOutput> DeltaBuilder<HO> {
        pub fn new() -> Self {
            DeltaBuilder {
                to_add: HashMap::new(),
                to_remove: HashSet::new(),
            }
        }
        pub fn add(&mut self, key: NodeKey<HO>, n: Node<HO>) {
            self.to_add.insert(key, n);
        }
        pub fn remove(&mut self, key: NodeKey<HO>) {
            self.to_remove.insert(key);
        }
        pub fn build(mut self) -> StoreDelta<HO> {
            for (k, _) in &self.to_add {
                self.to_remove.remove(k);
            }
            StoreDelta {
                add: self.to_add,
                remove: self.to_remove,
            }
        }
    }
}

pub use private::{DeltaBuilder, StoreDelta};

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct NodeKey<HO> {
    // The full key prefix to the node
    pub prefix: KeyVec,
    pub hash: HO,
}
impl<HO: HashOutput> NodeKey<HO> {
    pub fn new(prefix: KeyVec, hash: HO) -> Self {
        Self { prefix, hash }
    }
}

#[cfg(test)]
pub mod tests {

    use crate::merkle::testing::{new_empty_tree, TestHash};

    use super::super::super::hsm::types::{OwnedRange, RecordId};
    use super::super::agent::StoreDelta;

    #[test]
    fn test_squash_deltas() {
        let range = OwnedRange::full();
        let (mut tree, init_root, mut store) = new_empty_tree(&range);
        let mut deltas = Vec::new();

        // insert some keys, collect the deltas
        let mut root = init_root;
        let mut d: StoreDelta<TestHash>;
        for key in (1..6).map(|i| RecordId([i; RecordId::NUM_BYTES])) {
            let rp = store.read(&range, &init_root, &key).unwrap();
            let vp = tree.latest_proof(rp).unwrap();
            (root, d) = tree.insert(vp, key.0.to_vec()).unwrap();
            deltas.push(d);
        }
        // squashing the deltas and applying it, or applying them individually should result in the same thing
        let mut squashed_store = store.clone();
        let mut squashed = deltas[0].clone();
        for d in &deltas[1..] {
            squashed.squash(d.clone());
        }
        assert!(squashed.adds().len() < deltas.iter().map(|d| d.adds().len()).sum());
        assert!(squashed.removes().len() < deltas.iter().map(|d| d.removes().len()).sum());
        squashed_store.apply_store_delta(root, squashed);

        for d in deltas.into_iter() {
            store.apply_store_delta(root, d);
        }
        assert_eq!(store, squashed_store);
    }
}
