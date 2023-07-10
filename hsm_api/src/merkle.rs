use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

use bitvec::{BitSlice, BitVec, Bits};
use juicebox_sdk_marshalling::bytes;

pub type KeyVec = BitVec;
pub type KeySlice<'a> = BitSlice<'a>;

pub trait HashOutput: Copy + fmt::Debug + Eq + core::hash::Hash + Ord + Sync + Send {
    fn zero() -> Self;
    fn from_slice(bytes: &[u8]) -> Option<Self>;
    fn as_slice(&self) -> &[u8];
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NodeKey<HO> {
    // The full key prefix to the node
    pub prefix: KeyVec,
    pub hash: HO,
}

impl<HO> NodeKey<HO> {
    pub fn new(prefix: KeyVec, hash: HO) -> Self {
        Self { prefix, hash }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Node<HO> {
    Interior(InteriorNode<HO>),
    Leaf(LeafNode),
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeafNode {
    #[serde(with = "bytes")]
    pub value: Vec<u8>,
}

impl fmt::Debug for LeafNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LeafNode")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InteriorNode<HO> {
    pub left: Option<Branch<HO>>,
    pub right: Option<Branch<HO>>,
}

impl<HO> InteriorNode<HO> {
    pub fn new(left: Option<Branch<HO>>, right: Option<Branch<HO>>) -> Self {
        Branch::assert_dir(&left, Dir::Left);
        Branch::assert_dir(&right, Dir::Right);
        InteriorNode { left, right }
    }

    pub fn branch(&self, dir: Dir) -> &Option<Branch<HO>> {
        match dir {
            Dir::Left => &self.left,
            Dir::Right => &self.right,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct Branch<HO> {
    pub prefix: KeyVec,
    pub hash: HO,
}

impl<HO> Branch<HO> {
    pub fn new(prefix: KeyVec, hash: HO) -> Self {
        Branch { prefix, hash }
    }

    pub fn dir(&self) -> Dir {
        Dir::from(self.prefix[0])
    }

    pub fn assert_dir(b: &Option<Branch<HO>>, d: Dir) {
        if let Some(b) = b {
            assert!(!b.prefix.is_empty());
            assert_eq!(d, b.dir(), "{:?} prefix is invalid {}", d, b.prefix);
        }
    }
}

impl<HO: fmt::Debug> fmt::Debug for Branch<HO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} -> {:?}", &self.prefix, self.hash)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Dir {
    Left,
    Right,
}

impl Dir {
    pub fn from(bit: bool) -> Self {
        match bit {
            true => Dir::Right,
            false => Dir::Left,
        }
    }
    pub fn opposite(&self) -> Self {
        match self {
            Dir::Left => Dir::Right,
            Dir::Right => Dir::Left,
        }
    }
}

impl fmt::Display for Dir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dir::Left => f.write_str("Left"),
            Dir::Right => f.write_str("Right"),
        }
    }
}

/// A proof that a record exists or doesn't exist in a Merkle tree.
///
/// This includes the record itself, if it exists.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReadProof<HO> {
    /// The lookup key in the Merkle tree.
    pub key: RecordId,
    /// The range of record IDs stored in the tree that the proof was read
    /// from.
    pub range: OwnedRange,
    /// The leaf containing the record, if it exists.
    pub leaf: Option<LeafNode>,
    /// The path in root-to-leaf order of the nodes traversed to get to the
    /// leaf. If the leaf doesn't exist, this includes the furthest existing
    /// node in the path of the key.
    pub path: Vec<InteriorNode<HO>>,
    /// The hash of the root node.
    pub root_hash: HO,
}

// This module encapsulates `StoreDelta` so that its invariants are maintained.
mod private {
    extern crate alloc;

    use super::{HashOutput, Node, NodeKey};
    use alloc::collections::{BTreeMap, BTreeSet};
    use serde::{Deserialize, Serialize};

    /// A collection of changes to be made to a Merkle tree.
    ///
    /// Correct values of this struct have no overlap between nodes that are added
    /// and nodes that are removed.
    #[derive(Clone, Debug, Deserialize, Serialize)]
    pub struct StoreDelta<HO: HashOutput> {
        /// New nodes to be added.
        add: BTreeMap<NodeKey<HO>, Node<HO>>,
        /// Existing nodes to be removed.
        remove: BTreeSet<NodeKey<HO>>,
    }

    impl<HO: HashOutput> Default for StoreDelta<HO> {
        fn default() -> Self {
            Self {
                add: BTreeMap::new(),
                remove: BTreeSet::new(),
            }
        }
    }

    impl<HO: HashOutput> StoreDelta<HO> {
        pub fn adds(&self) -> &BTreeMap<NodeKey<HO>, Node<HO>> {
            &self.add
        }

        pub fn removes(&self) -> &BTreeSet<NodeKey<HO>> {
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
        to_add: BTreeMap<NodeKey<HO>, Node<HO>>,
        to_remove: BTreeSet<NodeKey<HO>>,
    }
    impl<HO: HashOutput> DeltaBuilder<HO> {
        pub fn new() -> Self {
            DeltaBuilder {
                to_add: BTreeMap::new(),
                to_remove: BTreeSet::new(),
            }
        }
        pub fn add(&mut self, key: NodeKey<HO>, n: Node<HO>) {
            self.to_add.insert(key, n);
        }
        pub fn remove(&mut self, key: NodeKey<HO>) {
            self.to_remove.insert(key);
        }
        pub fn build(mut self) -> StoreDelta<HO> {
            for k in self.to_add.keys() {
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

use crate::{OwnedRange, RecordId};
