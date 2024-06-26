extern crate alloc;

use core::{fmt::Debug, hash::Hasher};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;

use super::{NodeHashBuilder, NodeHasher, Tree};
use crate::hash::{HashExt, HashMap, NotRandomized};
use crate::merkle::InteriorNodeExt;
use bitvec::Bits;
use hsm_api::merkle::{
    Dir, HashOutput, InteriorNode, KeyVec, Node, NodeKey, ReadProof, StoreDelta,
};
use hsm_api::{OwnedRange, RecordId};
use juicebox_marshalling::bytes;

pub fn new_empty_tree(range: &OwnedRange) -> (Tree<TestHasher>, TestHash, MemStore<TestHash>) {
    let (root_hash, delta) = Tree::<TestHasher>::new_tree(range);
    let mut store = MemStore::new();
    store.apply_store_delta(root_hash, delta);
    assert_eq!(1, store.nodes.len());
    check_tree_invariants::<TestHasher>(range, root_hash, &store);
    let t = Tree::with_existing_root(root_hash, 15);
    (t, root_hash, store)
}

// helper to insert a value into the tree and update the store
pub fn tree_insert(
    tree: &mut Tree<TestHasher>,
    store: &mut MemStore<TestHash>,
    range: &OwnedRange,
    root: TestHash,
    key: &RecordId,
    val: Vec<u8>,
    skip_tree_check: bool,
) -> TestHash {
    // spot stupid test bugs
    assert!(range.contains(key), "test bug, key not inside key range");
    let rp = store.read(range, &root, key).unwrap();
    let vp = tree.latest_proof(rp).unwrap();
    let (new_root, d) = tree.insert(vp, val).unwrap();
    store.apply_store_delta(new_root, d);

    if !skip_tree_check {
        check_tree_invariants::<TestHasher>(range, new_root, store);
    }
    new_root
}

// Walks the tree starting at root verifying all the invariants are all true
//      1. only the root may have an empty branch
//      2. the left branch prefix always starts with a 0
//      3. the right branch prefix always starts with a 1
//      5. the leaf -> root hashes are verified.
pub fn check_tree_invariants<H: NodeHasher>(
    range: &OwnedRange,
    root: H::Output,
    store: &MemStore<H::Output>,
) {
    let root_hash = check_tree_node_invariants::<H>(range, true, root, KeyVec::new(), store);
    assert_eq!(root_hash, root);
}

fn check_tree_node_invariants<H: NodeHasher>(
    range: &OwnedRange,
    is_at_root: bool,
    node: H::Output,
    path: KeyVec,
    store: &MemStore<H::Output>,
) -> H::Output {
    match store
        .get_node(&node)
        .unwrap_or_else(|_| panic!("node with hash {node:?} should exist"))
    {
        Node::Leaf(l) => {
            NodeHashBuilder::<H>::Leaf(&RecordId::from_bitvec(&path), &l.value).build()
        }
        Node::Interior(int) => {
            match &int.left {
                None => assert!(is_at_root),
                Some(b) => {
                    assert!(!b.prefix.is_empty());
                    assert!(!b.prefix[0]);
                    let new_path = path.concat(&b.prefix);
                    let exp_child_hash =
                        check_tree_node_invariants::<H>(range, false, b.hash, new_path, store);
                    assert_eq!(exp_child_hash, b.hash);
                }
            }
            match &int.right {
                None => assert!(is_at_root),
                Some(b) => {
                    assert!(!b.prefix.is_empty());
                    assert!(b.prefix[0]);
                    let new_path = path.concat(&b.prefix);
                    let exp_child_hash =
                        check_tree_node_invariants::<H>(range, false, b.hash, new_path, store);
                    assert_eq!(exp_child_hash, b.hash);
                }
            }
            let exp_hash = InteriorNode::calc_hash::<H>(range, is_at_root, &int.left, &int.right);
            assert_eq!(exp_hash, node);
            exp_hash
        }
    }
}

pub fn check_delta_invariants<HO: HashOutput>(root: HO, delta: &StoreDelta<HO>) {
    let add_by_hash: HashMap<HO, (&NodeKey<HO>, &Node<HO>)> =
        delta.adds().iter().map(|(k, n)| (k.hash, (k, n))).collect();
    assert_eq!(
        add_by_hash.len(),
        delta.adds().len(),
        "hash is repeated in delta.add"
    );

    for k in delta.removes() {
        let added = add_by_hash.get(&k.hash);
        if added.is_some() {
            panic!("add & remove contains same hash");
        }
    }
    fn verify_prefixes<HO: HashOutput>(
        add_by_hash: &HashMap<HO, (&NodeKey<HO>, &Node<HO>)>,
        prefix: KeyVec,
        hash: &HO,
    ) {
        let n = match add_by_hash.get(hash) {
            Some(n) => n,
            // Interior nodes in the update will point to existing items that weren't
            // updated so aren't in the delta.
            None => return,
        };
        assert_eq!(prefix, n.0.prefix);
        match n.1 {
            Node::Interior(int) => {
                if let Some(b) = &int.left {
                    verify_prefixes(add_by_hash, prefix.concat(&b.prefix), &b.hash);
                }
                if let Some(b) = &int.right {
                    verify_prefixes(add_by_hash, prefix.concat(&b.prefix), &b.hash);
                }
            }
            Node::Leaf(_l) => {
                assert_eq!(n.0.prefix.len(), RecordId::NUM_BITS);
            }
        }
    }
    verify_prefixes(&add_by_hash, KeyVec::new(), &root);
}

#[derive(Default)]
pub struct TestHasher(DefaultHasher);

impl NodeHasher for TestHasher {
    type Output = TestHash;

    fn update(&mut self, d: &[u8]) {
        self.0.write(d);
    }

    fn finalize(self) -> TestHash {
        TestHash(self.0.finish().to_le_bytes())
    }
}

#[derive(Clone, Copy, Ord, PartialEq, PartialOrd, Deserialize, Eq, Hash, Serialize)]
pub struct TestHash(#[serde(with = "bytes")] pub [u8; 8]);

impl HashOutput for TestHash {
    fn zero() -> TestHash {
        TestHash([0; 8])
    }
    fn from_slice(bytes: &[u8]) -> Option<TestHash> {
        if bytes.len() == 8 {
            let mut h = TestHash([0u8; 8]);
            h.0.copy_from_slice(bytes);
            Some(h)
        } else {
            None
        }
    }
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Debug for TestHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.as_slice() {
            write!(f, "{:02x}", *b)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemStore<HO: core::hash::Hash + Eq> {
    nodes: HashMap<HO, Node<HO>, NotRandomized>,
}

#[derive(Debug)]
pub enum MemStoreError {
    MissingNode,
}

impl<HO: HashOutput> Default for MemStore<HO> {
    fn default() -> Self {
        Self::new()
    }
}

impl<HO: HashOutput> MemStore<HO> {
    fn new() -> Self {
        MemStore {
            nodes: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn add_from_other_store(&mut self, other: MemStore<HO>) {
        self.nodes.extend(other.nodes);
    }

    pub fn apply_store_delta(&mut self, new_root: HO, d: StoreDelta<HO>) {
        check_delta_invariants(new_root, &d);
        for (k, n) in d.adds() {
            self.nodes.insert(k.hash, n.clone());
        }
        for k in d.removes() {
            self.nodes.remove(&k.hash);
        }
    }

    pub fn get_node(&self, hash: &HO) -> Result<Node<HO>, MemStoreError> {
        match self.nodes.get(hash) {
            Some(n) => Ok(n.clone()),
            None => Err(MemStoreError::MissingNode),
        }
    }

    pub fn read(
        &self,
        range: &OwnedRange,
        root_hash: &HO,
        k: &RecordId,
    ) -> Result<ReadProof<HO>, MemStoreError> {
        let root = match self.get_node(root_hash)? {
            Node::Leaf(_) => panic!("found unexpected leaf node"),
            Node::Interior(int) => int,
        };
        let mut res = super::proof::new(k.clone(), range.clone(), *root_hash, root);
        let keyv = k.to_bitvec();
        let mut key = keyv.as_ref();
        loop {
            let n = res.path.last().unwrap();
            let d = Dir::from(key[0]);
            match n.branch(d) {
                None => return Ok(res),
                Some(b) => {
                    if !key.starts_with(&b.prefix) {
                        return Ok(res);
                    }
                    key = key.slice(b.prefix.len()..);
                    match self.nodes.get(&b.hash) {
                        None => return Err(MemStoreError::MissingNode),
                        Some(Node::Interior(int)) => {
                            res.path.push(int.clone());
                            continue;
                        }
                        Some(Node::Leaf(v)) => {
                            assert!(key.is_empty());
                            res.leaf = Some(v.clone());
                            return Ok(res);
                        }
                    }
                }
            }
        }
    }

    // Reads down the tree from the root always following one side until a leaf is reached.
    // Needed for merge.
    pub fn read_tree_side(
        &self,
        range: &OwnedRange,
        root_hash: &HO,
        side: Dir,
    ) -> Result<ReadProof<HO>, MemStoreError> {
        let mut path = Vec::new();
        let mut key = KeyVec::new();
        let mut current = *root_hash;
        loop {
            match self.nodes.get(&current) {
                None => panic!("node with hash {current:?} should exist"),
                Some(Node::Interior(int)) => match int.branch(side) {
                    None => match int.branch(side.opposite()) {
                        None => {
                            path.push(int.clone());
                            let k = if side == Dir::Right {
                                &range.end
                            } else {
                                &range.start
                            };
                            // TODO, should we remove key from ReadProof?
                            // this key is not a full key in this event.
                            // this can only happen for the root node.
                            return Ok(ReadProof {
                                key: k.clone(),
                                range: range.clone(),
                                root_hash: *root_hash,
                                leaf: None,
                                path,
                            });
                        }
                        Some(b) => {
                            current = b.hash;
                            key.extend(&b.prefix);
                            path.push(int.clone());
                            continue;
                        }
                    },
                    Some(b) => {
                        current = b.hash;
                        key.extend(&b.prefix);
                        path.push(int.clone());
                        continue;
                    }
                },
                Some(Node::Leaf(l)) => {
                    return Ok(ReadProof {
                        key: RecordId::from_bitvec(&key),
                        range: range.clone(),
                        root_hash: *root_hash,
                        leaf: Some(l.clone()),
                        path,
                    });
                }
            }
        }
    }
}
