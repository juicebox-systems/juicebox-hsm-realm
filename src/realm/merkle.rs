use bitvec::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    cmp::min,
    fmt::{Debug, Display},
    hash::Hash,
    iter::zip,
};

use self::{
    agent::{DeltaBuilder, Node, NodeKey, StoreDelta},
    overlay::TreeOverlay,
    proof::{ProofError, ReadProof, VerifiedProof},
};
use super::hsm::types::{OwnedRange, RecordId};

pub mod agent;
mod base128;
mod insert;
mod merge;
mod overlay;
pub mod proof;
mod split;

pub type KeyVec = BitVec<u8, Msb0>;
pub type KeySlice = BitSlice<u8, Msb0>;

// TODO
//  probably a bunch of stuff that should be pub but isn't
//  blake hasher
//
//  compact_keyslice_str should be a wrapper type?
//  remove hash from nodes rely on hash being in parent?
//  docs
//  more tests

pub struct Tree<H: NodeHasher<HO>, HO> {
    hasher: H,
    overlay: TreeOverlay<HO>,
}
impl<H: NodeHasher<HO>, HO: HashOutput> Tree<H, HO> {
    // Creates a new empty tree for the indicated partition. Returns the root
    // hash along with the storage delta required to create the tree.
    //
    // A typical read/write cycle to the tree looks like:
    //      Get a read proof from the store
    //      Call latest_proof to access the latest value of the key
    //      Use the value, possibly generating a new value to update the tree with
    //      Use the latest_proof result to call insert to put the updated value in the tree.
    //      Apply the store delta returned from insert to storage. Keep track of what
    //      the new root hash is.
    pub fn new_tree(hasher: &H, key_range: &OwnedRange) -> (HO, StoreDelta<HO>) {
        let root = InteriorNode::new(hasher, key_range, true, None, None);
        let hash = root.hash;
        let mut delta = DeltaBuilder::new();
        delta.add(NodeKey::new(KeyVec::new(), root.hash), Node::Interior(root));
        (hash, delta.build())
    }

    // Create a new Tree instance for a previously constructed tree given the root hash
    // of the tree's content.
    pub fn with_existing_root(hasher: H, root: HO) -> Self {
        Tree {
            hasher,
            overlay: TreeOverlay::new(root, 15),
        }
    }

    // Return a verified proof that was updated to the latest tree from the overlay.
    // This allows access to the current value, as well as being able to call insert later
    // to update the value in the tree.
    pub fn latest_proof(&self, rp: ReadProof<HO>) -> Result<VerifiedProof<HO>, ProofError> {
        rp.verify(&self.hasher, &self.overlay)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InteriorNode<HO> {
    left: Option<Branch<HO>>,
    right: Option<Branch<HO>>,
    hash: HO,
}
impl<HO: HashOutput> InteriorNode<HO> {
    fn new<H: NodeHasher<HO>>(
        h: &H,
        key_range: &OwnedRange,
        is_root: bool,
        left: Option<Branch<HO>>,
        right: Option<Branch<HO>>,
    ) -> InteriorNode<HO> {
        Branch::assert_dir(&left, Dir::Left);
        Branch::assert_dir(&right, Dir::Right);
        let hash = Self::calc_hash(h, key_range, is_root, &left, &right);
        InteriorNode { left, right, hash }
    }
    // construct returns a new InteriorNode with the supplied children. It will determine
    // which should be left and right. If you know which should be left & right use new instead.
    // TODO: get rid of new and always use this?
    fn construct<H: NodeHasher<HO>>(
        h: &H,
        key_range: &OwnedRange,
        is_root: bool,
        a: Option<Branch<HO>>,
        b: Option<Branch<HO>>,
    ) -> InteriorNode<HO> {
        match (&a, &b) {
            (None, None) => Self::new(h, key_range, is_root, None, None),
            (Some(x), _) => {
                let (l, r) = if x.dir() == Dir::Left { (a, b) } else { (b, a) };
                Self::new(h, key_range, is_root, l, r)
            }
            (_, Some(x)) => {
                let (l, r) = if x.dir() == Dir::Left { (b, a) } else { (a, b) };
                Self::new(h, key_range, is_root, l, r)
            }
        }
    }
    fn calc_hash<H: NodeHasher<HO>>(
        h: &H,
        key_range: &OwnedRange,
        is_root: bool,
        left: &Option<Branch<HO>>,
        right: &Option<Branch<HO>>,
    ) -> HO {
        let mut parts: [&[u8]; 6] = [&[], &[], &[], &[], &[], &[]];

        if is_root {
            parts[0] = &key_range.start.0;
            parts[1] = &key_range.end.0;
        }
        let left_p: Vec<u8>;
        if let Some(b) = left {
            left_p = b.prefix.iter().map(|b| if *b { 0xFF } else { 0 }).collect();
            parts[2] = &left_p;
            parts[3] = b.hash.as_u8();
        }
        let right_p: Vec<u8>;
        if let Some(b) = right {
            right_p = b.prefix.iter().map(|b| if *b { 0xFF } else { 0 }).collect();
            parts[4] = &right_p;
            parts[5] = b.hash.as_u8();
        }
        h.calc_hash(&parts)
    }
    fn branch(&self, dir: Dir) -> &Option<Branch<HO>> {
        match dir {
            Dir::Left => &self.left,
            Dir::Right => &self.right,
        }
    }
    fn root_with_new_partition<H: NodeHasher<HO>>(
        &self,
        h: &H,
        key_range: &OwnedRange,
    ) -> InteriorNode<HO> {
        InteriorNode::new(h, key_range, true, self.left.clone(), self.right.clone())
    }
    fn with_new_child<H: NodeHasher<HO>>(
        &self,
        h: &H,
        key_range: &OwnedRange,
        is_root: bool,
        dir: Dir,
        child: Branch<HO>,
    ) -> InteriorNode<HO> {
        match dir {
            Dir::Left => InteriorNode::new(h, key_range, is_root, Some(child), self.right.clone()),
            Dir::Right => InteriorNode::new(h, key_range, is_root, self.left.clone(), Some(child)),
        }
    }
    fn with_new_child_hash<H: NodeHasher<HO>>(
        &self,
        h: &H,
        key_range: &OwnedRange,
        is_root: bool,
        dir: Dir,
        hash: HO,
    ) -> InteriorNode<HO> {
        let b = self.branch(dir).as_ref().unwrap();
        let nb = Branch::new(b.prefix.clone(), hash);
        self.with_new_child(h, key_range, is_root, dir, nb)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LeafNode<HO> {
    pub value: Vec<u8>,
    pub hash: HO,
}
impl<HO> LeafNode<HO> {
    fn new<H: NodeHasher<HO>>(hasher: &H, k: &RecordId, v: Vec<u8>) -> LeafNode<HO> {
        let h = Self::calc_hash(hasher, k, &v);
        LeafNode { value: v, hash: h }
    }
    fn calc_hash<H: NodeHasher<HO>>(hasher: &H, k: &RecordId, v: &[u8]) -> HO {
        hasher.calc_hash(&[&k.0, v])
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
struct Branch<HO> {
    prefix: KeyVec,
    hash: HO,
}
impl<HO: HashOutput> Branch<HO> {
    fn new(prefix: KeyVec, hash: HO) -> Self {
        Branch { prefix, hash }
    }
    fn dir(&self) -> Dir {
        Dir::from(self.prefix[0])
    }
    fn assert_dir(b: &Option<Branch<HO>>, d: Dir) {
        if let Some(b) = b {
            assert!(!b.prefix.is_empty());
            assert_eq!(d, b.dir(), "{:?} prefix is invalid {}", d, b.prefix);
        }
    }
}
impl<HO: Debug> Debug for Branch<HO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} -> {:?}",
            compact_keyslice_str(&self.prefix, " "),
            self.hash
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Dir {
    Left,
    Right,
}
impl Dir {
    fn from(v: bool) -> Self {
        match v {
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
impl Display for Dir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dir::Left => f.write_str("Left"),
            Dir::Right => f.write_str("Right"),
        }
    }
}

// The result of performing a split operation on the tree. The tree is split
// into 2 halves.
pub struct SplitResult<HO: HashOutput> {
    // The previous root hash.
    pub old_root: HO,
    // The new tree that was from the left side of the split point.
    pub left: SplitRoot<HO>,
    // The new tree that was from the right side of the split point.
    pub right: SplitRoot<HO>,
    // The delta that needs applying to the store to perform the split.
    pub delta: StoreDelta<HO>,
}
pub struct SplitRoot<HO> {
    // The new root hash of this split off branch.
    pub root_hash: HO,
    // The resulting key range
    pub range: OwnedRange,
}
impl<HO: Debug> Debug for SplitRoot<HO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} hash {:?}", self.range, self.root_hash)
    }
}

pub struct MergeResult<HO: HashOutput> {
    pub range: OwnedRange,
    pub root_hash: HO,
    pub delta: StoreDelta<HO>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MergeError {
    Proof(ProofError),
    NotAdjacentRanges,
}

pub trait HashOutput: Hash + Copy + Eq + Debug {
    fn as_u8(&self) -> &[u8];
}

pub trait NodeHasher<HO> {
    fn calc_hash(&self, parts: &[&[u8]]) -> HO;
}

fn concat(a: &KeySlice, b: &KeySlice) -> KeyVec {
    let mut r = KeyVec::with_capacity(a.len() + b.len());
    r.extend(a);
    r.extend(b);
    r
}

fn common_prefix<'a, U: BitStore, O: BitOrder>(
    a: &'a BitSlice<U, O>,
    b: &BitSlice<U, O>,
) -> &'a BitSlice<U, O> {
    let l = min(a.len(), b.len());
    match zip(a.iter(), b.iter()).position(|(x, y)| x != y) {
        None => &a[..l],
        Some(p) => &a[..p],
    }
}

pub fn compact_keyslice_str(k: &KeySlice, delim: &str) -> String {
    let mut s = String::with_capacity(k.len());
    for (i, b) in k.iter().enumerate() {
        if i > 0 && i % 8 == 0 {
            s.push_str(delim);
        }
        s.push(if *b { '1' } else { '0' });
    }
    s
}

#[cfg(test)]
mod dot;

#[cfg(test)]
mod tests {
    use super::{
        agent::{read, Node, StoreKey, StoreKeyStart, TreeStoreError, TreeStoreReader},
        *,
    };
    use std::{collections::HashMap, hash::Hasher};

    #[test]
    fn test_bitvec_order() {
        // sanity check that the patched version of bitvec is being used.
        let k = bitvec![u8,Msb0;0, 1, 0, 1];
        let r = bitvec![u8,Msb0;1, 0, 0, 0];
        let k_slice = &k[..];
        let r_slice = &r[..];
        assert!(r > k);
        assert!(k < r);
        assert!(r_slice > k_slice);
        assert!(k_slice < r_slice);
        assert!(r_slice > k);
        assert!(k < r_slice);
        assert!(k_slice < r);
        assert!(r > k_slice);
    }

    #[test]
    fn get_nothing() {
        let range = OwnedRange::full();
        let (tree, root, store) = new_empty_tree(&range);
        let p = read(&store, &range, &root, &rec_id(&[1, 2, 3])).unwrap();
        assert_eq!(1, p.path.len());
        assert_eq!(root, p.path[0].hash);
        assert!(p.leaf.is_none());
        check_tree_invariants(&tree.hasher, &range, root, &store);
    }

    #[test]
    fn test_empty_root_prefix_hash() {
        let h = TestHasher {};
        let root = InteriorNode::new(&h, &OwnedRange::full(), true, None, None);
        let p0 = OwnedRange {
            start: rec_id(&[1]),
            end: rec_id(&[2]),
        };
        let root_p0 = InteriorNode::new(&h, &p0, true, None, None);
        let p1 = OwnedRange {
            start: p0.start,
            end: p0.end.next().unwrap(),
        };
        let root_p1 = InteriorNode::new(&h, &p1, true, None, None);
        assert_ne!(root.hash, root_p0.hash);
        assert_ne!(root.hash, root_p1.hash);
        assert_ne!(root_p0.hash, root_p1.hash);
    }

    #[test]
    fn test_branch_prefix_hash() {
        let p = OwnedRange::full();
        let h = TestHasher {};
        let k1 = KeyVec::from_element(0b00110000);
        let k2 = KeyVec::from_element(0b11010000);
        let a = InteriorNode::new(
            &h,
            &p,
            false,
            Some(Branch::new(
                k1[..4].into(),
                TestHash([1, 2, 3, 4, 5, 6, 7, 8]),
            )),
            Some(Branch::new(
                k2[..5].into(),
                TestHash([8, 7, 6, 5, 4, 3, 2, 1]),
            )),
        );
        let b = InteriorNode::new(
            &h,
            &p,
            false,
            Some(Branch::new(
                k1[..5].into(),
                TestHash([1, 2, 3, 4, 5, 6, 7, 8]),
            )),
            Some(Branch::new(
                k2[..6].into(),
                TestHash([8, 7, 6, 5, 4, 3, 2, 1]),
            )),
        );
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn test_leaf_hash() {
        let h = TestHasher {};
        let v = vec![1, 2, 3, 4, 5, 6, 8, 9];
        let k1 = rec_id(&[1, 2]);
        let k2 = rec_id(&[1, 4]);
        let ha = LeafNode::calc_hash(&h, &k1, &v);
        let hb = LeafNode::calc_hash(&h, &k2, &v);
        assert_ne!(ha, hb);
    }

    #[test]
    fn test_common_prefix_with_prefix() {
        let a: &BitSlice<u8> = BitSlice::from_slice(&[1, 2, 3]);
        let b = BitSlice::from_slice(&[1, 0, 0]);
        assert_eq!(a[..9], common_prefix(a, b));
        assert_eq!(b[..9], common_prefix(a, b));
    }

    #[test]
    fn test_common_prefix_none() {
        let a: &BitSlice<u8> = BitSlice::from_slice(&[0]);
        let b = BitSlice::from_slice(&[255u8]);
        assert!(common_prefix(a, b).is_empty());
    }

    #[test]
    fn test_common_prefix_same() {
        let a: &BitSlice<u8> = BitSlice::from_slice(&[1]);
        let b = BitSlice::from_slice(&[1]);
        let c = common_prefix(a, b);
        assert_eq!(c, b);
        assert_eq!(8, c.len());
    }

    pub fn rec_id(bytes: &[u8]) -> RecordId {
        let mut r = RecordId([0u8; 32]);
        r.0[..bytes.len()].copy_from_slice(bytes);
        r
    }

    pub fn new_empty_tree(
        range: &OwnedRange,
    ) -> (Tree<TestHasher, TestHash>, TestHash, MemStore<TestHash>) {
        let h = TestHasher {};
        let (root_hash, delta) = Tree::new_tree(&h, range);
        let mut store = MemStore::new();
        store.apply_store_delta(root_hash, delta);
        assert_eq!(1, store.nodes.len());
        check_tree_invariants(&h, range, root_hash, &store);
        let t = Tree::with_existing_root(h, root_hash);
        (t, root_hash, store)
    }

    // helper to insert a value into the tree and update the store
    pub fn tree_insert(
        tree: &mut Tree<TestHasher, TestHash>,
        store: &mut MemStore<TestHash>,
        range: &OwnedRange,
        root: TestHash,
        key: &RecordId,
        val: Vec<u8>,
        skip_tree_check: bool,
    ) -> TestHash {
        // spot stupid test bugs
        assert!(range.contains(key), "test bug, key not inside key range");
        let rp = read(store, range, &root, key).unwrap();
        let vp = tree.latest_proof(rp).unwrap();
        let new_root = match tree.insert(vp, val).unwrap() {
            (root, None) => root,
            (root, Some(d)) => {
                store.apply_store_delta(root, d);
                root
            }
        };
        if !skip_tree_check {
            check_tree_invariants(&tree.hasher, range, new_root, store);
        }
        new_root
    }

    pub fn tree_size<HO: HashOutput>(
        prefix: &KeySlice,
        root: HO,
        store: &impl TreeStoreReader<HO>,
    ) -> Result<usize, TreeStoreError> {
        match store.fetch(prefix.to_bitvec(), root)? {
            Node::Interior(int) => {
                let lc = match &int.left {
                    None => 0,
                    Some(b) => tree_size(&concat(prefix, &b.prefix), b.hash, store)?,
                };
                let rc = match &int.right {
                    None => 0,
                    Some(b) => tree_size(&concat(prefix, &b.prefix), b.hash, store)?,
                };
                Ok(lc + rc + 1)
            }
            Node::Leaf(_) => Ok(1),
        }
    }

    // Walks the tree starting at root verifying all the invariants are all true
    //      1. only the root may have an empty branch
    //      2. the left branch prefix always starts with a 0
    //      3. the right branch prefix always starts with a 1
    //      5. the leaf -> root hashes are verified.
    pub fn check_tree_invariants<HO: HashOutput>(
        hasher: &impl NodeHasher<HO>,
        range: &OwnedRange,
        root: HO,
        store: &impl TreeStoreReader<HO>,
    ) {
        let root_hash = check_tree_node_invariants(hasher, range, true, root, KeyVec::new(), store);
        assert_eq!(root_hash, root);
    }
    fn check_tree_node_invariants<HO: HashOutput>(
        hasher: &impl NodeHasher<HO>,
        range: &OwnedRange,
        is_at_root: bool,
        node: HO,
        path: KeyVec,
        store: &impl TreeStoreReader<HO>,
    ) -> HO {
        match store
            .fetch(path.clone(), node)
            .unwrap_or_else(|_| panic!("node with hash {node:?} should exist"))
        {
            Node::Leaf(l) => {
                let exp_hash = LeafNode::calc_hash(hasher, &rec_id(&path.into_vec()), &l.value);
                assert_eq!(exp_hash, l.hash);
                exp_hash
            }
            Node::Interior(int) => {
                match &int.left {
                    None => assert!(is_at_root),
                    Some(b) => {
                        assert!(!b.prefix.is_empty());
                        assert!(!b.prefix[0]);
                        let new_path = concat(&path, &b.prefix);
                        let exp_child_hash = check_tree_node_invariants(
                            hasher, range, false, b.hash, new_path, store,
                        );
                        assert_eq!(exp_child_hash, b.hash);
                    }
                }
                match &int.right {
                    None => assert!(is_at_root),
                    Some(b) => {
                        assert!(!b.prefix.is_empty());
                        assert!(b.prefix[0]);
                        let new_path = concat(&path, &b.prefix);
                        let exp_child_hash = check_tree_node_invariants(
                            hasher, range, false, b.hash, new_path, store,
                        );
                        assert_eq!(exp_child_hash, b.hash);
                    }
                }
                let exp_hash =
                    InteriorNode::calc_hash(hasher, range, is_at_root, &int.left, &int.right);
                assert_eq!(exp_hash, int.hash);
                exp_hash
            }
        }
    }

    pub fn check_delta_invariants<HO: HashOutput>(root: HO, delta: &StoreDelta<HO>) {
        let add_by_hash: HashMap<HO, (&NodeKey<HO>, &Node<HO>)> =
            delta.add.iter().map(|(k, n)| (k.hash, (k, n))).collect();
        assert_eq!(
            add_by_hash.len(),
            delta.add.len(),
            "hash is repeated in delta.add"
        );

        for (k, n) in &delta.add {
            assert_eq!(k.hash, n.hash(), "node and key have differing hashes");
        }
        for k in &delta.remove {
            let added = add_by_hash.get(&k.hash);
            if added.is_some() {
                panic!("add & remove contains same hash");
            }
        }
        fn verify_prefixes<HO: HashOutput>(
            add_by_hash: &HashMap<HO, (&NodeKey<HO>, &Node<HO>)>,
            prefix: &KeySlice,
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
                        verify_prefixes(add_by_hash, &concat(prefix, &b.prefix), &b.hash);
                    }
                    if let Some(b) = &int.right {
                        verify_prefixes(add_by_hash, &concat(prefix, &b.prefix), &b.hash);
                    }
                }
                Node::Leaf(_l) => {
                    assert_eq!(n.0.prefix.len(), RecordId::num_bits());
                }
            }
        }
        verify_prefixes(&add_by_hash, KeySlice::empty(), &root);
    }

    #[derive(Clone)]
    pub struct MemStore<HO> {
        nodes: Vec<(StoreKey, Node<HO>)>,
    }
    impl<HO> MemStore<HO> {
        fn new() -> Self {
            MemStore { nodes: Vec::new() }
        }
    }
    impl<HO: HashOutput> MemStore<HO> {
        pub fn len(&self) -> usize {
            self.nodes.len()
        }
        pub fn add_from_other_store(&mut self, other: MemStore<HO>) {
            for (enc, n) in other.nodes {
                match self.nodes.binary_search_by(|i| i.0.cmp(&enc)) {
                    Ok(idx) => self.nodes[idx] = (enc, n),
                    Err(idx) => self.nodes.insert(idx, (enc, n)),
                }
            }
        }
        pub fn apply_store_delta(&mut self, new_root: HO, d: StoreDelta<HO>) {
            check_delta_invariants(new_root, &d);
            for (k, n) in d.add {
                let enc = k.store_key();
                match self.nodes.binary_search_by(|i| i.0.cmp(&enc)) {
                    Ok(idx) => self.nodes[idx] = (enc, n),
                    Err(idx) => self.nodes.insert(idx, (enc, n)),
                }
            }
            for k in d.remove {
                let enc = k.store_key();
                if let Ok(idx) = self.nodes.binary_search_by(|i| i.0.cmp(&enc)) {
                    self.nodes.remove(idx);
                }
            }
        }
    }
    impl<HO: HashOutput> TreeStoreReader<HO> for MemStore<HO> {
        fn range(&self, key_start: &StoreKeyStart) -> Result<Vec<Node<HO>>, TreeStoreError> {
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
        fn fetch(&self, prefix: KeyVec, hash: HO) -> Result<Node<HO>, TreeStoreError> {
            let k = StoreKey::new(prefix, hash);
            match self.nodes.binary_search_by(|item| item.0.cmp(&k)) {
                Ok(idx) => Ok(self.nodes[idx].1.clone()),
                Err(_) => Err(TreeStoreError::MissingNode),
            }
        }
    }
    pub struct TestHasher {}
    impl NodeHasher<TestHash> for TestHasher {
        fn calc_hash(&self, parts: &[&[u8]]) -> TestHash {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            for p in parts {
                h.write(&[b'|']); //delim all the parts
                h.write(p);
            }
            TestHash(h.finish().to_le_bytes())
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TestHash(pub [u8; 8]);
    impl HashOutput for TestHash {
        fn as_u8(&self) -> &[u8] {
            self.0.as_slice()
        }
    }
    impl Debug for TestHash {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            for b in self.as_u8() {
                write!(f, "{:02x}", *b)?;
            }
            Ok(())
        }
    }
}
