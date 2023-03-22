extern crate alloc;

use alloc::vec::Vec;
use core::{
    fmt::{self, Debug, Display},
    hash::Hash,
};
use serde::{Deserialize, Serialize};

use self::{
    agent::{DeltaBuilder, Node, NodeKey, StoreDelta},
    overlay::TreeOverlay,
    proof::{ProofError, ReadProof, VerifiedProof},
};
use super::bitvec::{BitSlice, BitVec, Bits};
use super::hsm::types::{OwnedRange, RecordId};

pub mod agent;
mod base128;
mod insert;
mod merge;
mod overlay;
pub mod proof;
mod split;

pub type KeyVec = BitVec;
pub type KeySlice<'a> = BitSlice<'a>;

// TODO
//  blake hasher
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
        let (hash, root) = InteriorNode::new(hasher, key_range, true, None, None);
        let mut delta = DeltaBuilder::new();
        delta.add(NodeKey::new(KeyVec::new(), hash), Node::Interior(root));
        (hash, delta.build())
    }

    // Create a new Tree instance for a previously constructed tree given the root hash
    // of the tree's content.
    pub fn with_existing_root(hasher: H, root: HO, overlay_size: u16) -> Self {
        Tree {
            hasher,
            overlay: TreeOverlay::new(root, overlay_size),
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
}
impl<HO: HashOutput> InteriorNode<HO> {
    fn new<H: NodeHasher<HO>>(
        h: &H,
        key_range: &OwnedRange,
        is_root: bool,
        left: Option<Branch<HO>>,
        right: Option<Branch<HO>>,
    ) -> (HO, InteriorNode<HO>) {
        Branch::assert_dir(&left, Dir::Left);
        Branch::assert_dir(&right, Dir::Right);
        let hash = Self::calc_hash(h, key_range, is_root, &left, &right);
        (hash, InteriorNode { left, right })
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
    ) -> (HO, InteriorNode<HO>) {
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
        let mut parts: [&[u8]; 8] = Default::default();

        if is_root {
            parts[0] = &key_range.start.0;
            parts[1] = &key_range.end.0;
        }
        let left_prefix_len = left.as_ref().map(|b| b.prefix.len().to_be_bytes());
        if let Some(b) = left {
            parts[2] = left_prefix_len.as_ref().unwrap();
            parts[3] = b.prefix.as_bytes();
            parts[4] = b.hash.as_u8();
        }
        let right_prefix_len = right.as_ref().map(|b| b.prefix.len().to_be_bytes());
        if let Some(b) = right {
            parts[5] = right_prefix_len.as_ref().unwrap();
            parts[6] = b.prefix.as_bytes();
            parts[7] = b.hash.as_u8();
        }
        h.calc_hash(&parts)
    }
    pub fn branch(&self, dir: Dir) -> &Option<Branch<HO>> {
        match dir {
            Dir::Left => &self.left,
            Dir::Right => &self.right,
        }
    }
    fn root_with_new_partition<H: NodeHasher<HO>>(
        &self,
        h: &H,
        key_range: &OwnedRange,
    ) -> (HO, InteriorNode<HO>) {
        InteriorNode::new(h, key_range, true, self.left.clone(), self.right.clone())
    }
    fn with_new_child<H: NodeHasher<HO>>(
        &self,
        h: &H,
        key_range: &OwnedRange,
        is_root: bool,
        dir: Dir,
        child: Branch<HO>,
    ) -> (HO, InteriorNode<HO>) {
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
    ) -> (HO, InteriorNode<HO>) {
        let b = self.branch(dir).as_ref().unwrap();
        let nb = Branch::new(b.prefix.clone(), hash);
        self.with_new_child(h, key_range, is_root, dir, nb)
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub struct LeafNode {
    pub value: Vec<u8>,
}

impl Debug for LeafNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LeafNode")
    }
}

impl LeafNode {
    fn new<HO, H: NodeHasher<HO>>(hasher: &H, k: &RecordId, v: Vec<u8>) -> (HO, LeafNode) {
        let h = Self::calc_hash(hasher, k, &v);
        (h, LeafNode { value: v })
    }
    fn calc_hash<HO, H: NodeHasher<HO>>(hasher: &H, k: &RecordId, v: &[u8]) -> HO {
        hasher.calc_hash(&[&k.0, v])
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct Branch<HO> {
    pub prefix: KeyVec,
    pub hash: HO,
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
    pub fn from(v: bool) -> Self {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dir::Left => f.write_str("Left"),
            Dir::Right => f.write_str("Right"),
        }
    }
}

// The result of performing a split operation on the tree. The tree is split
// into 2 halves.
pub struct SplitResult<HO: HashOutput> {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

pub trait HashOutput: Hash + Copy + Eq + Debug + Sync + Send {
    fn from_slice(bytes: &[u8]) -> Option<Self>;
    fn as_u8(&self) -> &[u8];
}

pub trait NodeHasher<HO>: Sync {
    fn calc_hash(&self, parts: &[&[u8]]) -> HO;
}

#[cfg(test)]
mod dot;

#[cfg(test)]
mod tests {
    use async_recursion::async_recursion;
    use async_trait::async_trait;

    use super::super::hsm::types::RealmId;
    use super::{
        agent::{
            all_store_key_starts, tests::read, tests::TreeStoreReader, Node, StoreKey,
            TreeStoreError,
        },
        *,
    };
    use crate::bitvec;
    use std::{
        collections::{BTreeMap, HashMap},
        hash::Hasher,
    };

    pub const TEST_REALM: RealmId = RealmId([42u8; 16]);

    #[tokio::test]
    async fn get_nothing() {
        let range = OwnedRange::full();
        let (tree, root, store) = new_empty_tree(&range).await;
        let p = read(&TEST_REALM, &store, &range, &root, &rec_id(&[1, 2, 3]))
            .await
            .unwrap();
        assert_eq!(1, p.path.len());
        assert!(p.leaf.is_none());
        check_tree_invariants(&tree.hasher, &range, root, &store).await;
    }

    #[test]
    fn test_empty_root_prefix_hash() {
        let h = TestHasher {};
        let (root_hash, _) = InteriorNode::new(&h, &OwnedRange::full(), true, None, None);
        let p0 = OwnedRange {
            start: rec_id(&[1]),
            end: rec_id(&[2]),
        };
        let (hash_p0, _) = InteriorNode::new(&h, &p0, true, None, None);
        let p1 = OwnedRange {
            start: p0.start,
            end: p0.end.next().unwrap(),
        };
        let (hash_p1, _) = InteriorNode::new(&h, &p1, true, None, None);
        assert_ne!(root_hash, hash_p0);
        assert_ne!(root_hash, hash_p1);
        assert_ne!(hash_p0, hash_p1);
    }

    #[test]
    fn test_branch_prefix_hash() {
        let p = OwnedRange::full();
        let h = TestHasher {};
        let k1 = bitvec![0, 0, 1, 1, 0, 0, 0, 0];
        let k2 = bitvec![1, 1, 0, 1, 0, 0, 0, 0];
        let a = InteriorNode::new(
            &h,
            &p,
            false,
            Some(Branch::new(
                k1.slice(..4).into(),
                TestHash([1, 2, 3, 4, 5, 6, 7, 8]),
            )),
            Some(Branch::new(
                k2.slice(..5).into(),
                TestHash([8, 7, 6, 5, 4, 3, 2, 1]),
            )),
        );
        let b = InteriorNode::new(
            &h,
            &p,
            false,
            Some(Branch::new(
                k1.slice(..5).into(),
                TestHash([1, 2, 3, 4, 5, 6, 7, 8]),
            )),
            Some(Branch::new(
                k2.slice(..6).into(),
                TestHash([8, 7, 6, 5, 4, 3, 2, 1]),
            )),
        );
        assert_ne!(a.0, b.0);
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

    pub fn rec_id(bytes: &[u8]) -> RecordId {
        let mut r = RecordId([0u8; 32]);
        r.0[..bytes.len()].copy_from_slice(bytes);
        r
    }

    pub async fn new_empty_tree(
        range: &OwnedRange,
    ) -> (Tree<TestHasher, TestHash>, TestHash, MemStore<TestHash>) {
        let h = TestHasher {};
        let (root_hash, delta) = Tree::new_tree(&h, range);
        let mut store = MemStore::new();
        store.apply_store_delta(root_hash, delta);
        assert_eq!(1, store.nodes.len());
        check_tree_invariants(&h, range, root_hash, &store).await;
        let t = Tree::with_existing_root(h, root_hash, 15);
        (t, root_hash, store)
    }

    // helper to insert a value into the tree and update the store
    pub async fn tree_insert(
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
        let rp = read(&TEST_REALM, store, range, &root, key).await.unwrap();
        let vp = tree.latest_proof(rp).unwrap();
        let new_root = match tree.insert(vp, val).unwrap() {
            (root, None) => root,
            (root, Some(d)) => {
                store.apply_store_delta(root, d);
                root
            }
        };
        if !skip_tree_check {
            check_tree_invariants(&tree.hasher, range, new_root, store).await;
        }
        new_root
    }

    #[async_recursion]
    pub async fn tree_size<HO: HashOutput>(
        prefix: KeyVec,
        root: HO,
        store: &impl TreeStoreReader<HO>,
    ) -> Result<usize, TreeStoreError> {
        match store
            .read_node(&TEST_REALM, StoreKey::new(&prefix, &root))
            .await?
        {
            Node::Interior(int) => {
                let lc = match &int.left {
                    None => 0,
                    Some(b) => tree_size(prefix.concat(&b.prefix), b.hash, store).await?,
                };
                let rc = match &int.right {
                    None => 0,
                    Some(b) => tree_size(prefix.concat(&b.prefix), b.hash, store).await?,
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
    pub async fn check_tree_invariants<HO: HashOutput>(
        hasher: &impl NodeHasher<HO>,
        range: &OwnedRange,
        root: HO,
        store: &impl TreeStoreReader<HO>,
    ) {
        let root_hash =
            check_tree_node_invariants(hasher, range, true, root, KeyVec::new(), store).await;
        assert_eq!(root_hash, root);
    }
    #[async_recursion]
    async fn check_tree_node_invariants<HO: HashOutput>(
        hasher: &impl NodeHasher<HO>,
        range: &OwnedRange,
        is_at_root: bool,
        node: HO,
        path: KeyVec,
        store: &impl TreeStoreReader<HO>,
    ) -> HO {
        match store
            .read_node(&TEST_REALM, StoreKey::new(&path, &node))
            .await
            .unwrap_or_else(|_| panic!("node with hash {node:?} should exist"))
        {
            Node::Leaf(l) => LeafNode::calc_hash(hasher, &RecordId::from_bitvec(&path), &l.value),
            Node::Interior(int) => {
                match &int.left {
                    None => assert!(is_at_root),
                    Some(b) => {
                        assert!(!b.prefix.is_empty());
                        assert!(!b.prefix[0]);
                        let new_path = path.concat(&b.prefix);
                        let exp_child_hash = check_tree_node_invariants(
                            hasher, range, false, b.hash, new_path, store,
                        )
                        .await;
                        assert_eq!(exp_child_hash, b.hash);
                    }
                }
                match &int.right {
                    None => assert!(is_at_root),
                    Some(b) => {
                        assert!(!b.prefix.is_empty());
                        assert!(b.prefix[0]);
                        let new_path = path.concat(&b.prefix);
                        let exp_child_hash = check_tree_node_invariants(
                            hasher, range, false, b.hash, new_path, store,
                        )
                        .await;
                        assert_eq!(exp_child_hash, b.hash);
                    }
                }
                let exp_hash =
                    InteriorNode::calc_hash(hasher, range, is_at_root, &int.left, &int.right);
                assert_eq!(exp_hash, node);
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

        for k in &delta.remove {
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
                    assert_eq!(n.0.prefix.len(), RecordId::num_bits());
                }
            }
        }
        verify_prefixes(&add_by_hash, KeyVec::new(), &root);
    }

    #[derive(Clone)]
    pub struct MemStore<HO> {
        nodes: BTreeMap<Vec<u8>, (HO, Node<HO>)>,
    }
    impl<HO> MemStore<HO> {
        fn new() -> Self {
            MemStore {
                nodes: BTreeMap::new(),
            }
        }
    }
    impl<HO: HashOutput> MemStore<HO> {
        pub fn len(&self) -> usize {
            self.nodes.len()
        }
        pub fn add_from_other_store(&mut self, other: MemStore<HO>) {
            self.nodes.extend(other.nodes);
        }
        pub fn apply_store_delta(&mut self, new_root: HO, d: StoreDelta<HO>) {
            check_delta_invariants(new_root, &d);
            for (k, n) in d.add {
                let enc = k.store_key();
                self.nodes.insert(enc.into_bytes(), (k.hash, n));
            }
            for k in d.remove {
                let enc = k.store_key();
                self.nodes.remove(&enc.into_bytes());
            }
        }
    }
    #[async_trait]
    impl<HO: HashOutput> TreeStoreReader<HO> for MemStore<HO> {
        async fn path_lookup(
            &self,
            _realm_id: &RealmId,
            record_id: &RecordId,
        ) -> Result<HashMap<HO, Node<HO>>, TreeStoreError> {
            let mut results = HashMap::new();
            for start in all_store_key_starts(record_id) {
                let end = start.next();
                results.extend(
                    self.nodes
                        .range(start.into_bytes()..end.into_bytes())
                        .map(|i| (i.1 .0, i.1 .1.clone())),
                );
            }
            Ok(results)
        }
        async fn read_node(
            &self,
            _realm_id: &RealmId,
            key: StoreKey,
        ) -> Result<Node<HO>, TreeStoreError> {
            match self.nodes.get(&key.into_bytes()) {
                Some((_hash, n)) => Ok(n.clone()),
                None => Err(TreeStoreError::MissingNode),
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
        fn from_slice(bytes: &[u8]) -> Option<TestHash> {
            if bytes.len() == 8 {
                let mut h = TestHash([0u8; 8]);
                h.0.copy_from_slice(bytes);
                Some(h)
            } else {
                None
            }
        }
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
