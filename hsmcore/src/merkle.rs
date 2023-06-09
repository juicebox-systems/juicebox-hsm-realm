extern crate alloc;

use alloc::vec::Vec;
use core::fmt::{self, Debug, Display};
use core::hash::Hash;
use juicebox_sdk_marshalling::bytes;
use serde::{Deserialize, Serialize};

use self::agent::{DeltaBuilder, Node, NodeKey, StoreDelta};
use self::overlay::TreeOverlay;
use self::proof::{ProofError, ReadProof, VerifiedProof};
use super::bitvec::{BitSlice, BitVec, Bits};
use super::hsm::types::{OwnedRange, RecordId};

pub mod agent;
mod base128;
#[cfg(feature = "dot")]
pub mod dot;
mod insert;
mod merge;
mod overlay;
pub mod proof;
mod split;
#[cfg(any(test, feature = "dot"))]
pub mod test_types;

pub type KeyVec = BitVec;
pub type KeySlice<'a> = BitSlice<'a>;

// TODO
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct LeafNode {
    #[serde(with = "bytes")]
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
    pub fn new(prefix: KeyVec, hash: HO) -> Self {
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
mod tests {
    use async_recursion::async_recursion;

    use super::agent::{Node, StoreKey, TreeStoreError};
    use super::dot::TreeStoreReader;
    use super::test_types::{
        check_tree_invariants, new_empty_tree, read, rec_id, TestHash, TestHasher,
    };
    use super::{BitVec, Branch, HashOutput, InteriorNode, KeyVec, LeafNode};
    use crate::bitvec;
    use crate::bitvec::Bits;
    use crate::hsm::types::OwnedRange;
    use juicebox_sdk_core::types::RealmId;
    use juicebox_sdk_marshalling as marshalling;

    pub const TEST_REALM: RealmId = RealmId([42u8; 16]);

    #[test]
    fn test_leaf_serialization() {
        let rt = |v: Vec<u8>| {
            let v_len = v.len();
            let node = Node::<TestHash>::Leaf(LeafNode { value: v });
            let marshalled = marshalling::to_vec(&node).unwrap();
            // there's ~15 bytes of overhead currently (mostly field names)
            assert!(
                marshalled.len() < v_len + 20,
                "expecting marshalled length of {} to be less than {}",
                marshalled.len(),
                v_len + 20
            );
            let node2 = marshalling::from_slice(&marshalled).unwrap();
            assert_eq!(node, node2);
        };
        rt(Vec::new());
        rt(vec![42; 124]);
        rt(vec![255, 32]);
        rt(vec![0; 1]);
        let mut v = vec![0u8; 300];
        for (i, val) in v.iter_mut().enumerate() {
            *val = (i % 255).try_into().unwrap();
        }
        rt(v);
    }

    #[test]
    fn test_interior_node_serialization() {
        let rt = |n: InteriorNode<TestHash>| {
            let node = Node::Interior(n);
            let marshalled = marshalling::to_vec(&node).unwrap();
            let node2 = marshalling::from_slice(&marshalled).unwrap();
            assert_eq!(node, node2);
            // (prefix is 32, testhash is 8)*2 = 80 + ~80 overhead (types, fieldnames)
            assert!(
                marshalled.len() < 160,
                "expecting marshalled length of {} to be less than 160",
                marshalled.len(),
            );
        };
        rt(InteriorNode {
            left: None,
            right: None,
        });
        rt(InteriorNode {
            left: Some(Branch {
                prefix: BitVec::from_bytes(&[128; 32]),
                hash: TestHash([43; 8]),
            }),
            right: Some(Branch {
                prefix: BitVec::new(),
                hash: TestHash([255; 8]),
            }),
        });
        rt(InteriorNode {
            left: None,
            right: Some(Branch {
                prefix: BitVec::from_bytes(&[42; 32]),
                hash: TestHash([243; 8]),
            }),
        });
        rt(InteriorNode {
            left: Some(Branch {
                prefix: BitVec::new(),
                hash: TestHash([43; 8]),
            }),
            right: None,
        });
    }

    #[tokio::test]
    async fn get_nothing() {
        let range = OwnedRange::full();
        let (tree, root, store) = new_empty_tree(&range).await;
        let p = read(&TEST_REALM, &store, &range, &root, &rec_id(&[1, 2, 3]))
            .await
            .unwrap();
        assert_eq!(1, p.path.len());
        assert!(p.leaf.is_none());
        check_tree_invariants(&tree.hasher, &range, &TEST_REALM, root, &store).await;
    }

    #[test]
    fn test_empty_root_prefix_hash() {
        let h = TestHasher;
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
}
