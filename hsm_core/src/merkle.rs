extern crate alloc;

use alloc::vec::Vec;
use core::fmt::{self, Debug};
use juicebox_marshalling::{to_be2, to_be8};

use self::proof::{ProofError, VerifiedProof};
use bitvec::Bits;
use hsm_api::merkle::{
    Branch, DeltaBuilder, Dir, HashOutput, InteriorNode, KeyVec, LeafNode, Node, NodeKey,
    ReadProof, StoreDelta,
};
use hsm_api::{OwnedRange, RecordId};

mod delta;
#[cfg(feature = "dot")]
pub mod dot;
mod insert;
mod merge;
mod overlay;
pub mod proof;
mod split;
#[cfg(any(test, feature = "dot"))]
pub mod testing;

pub type TreeOverlay<HO> = self::overlay::TreeOverlay<HO>;

pub struct Tree<H: NodeHasher> {
    overlay: TreeOverlay<H::Output>,
}

impl<H: NodeHasher> Tree<H> {
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
    pub fn new_tree(key_range: &OwnedRange) -> (H::Output, StoreDelta<H::Output>) {
        let (hash, root) = InteriorNode::new_with_hash::<H>(key_range, true, None, None);
        let mut delta = DeltaBuilder::new();
        delta.add(NodeKey::new(KeyVec::new(), hash), Node::Interior(root));
        (hash, delta.build())
    }

    // Create a new Tree instance for a previously constructed tree given the root hash
    // of the tree's content.
    pub fn with_existing_root(root: H::Output, overlay_size: u16) -> Self {
        Tree {
            overlay: TreeOverlay::new(root, overlay_size),
        }
    }

    // Return a verified proof that was updated to the latest tree from the overlay.
    // This allows access to the current value, as well as being able to call insert later
    // to update the value in the tree.
    pub fn latest_proof(
        &self,
        rp: ReadProof<H::Output>,
    ) -> Result<VerifiedProof<H::Output>, ProofError> {
        proof::verify::<H>(rp, &self.overlay)
    }

    // Returns the tree overlay.
    pub fn overlay(&self) -> &TreeOverlay<H::Output> {
        &self.overlay
    }
}

pub(crate) trait InteriorNodeExt<HO> {
    fn new_with_hash<H: NodeHasher<Output = HO>>(
        key_range: &OwnedRange,
        is_root: bool,
        left: Option<Branch<H::Output>>,
        right: Option<Branch<H::Output>>,
    ) -> (H::Output, InteriorNode<H::Output>);

    fn construct<H: NodeHasher<Output = HO>>(
        key_range: &OwnedRange,
        is_root: bool,
        a: Option<Branch<H::Output>>,
        b: Option<Branch<H::Output>>,
    ) -> (HO, InteriorNode<H::Output>);

    fn calc_hash<H: NodeHasher<Output = HO>>(
        key_range: &OwnedRange,
        is_root: bool,
        left: &Option<Branch<H::Output>>,
        right: &Option<Branch<H::Output>>,
    ) -> H::Output;

    fn root_with_new_partition<H: NodeHasher<Output = HO>>(
        &self,
        key_range: &OwnedRange,
    ) -> (H::Output, InteriorNode<H::Output>);

    fn with_new_child<H: NodeHasher<Output = HO>>(
        &self,
        key_range: &OwnedRange,
        is_root: bool,
        dir: Dir,
        child: Branch<H::Output>,
    ) -> (H::Output, InteriorNode<H::Output>);

    fn with_new_child_hash<H: NodeHasher<Output = HO>>(
        &self,
        key_range: &OwnedRange,
        is_root: bool,
        dir: Dir,
        hash: H::Output,
    ) -> (H::Output, InteriorNode<H::Output>);
}

impl<HO: HashOutput> InteriorNodeExt<HO> for InteriorNode<HO> {
    fn new_with_hash<H: NodeHasher<Output = HO>>(
        key_range: &OwnedRange,
        is_root: bool,
        left: Option<Branch<H::Output>>,
        right: Option<Branch<H::Output>>,
    ) -> (H::Output, InteriorNode<H::Output>) {
        let hash = Self::calc_hash::<H>(key_range, is_root, &left, &right);
        (hash, InteriorNode::new(left, right))
    }

    // construct returns a new InteriorNode with the supplied children. It will determine
    // which should be left and right. If you know which should be left & right use new instead.
    fn construct<H: NodeHasher<Output = HO>>(
        key_range: &OwnedRange,
        is_root: bool,
        a: Option<Branch<H::Output>>,
        b: Option<Branch<H::Output>>,
    ) -> (HO, InteriorNode<H::Output>) {
        match (&a, &b) {
            (None, None) => Self::new_with_hash::<H>(key_range, is_root, None, None),
            (Some(x), _) => {
                let (l, r) = if x.dir() == Dir::Left { (a, b) } else { (b, a) };
                Self::new_with_hash::<H>(key_range, is_root, l, r)
            }
            (_, Some(x)) => {
                let (l, r) = if x.dir() == Dir::Left { (b, a) } else { (a, b) };
                Self::new_with_hash::<H>(key_range, is_root, l, r)
            }
        }
    }

    fn calc_hash<H: NodeHasher<Output = HO>>(
        key_range: &OwnedRange,
        is_root: bool,
        left: &Option<Branch<H::Output>>,
        right: &Option<Branch<H::Output>>,
    ) -> H::Output {
        let b = if is_root {
            NodeHashBuilder::<H>::Root(key_range, left, right)
        } else {
            NodeHashBuilder::<H>::Interior(left.as_ref().unwrap(), right.as_ref().unwrap())
        };
        b.build()
    }

    fn root_with_new_partition<H: NodeHasher<Output = HO>>(
        &self,
        key_range: &OwnedRange,
    ) -> (H::Output, InteriorNode<H::Output>) {
        InteriorNode::new_with_hash::<H>(key_range, true, self.left.clone(), self.right.clone())
    }

    fn with_new_child<H: NodeHasher<Output = HO>>(
        &self,
        key_range: &OwnedRange,
        is_root: bool,
        dir: Dir,
        child: Branch<H::Output>,
    ) -> (H::Output, InteriorNode<H::Output>) {
        match dir {
            Dir::Left => InteriorNode::new_with_hash::<H>(
                key_range,
                is_root,
                Some(child),
                self.right.clone(),
            ),
            Dir::Right => {
                InteriorNode::new_with_hash::<H>(key_range, is_root, self.left.clone(), Some(child))
            }
        }
    }

    fn with_new_child_hash<H: NodeHasher<Output = HO>>(
        &self,
        key_range: &OwnedRange,
        is_root: bool,
        dir: Dir,
        hash: H::Output,
    ) -> (H::Output, InteriorNode<H::Output>) {
        let b = self.branch(dir).as_ref().unwrap();
        let nb = Branch::new(b.prefix.clone(), hash);
        self.with_new_child::<H>(key_range, is_root, dir, nb)
    }
}

fn new_leaf<H: NodeHasher>(k: &RecordId, v: Vec<u8>) -> (H::Output, LeafNode) {
    let h = NodeHashBuilder::<H>::Leaf(k, &v).build();
    (h, LeafNode { value: v })
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

#[derive(Debug, Eq, PartialEq)]
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

pub trait NodeHasher: Default {
    type Output: HashOutput;

    fn update(&mut self, d: &[u8]);
    fn finalize(self) -> Self::Output;
}

pub enum NodeHashBuilder<'a, H: NodeHasher> {
    Leaf(&'a RecordId, &'a [u8]),
    Interior(&'a Branch<H::Output>, &'a Branch<H::Output>),
    Root(
        &'a OwnedRange,
        &'a Option<Branch<H::Output>>,
        &'a Option<Branch<H::Output>>,
    ),
}

impl<'a, H: NodeHasher> NodeHashBuilder<'a, H> {
    pub fn build(&self) -> H::Output {
        match self {
            NodeHashBuilder::Leaf(key, val) => {
                let mut h = H::default();
                h.update(b"leaf");
                h.update(&key.0);
                h.update(&to_be8(val.len()));
                h.update(val);
                h.finalize()
            }
            NodeHashBuilder::Interior(left, right) => {
                let mut h = H::default();
                h.update(b"interior");
                h.update(&[Self::branch_len(left)]);
                h.update(&[Self::branch_len(right)]);
                Self::branch(&mut h, left);
                Self::branch(&mut h, right);
                h.finalize()
            }
            NodeHashBuilder::Root(partition, left_maybe, right_maybe) => {
                let mut h = H::default();
                h.update(b"root");
                h.update(&partition.start.0);
                h.update(&partition.end.0);
                let zero = Branch::new(KeyVec::new(), H::Output::zero());
                let left = left_maybe.as_ref().unwrap_or(&zero);
                let right = right_maybe.as_ref().unwrap_or(&zero);
                h.update(&[Self::branch_len(left)]);
                h.update(&[Self::branch_len(right)]);
                Self::branch(&mut h, left);
                Self::branch(&mut h, right);
                h.finalize()
            }
        }
    }
    fn branch_len(b: &Branch<H::Output>) -> u8 {
        // 2 for prefix_len
        u8::try_from(2 + b.prefix.as_bytes().len() + b.hash.as_slice().len()).unwrap()
    }
    fn branch(h: &mut H, b: &Branch<H::Output>) {
        h.update(&to_be2(b.prefix.len()));
        h.update(b.prefix.as_bytes());
        h.update(b.hash.as_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{
        check_tree_invariants, new_empty_tree, MemStore, MemStoreError, TestHash, TestHasher,
    };
    use super::{HashOutput, InteriorNode};
    use crate::merkle::{InteriorNodeExt, NodeHashBuilder};
    use bitvec::Bits;
    use bitvec::{bitvec, BitVec};
    use hsm_api::merkle::{Branch, KeyVec, LeafNode, Node};
    use hsm_api::{OwnedRange, RecordId};
    use juicebox_marshalling as marshalling;

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

    #[test]
    fn get_nothing() {
        let range = OwnedRange::full();
        let (_tree, root, store) = new_empty_tree(&range);
        let p = store
            .read(&range, &root, &RecordId::min_id().with(&[1, 2, 3]))
            .unwrap();
        assert_eq!(1, p.path.len());
        assert!(p.leaf.is_none());
        check_tree_invariants::<TestHasher>(&range, root, &store);
    }

    #[test]
    fn test_empty_root_prefix_hash() {
        let (root_hash, _) =
            InteriorNode::new_with_hash::<TestHasher>(&OwnedRange::full(), true, None, None);
        let p0 = OwnedRange {
            start: RecordId::min_id().with(&[1]),
            end: RecordId::min_id().with(&[2]),
        };
        let (hash_p0, _) = InteriorNode::new_with_hash::<TestHasher>(&p0, true, None, None);
        let p1 = OwnedRange {
            start: p0.start,
            end: p0.end.next().unwrap(),
        };
        let (hash_p1, _) = InteriorNode::new_with_hash::<TestHasher>(&p1, true, None, None);
        assert_ne!(root_hash, hash_p0);
        assert_ne!(root_hash, hash_p1);
        assert_ne!(hash_p0, hash_p1);
    }

    #[test]
    fn test_branch_prefix_hash() {
        let p = OwnedRange::full();
        let k1 = bitvec![0, 0, 1, 1, 0, 0, 0, 0];
        let k2 = bitvec![1, 1, 0, 1, 0, 0, 0, 0];
        let a = InteriorNode::new_with_hash::<TestHasher>(
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
        let b = InteriorNode::new_with_hash::<TestHasher>(
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
        let v = vec![1, 2, 3, 4, 5, 6, 8, 9];
        let k1 = RecordId::min_id().with(&[1, 2]);
        let k2 = RecordId::min_id().with(&[1, 4]);
        let ha = NodeHashBuilder::<TestHasher>::Leaf(&k1, &v).build();
        let hb = NodeHashBuilder::<TestHasher>::Leaf(&k2, &v).build();
        assert_ne!(ha, hb);
    }

    pub fn tree_size<HO: HashOutput>(
        prefix: KeyVec,
        root: HO,
        store: &MemStore<HO>,
    ) -> Result<usize, MemStoreError> {
        match store.get_node(&root)? {
            Node::Interior(int) => {
                let lc = match &int.left {
                    None => 0,
                    Some(b) => tree_size(prefix.concat(&b.prefix), b.hash, store)?,
                };
                let rc = match &int.right {
                    None => 0,
                    Some(b) => tree_size(prefix.concat(&b.prefix), b.hash, store)?,
                };
                Ok(lc + rc + 1)
            }
            Node::Leaf(_) => Ok(1),
        }
    }
}
