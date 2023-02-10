use bitvec::prelude::*;
use std::{
    cmp::min,
    fmt::{Debug, Display},
    hash::Hash,
    iter::zip,
};

use self::{
    agent::{DeltaBuilder, Node, StoreDelta},
    overlay::TreeOverlay,
    proof::{ProofError, ReadProof, VerifiedProof},
};
use super::hsm::types::{OwnedRange, RecordId};

pub mod agent;
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
        delta.add(Node::Interior(root));
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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

#[derive(Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
pub struct SplitResult<HO> {
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

pub struct MergeResult<HO> {
    pub range: OwnedRange,
    pub root_hash: HO,
    pub delta: StoreDelta<HO>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MergeError {
    Proof(ProofError),
    NotAdjacentRanges,
}

pub struct Delta<HO> {
    // Nodes are in tail -> root order.
    pub add: Vec<InteriorNode<HO>>,
    pub leaf: LeafNode<HO>,
    pub remove: Vec<HO>,
}
impl<HO: Debug> Debug for Delta<HO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "[l] hash={:?}, value={:?}",
            &self.leaf.hash, self.leaf.value
        )?;
        for n in &self.add {
            writeln!(
                f,
                "[i] hash={:?} left:{:?} right:{:?}",
                &n.hash, n.left, n.right
            )?;
        }
        for n in &self.remove {
            writeln!(f, "remove {n:?}")?;
        }
        Ok(())
    }
}
impl<HO: HashOutput> Delta<HO> {
    fn new(new_leaf: LeafNode<HO>) -> Self {
        Delta {
            leaf: new_leaf,
            add: Vec::new(),
            remove: Vec::new(),
        }
    }
    pub fn root(&self) -> &HO {
        &self
            .add
            .last()
            .expect("add should contain at least a new root")
            .hash
    }
    pub fn store_delta(self) -> StoreDelta<HO> {
        let mut b = DeltaBuilder::new();
        for n in self.add {
            b.add(Node::Interior(n));
        }
        b.add(Node::Leaf(self.leaf));
        b.build()
    }
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
        agent::{read, read_tree_side, Node, TreeStoreError, TreeStoreReader},
        *,
    };
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::{
        collections::{BTreeMap, HashMap},
        hash::Hasher,
    };

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
    fn first_insert() {
        let range = OwnedRange::full();
        let (mut tree, mut root, mut store) = new_empty_tree(&range);
        let rp = read(&store, &range, &root, &rec_id(&[1, 2, 3])).unwrap();
        let d = tree
            .insert(tree.latest_proof(rp).unwrap(), [42].to_vec())
            .unwrap()
            .unwrap();
        assert_eq!(1, d.add.len());
        assert_eq!([42].to_vec(), d.leaf.value);
        assert_eq!(root, d.remove[0]);
        root = store.apply(d);
        check_tree_invariants(&tree.hasher, &range, root, &store);

        let p = read(&store, &range, &root, &rec_id(&[1, 2, 3])).unwrap();
        assert_eq!([42].to_vec(), p.leaf.as_ref().unwrap().value);
        assert_eq!(1, p.path.len());
        assert_eq!(root, p.path[0].hash);
        check_tree_invariants(&tree.hasher, &range, root, &store);
    }

    #[test]
    fn insert_some() {
        let range = OwnedRange::full();
        let (mut tree, mut root, mut store) = new_empty_tree(&range);
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &rec_id(&[2, 6, 8]),
            [42].to_vec(),
            true,
        );
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &rec_id(&[4, 4, 6]),
            [43].to_vec(),
            true,
        );
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &rec_id(&[0, 2, 3]),
            [44].to_vec(),
            false,
        );

        let p = read(&store, &range, &root, &rec_id(&[2, 6, 8])).unwrap();
        assert_eq!([42].to_vec(), p.leaf.unwrap().value);
        assert_eq!(3, p.path.len());
        assert_eq!(root, p.path[0].hash);
        check_tree_invariants(&tree.hasher, &range, root, &store);
    }

    #[test]
    fn update_some() {
        let range = OwnedRange {
            start: rec_id(&[1]),
            end: rec_id(&[6]),
        };
        let (mut tree, mut root, mut store) = new_empty_tree(&range);
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &rec_id(&[2, 6, 8]),
            [42].to_vec(),
            false,
        );
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &rec_id(&[4, 4, 6]),
            [43].to_vec(),
            false,
        );
        // now do a read/write for an existing key
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &rec_id(&[4, 4, 6]),
            [44].to_vec(),
            false,
        );

        let rp = read(&store, &range, &root, &rec_id(&[4, 4, 6])).unwrap();
        assert_eq!([44].to_vec(), rp.leaf.unwrap().value);
        check_tree_invariants(&tree.hasher, &range, root, &store);

        // writing the same value again shouldn't do anything dumb, like cause the leaf to be deleted.
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &rec_id(&[4, 4, 6]),
            [44].to_vec(),
            false,
        );
        let rp = read(&store, &range, &root, &rec_id(&[4, 4, 6])).unwrap();
        assert_eq!([44].to_vec(), rp.leaf.unwrap().value);
    }

    #[test]
    fn test_insert_lots() {
        let range = OwnedRange::full();
        let (mut tree, mut root, mut store) = new_empty_tree(&range);
        let seed = [0u8; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut random_key = [0u8; 4];
        let mut expected = BTreeMap::new();
        for i in 0..150 {
            rng.fill_bytes(&mut random_key);
            let key = rec_id(&random_key);
            // write our new key/value
            root = tree_insert(
                &mut tree,
                &mut store,
                &range,
                root,
                &key,
                [i].to_vec(),
                true,
            );
            expected.insert(key, i);

            // verify we can read all the key/values we've stored.
            for (k, v) in expected.iter() {
                let p = read(&store, &range, &root, k).unwrap();
                assert_eq!([*v].to_vec(), p.leaf.unwrap().value);
            }
            // if i == 16 {
            //     dot::tree_to_dot(root, &store, "many.dot").unwrap();
            // }
        }
        check_tree_invariants(&tree.hasher, &range, root, &store);
    }

    #[test]
    fn test_arb_split_1bit() {
        // test split where the root has branches with single bit prefixes.
        let keys = [rec_id(&[0]), rec_id(&[0b11110000])];
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[0b1000000]));
    }
    #[test]
    fn test_arb_split_multiple_bits() {
        // test split where the root has branches with multiple bits in the prefixes.
        let keys = [rec_id(&[0]), rec_id(&[0b00010000])];
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[0b1000000]));
    }
    #[test]
    fn test_arb_root_one_branch() {
        // test split where the root has only one branch with multiple bits in its prefix.
        let keys = [rec_id(&[0]), rec_id(&[0, 0, 5]), rec_id(&[0, 0, 6])];
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[0b1000000]));
    }

    #[test]
    fn test_arb_split_on_key_with_record() {
        let keys: Vec<_> = (0u8..10).map(|k| rec_id(&[k])).collect();
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[5]));
    }

    #[test]
    fn test_arb_split_on_no_record_key() {
        let keys: Vec<_> = (0u8..100).step_by(10).map(|k| rec_id(&[k])).collect();
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[10, 0, 0, 5]));
    }

    #[test]
    fn test_arb_split_one_side_ends_up_empty() {
        let keys: Vec<_> = (10u8..100).step_by(10).map(|k| rec_id(&[k])).collect();
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[5]));
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[101]));
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[200]));
    }

    #[test]
    fn test_arb_split_one_key_only() {
        test_arb_split_merge(OwnedRange::full(), &[rec_id(&[20])], &rec_id(&[4]));
        test_arb_split_merge(OwnedRange::full(), &[rec_id(&[20])], &rec_id(&[24]));
    }

    #[test]
    fn test_arb_split_empty_tree() {
        test_arb_split_merge(OwnedRange::full(), &[], &rec_id(&[4]));
    }

    #[test]
    fn test_arb_split_dense_root() {
        let k = &[
            0u8, 0b11111111, 0b01111111, 0b10111100, 0b10001111, 0b01011100, 0b00111100,
            0b11001100, 0b11100000, 0b11110001,
        ];
        let keys: Vec<_> = k.iter().map(|k| rec_id(&[*k])).collect();
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[4]));
        test_arb_split_merge(OwnedRange::full(), &keys, &keys[3]);
    }

    #[test]
    fn test_arb_split_lob_sided_tree() {
        let k = &[
            0u8, 0b11111111, 0b11111110, 0b11111100, 0b11111000, 0b11110000, 0b11110001,
        ];
        let keys: Vec<_> = k.iter().map(|k| rec_id(&[*k])).collect();
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[4]));
        test_arb_split_merge(OwnedRange::full(), &keys, &keys[3]);
    }

    #[test]
    fn test_arb_split_on_all_keys() {
        let keys: Vec<_> = (2u8..251).step_by(10).map(|k| rec_id(&[k])).collect();
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[1]));
        for k in &keys {
            test_arb_split_merge(OwnedRange::full(), &keys, k);
            let mut kk = k.clone();
            kk.0[22] = 5;
            test_arb_split_merge(OwnedRange::full(), &keys, &kk);
        }
    }

    // Creates a new tree populated with 'keys'. splits it into 2 at 'split'. verifies the split was correct
    // then merges them back together and verifies you got back to the start.
    fn test_arb_split_merge(range: OwnedRange, keys: &[RecordId], split: &RecordId) {
        let (mut tree, mut root, mut store) = new_empty_tree(&range);
        for k in keys {
            root = tree_insert(&mut tree, &mut store, &range, root, k, vec![k.0[0]], true);
        }
        check_tree_invariants(&tree.hasher, &range, root, &store);
        let pre_split_root_hash = root;
        let pre_split_store = store.clone();

        let proof = read(&store, &range, &root, split).unwrap();
        let s = tree.range_split(proof).unwrap();
        store.apply_store_delta(s.delta);
        check_tree_invariants(&TestHasher {}, &s.left.range, s.left.root_hash, &store);
        check_tree_invariants(&TestHasher {}, &s.right.range, s.right.root_hash, &store);

        let (mut tree_l, mut root_l, mut store_l) = new_empty_tree(&s.left.range);
        let (mut tree_r, mut root_r, mut store_r) = new_empty_tree(&s.right.range);
        for k in keys {
            if k < split {
                root_l = tree_insert(
                    &mut tree_l,
                    &mut store_l,
                    &s.left.range,
                    root_l,
                    k,
                    vec![k.0[0]],
                    true,
                );
            } else {
                root_r = tree_insert(
                    &mut tree_r,
                    &mut store_r,
                    &s.right.range,
                    root_r,
                    k,
                    vec![k.0[0]],
                    true,
                );
            }
        }
        check_tree_invariants(&TestHasher {}, &s.left.range, root_l, &store_l);
        check_tree_invariants(&TestHasher {}, &s.right.range, root_r, &store_r);

        if root_l != s.left.root_hash {
            dot::tree_to_dot(root_l, &store_l, "expected_left.dot").unwrap();
            dot::tree_to_dot(s.left.root_hash, &store, "actual_left.dot").unwrap();
            dot::tree_to_dot(s.right.root_hash, &store, "actual_right.dot").unwrap();
            dot::tree_to_dot(root, &pre_split_store, "before_split.dot").unwrap();
            panic!("left tree after split at {split:?} not as expected, see expected_left.dot & actual_left.dot for details");
        }
        if root_r != s.right.root_hash {
            dot::tree_to_dot(root_r, &store_r, "expected_right.dot").unwrap();
            dot::tree_to_dot(s.left.root_hash, &store, "actual_left.dot").unwrap();
            dot::tree_to_dot(s.right.root_hash, &store, "actual_right.dot").unwrap();
            dot::tree_to_dot(root, &pre_split_store, "before_split.dot").unwrap();
            panic!("right tree after split at {split:?} not as expected, see expected_right.dot & actual_right.dot for details");
        }

        let left_proof = read_tree_side(&store_l, &s.left.range, &root_l, Dir::Right).unwrap();
        let right_proof = read_tree_side(&store_r, &s.right.range, &root_r, Dir::Left).unwrap();

        let merged = tree_l.merge(left_proof, right_proof).unwrap();
        store_l.nodes.extend(store_r.nodes);
        store_l.apply_store_delta(merged.delta);
        if pre_split_root_hash != merged.root_hash {
            dot::tree_to_dot(pre_split_root_hash, &pre_split_store, "before_split.dot").unwrap();
            dot::tree_to_dot(merged.root_hash, &store_l, "after_merge.dot").unwrap();
            assert_eq!(
                pre_split_root_hash, merged.root_hash,
                "tree after split then merge should be the same as before the initial split"
            );
        }
        check_tree_invariants(&tree_r.hasher, &merged.range, merged.root_hash, &store_l);
    }

    #[test]
    fn test_read_proof_verify() {
        let range = OwnedRange::full();
        let (mut tree, mut root, mut store) = new_empty_tree(&range);
        let rid1 = rec_id(&[1]);
        let rid5 = rec_id(&[5]);
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &rid1,
            [1].to_vec(),
            true,
        );
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &rid5,
            [2].to_vec(),
            false,
        );

        let p = read(&store, &range, &root, &rid5).unwrap();
        assert!(p.verify(&tree.hasher, &tree.overlay).is_ok());

        // claim there's no leaf
        let mut p = read(&store, &range, &root, &rid5).unwrap();
        p.leaf = None;
        assert!(p.verify(&tree.hasher, &tree.overlay).is_err());

        let mut p = read(&store, &range, &root, &rid5).unwrap();
        // truncate the tail of the path to claim there's no leaf
        p.leaf = None;
        p.path.pop();
        assert!(p.verify(&tree.hasher, &tree.overlay).is_err());

        let mut p = read(&store, &range, &root, &rid5).unwrap();
        // futz with the path
        p.key.0[0] = 2;
        assert!(p.verify(&tree.hasher, &tree.overlay).is_err());

        // futz with the value (checks the hash)
        let mut p = read(&store, &range, &root, &rid5).unwrap();
        if let Some(ref mut l) = p.leaf {
            l.value[0] += 1;
        }
        assert!(p.verify(&tree.hasher, &tree.overlay).is_err());

        // futz with a node (checks the hash)
        let mut p = read(&store, &range, &root, &rid5).unwrap();
        if let Some(ref mut b) = &mut p.path[0].left {
            b.prefix.pop();
        }
        assert!(p.verify(&tree.hasher, &tree.overlay).is_err());
    }

    #[test]
    fn test_insert_pipeline() {
        let range = OwnedRange::full();
        let (mut tree, mut root, mut store) = new_empty_tree(&range);
        let rid1 = rec_id(&[1]);
        let rid2 = rec_id(&[2]);
        let rid3 = rec_id(&[3]);
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &rid1,
            [1].to_vec(),
            false,
        );
        let rp_1 = read(&store, &range, &root, &rid1).unwrap();
        let rp_2 = read(&store, &range, &root, &rid2).unwrap();
        let rp_3 = read(&store, &range, &root, &rid3).unwrap();
        let d1 = tree
            .insert(tree.latest_proof(rp_1).unwrap(), [11].to_vec())
            .unwrap()
            .unwrap();
        let d2 = tree
            .insert(tree.latest_proof(rp_2).unwrap(), [12].to_vec())
            .unwrap()
            .unwrap();
        let d3 = tree
            .insert(tree.latest_proof(rp_3).unwrap(), [13].to_vec())
            .unwrap()
            .unwrap();
        root = store.apply(d1);
        check_tree_invariants(&tree.hasher, &range, root, &store);
        root = store.apply(d2);
        check_tree_invariants(&tree.hasher, &range, root, &store);
        root = store.apply(d3);
        check_tree_invariants(&tree.hasher, &range, root, &store);

        let rp_1 = read(&store, &range, &root, &rid1).unwrap();
        assert_eq!([11].to_vec(), rp_1.leaf.unwrap().value);
        let rp_2 = read(&store, &range, &root, &rid2).unwrap();
        assert_eq!([12].to_vec(), rp_2.leaf.unwrap().value);
        let rp_3 = read(&store, &range, &root, &rid3).unwrap();
        assert_eq!([13].to_vec(), rp_3.leaf.unwrap().value);
    }

    #[test]
    fn test_stale_proof() {
        let range = OwnedRange::full();
        let (mut tree, mut root, mut store) = new_empty_tree(&range);
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &rec_id(&[0b10000000]),
            [1].to_vec(),
            false,
        );
        let rp_1 = read(&store, &range, &root, &rec_id(&[0b10000000])).unwrap();
        for i in 0..20 {
            root = tree_insert(
                &mut tree,
                &mut store,
                &range,
                root,
                &rec_id(&[0b11000000]),
                [i].to_vec(),
                false,
            );
        }
        let err = tree
            .latest_proof(rp_1)
            .expect_err("should have been declared stale");
        assert_eq!(ProofError::Stale, err);
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

    fn rec_id(bytes: &[u8]) -> RecordId {
        let mut r = RecordId([0u8; 32]);
        r.0[..bytes.len()].copy_from_slice(bytes);
        r
    }

    fn new_empty_tree(
        range: &OwnedRange,
    ) -> (Tree<TestHasher, TestHash>, TestHash, MemStore<TestHash>) {
        let h = TestHasher {};
        let (root_hash, delta) = Tree::new_tree(&h, range);
        let mut store = MemStore::new();
        store.apply_store_delta(delta);
        check_tree_invariants(&h, range, root_hash, &store);
        let t = Tree::with_existing_root(h, root_hash);
        (t, root_hash, store)
    }

    // helper to insert a value into the tree and update the store
    fn tree_insert(
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
            None => root,
            Some(d) => store.apply(d),
        };
        if !skip_tree_check {
            check_tree_invariants(&tree.hasher, range, new_root, store);
        }
        new_root
    }

    // walks the tree starting at root verifying all the invariants are all true
    //      1. only the root may have an empty branch
    //      2. the left branch prefix always starts with a 0
    //      3. the right branch prefix always starts with a 1
    //      5. the leaf -> root hashes are verified.
    fn check_tree_invariants<HO: HashOutput>(
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
            .fetch(&node)
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

    #[derive(Clone)]
    struct MemStore<HO> {
        nodes: HashMap<Vec<u8>, Node<HO>>,
    }
    impl<HO> MemStore<HO> {
        fn new() -> Self {
            MemStore {
                nodes: HashMap::new(),
            }
        }
    }
    impl<HO: HashOutput> MemStore<HO> {
        fn apply_store_delta(&mut self, d: StoreDelta<HO>) {
            let (add, rem) = d.items();
            for n in add {
                self.insert(n.hash(), n);
            }
            for r in rem {
                self.nodes.remove(r.as_u8());
            }
        }

        // Returns the new root hash.
        fn apply(&mut self, delta: Delta<HO>) -> HO {
            self.insert(delta.leaf.hash, Node::Leaf(delta.leaf));
            let root_hash = delta.add.last().unwrap().hash;
            for a in delta.add {
                self.insert(a.hash, Node::Interior(a));
            }
            for h in delta.remove {
                self.nodes.remove(h.as_u8());
            }
            root_hash
        }
        fn insert(&mut self, k: HO, n: Node<HO>) {
            self.nodes.insert(k.as_u8().to_vec(), n);
        }
    }
    impl<HO: HashOutput> TreeStoreReader<HO> for MemStore<HO> {
        fn fetch(&self, k: &HO) -> Result<Node<HO>, TreeStoreError> {
            match self.nodes.get(k.as_u8()) {
                None => Err(TreeStoreError::MissingNode),
                Some(n) => Ok(n.clone()),
            }
        }
    }
    struct TestHasher {}
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
    struct TestHash([u8; 8]);
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
