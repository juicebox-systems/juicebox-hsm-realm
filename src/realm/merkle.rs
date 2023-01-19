#![allow(dead_code)]

use bitvec::{order::Msb0, prelude::BitOrder, slice::BitSlice, store::BitStore, vec::BitVec};
use std::{
    fmt::{Debug, Display},
    iter::zip,
    marker::PhantomData,
};

pub mod dot;

type KeyVec = BitVec<u8, Msb0>;
type KeySlice = BitSlice<u8, Msb0>;

// TODO
//  probably a bunch of stuff that should be pub but isn't
//  blake hasher
//  tree overlay
//         delta changes to support this
//         apply overlay to earlier proof
//         remove ealier deltas
//  split
//      "simple split" where the root is split into 2
//      "complex split" split on arbitary keys
//  int node hash uses whole bytes of prefix path. needs to distingush between 0001 and 00010
//  compact_keyslice_str should be a wrapper type?
//  docs
//  more tests

pub struct Tree<H: NodeHasher<HO>, HO> {
    hasher: H,
    _marker: PhantomData<HO>,
}
impl<H: NodeHasher<HO>, HO: HashOutput> Tree<H, HO> {
    pub fn new(hasher: H) -> Self {
        Tree {
            hasher,
            _marker: PhantomData,
        }
    }

    pub fn empty_root(&self) -> InteriorNode<HO> {
        InteriorNode::new(&self.hasher, None, None)
    }

    pub fn read<R: TreeStoreReader<HO>>(
        &self,
        store: &R,
        root_hash: &HO,
        k: &[u8],
    ) -> Result<ReadProof<HO>, TreeStoreError> {
        let root = match store.fetch(root_hash.as_u8())? {
            Node::Interior(int) => int,
            Node::Leaf(_) => panic!("found unexpected leaf node"),
        };
        let mut res = ReadProof::new(k, root);
        let mut key = KeySlice::from_slice(k);
        loop {
            let n = res.path.last().unwrap();
            let d = Dir::from(key[0]);
            match n.branch(d) {
                None => return Ok(res),
                Some(b) => {
                    if !key.starts_with(&b.prefix) {
                        return Ok(res);
                    }
                    key = &key[b.prefix.len()..];
                    match store.fetch(b.hash.as_u8())? {
                        Node::Interior(int) => {
                            res.add_to_path(int, d);
                            continue;
                        }
                        Node::Leaf(v) => {
                            assert!(key.is_empty());
                            res.leaf = Some(v);
                            return Ok(res);
                        }
                    }
                }
            }
        }
    }

    pub fn insert(&mut self, mut rp: ReadProof<HO>, v: Vec<u8>) -> Result<Delta<HO>, InsertError> {
        if !rp.verify(&self.hasher) {
            return Err(InsertError::InvalidProof);
        }
        let path_prefix = rp.prefix_of_path();
        let mut delta = Delta::new(LeafNode::new(&self.hasher, &rp.key, v));
        let key = &KeySlice::from_slice(&rp.key)[path_prefix.len()..];
        let tail = rp
            .path
            .pop()
            .expect("the path should always include at least the root");

        match rp.leaf {
            Some(l) => {
                // There's an existing path to the correct leaf. We need to delete the old
                // leaf. We also recalculate the hash for tail node with the new leaf
                let (updated_n, old_hash) =
                    tail.with_new_child_hash(&self.hasher, Dir::from(key[0]), delta.leaf.hash);
                delta.add.push(updated_n);
                delta.remove.push(old_hash);
                delta.remove.push(l.hash);
                // the remained of the path is updated below.
            }
            None => {
                // We need to mutate the tree to add a path to our new leaf. The mutation starts
                // at the last node in the path.
                let dir = Dir::from(key[0]);
                match tail.branch(dir) {
                    None => {
                        // There's no existing entry for the branch we want to use. We update it to point to the new leaf.
                        let new_b = Branch::new(key.into(), delta.leaf.hash);
                        let (updated_tail, old_hash) =
                            tail.with_new_child(&self.hasher, dir, new_b);
                        delta.add.push(updated_tail);
                        delta.remove.push(old_hash);
                    }
                    Some(branch) => {
                        let kp = &key[..branch.prefix.len()];
                        match kp.cmp(&branch.prefix) {
                            std::cmp::Ordering::Equal => {
                                panic!("invalid path, the path should of included the next node");
                            }
                            std::cmp::Ordering::Greater | std::cmp::Ordering::Less => {
                                // We need to create a new child interior node from this branch that contains (new_leaf, prev_branch_dest).
                                // The current branch should have its prefix shortened to the common prefix.
                                let comm = common_prefix(kp, &branch.prefix);
                                let new_child = InteriorNode::construct(
                                    &self.hasher,
                                    Some(Branch::new(key[comm.len()..].into(), delta.leaf.hash)),
                                    Some(Branch::new(
                                        branch.prefix[comm.len()..].into(),
                                        branch.hash,
                                    )),
                                );
                                let (updated_n, old_hash) = tail.with_new_child(
                                    &self.hasher,
                                    dir,
                                    Branch::new(comm.into(), new_child.hash),
                                );
                                delta.add.push(new_child);
                                delta.add.push(updated_n);
                                delta.remove.push(old_hash);
                            }
                        }
                    }
                }
            }
        }
        // At this point, rp.path contains the list of existing nodes that were traversed to find out
        // where to insert new item, and they need updating with new hashes.
        // Delta contains the mutations to get from the end of 'path' to the new leaf. The last item
        // in delta is the child of the last item in rp.path. Regardless of if there was an existing
        // leaf or not, the above code has already updated the leaf and the last interior node.
        assert!(!delta.add.is_empty());
        let mut child_hash = delta.add.last().unwrap().hash;
        loop {
            match rp.path.pop() {
                None => break,
                Some(n) => {
                    let dir = rp.dirs.pop().unwrap();
                    let (new_n, old_hash) = n.with_new_child_hash(&self.hasher, dir, child_hash);
                    child_hash = new_n.hash;
                    delta.add.push(new_n);
                    delta.remove.push(old_hash);
                }
            }
        }
        assert!(rp.dirs.is_empty());
        Ok(delta)
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
        left: Option<Branch<HO>>,
        right: Option<Branch<HO>>,
    ) -> InteriorNode<HO> {
        Branch::assert_dir(&left, Dir::Left);
        Branch::assert_dir(&right, Dir::Right);
        let hash = Self::calc_hash(h, &left, &right);
        InteriorNode { left, right, hash }
    }
    // construct returns a new InteriorNode with the supplied children. It will determine
    // which should be left and right. If you know which should be left & right use new instead.
    // TODO: get rid of new and always use this?
    fn construct<H: NodeHasher<HO>>(
        h: &H,
        a: Option<Branch<HO>>,
        b: Option<Branch<HO>>,
    ) -> InteriorNode<HO> {
        match (&a, &b) {
            (None, None) => Self::new(h, None, None),
            (Some(x), _) => {
                let (l, r) = if x.dir() == Dir::Left { (a, b) } else { (b, a) };
                Self::new(h, l, r)
            }
            (_, Some(x)) => {
                let (l, r) = if x.dir() == Dir::Left { (b, a) } else { (a, b) };
                Self::new(h, l, r)
            }
        }
    }
    fn calc_hash<H: NodeHasher<HO>>(
        h: &H,
        left: &Option<Branch<HO>>,
        right: &Option<Branch<HO>>,
    ) -> HO {
        let mut parts: [&[u8]; 5] = [&[], &[], &[42], &[], &[]];
        if let Some(b) = left {
            parts[0] = b.prefix.as_raw_slice();
            parts[1] = b.hash.as_u8();
        }
        if let Some(b) = right {
            parts[3] = b.prefix.as_raw_slice();
            parts[4] = b.hash.as_u8();
        }
        h.calc_hash(&parts)
    }
    fn branch(&self, dir: Dir) -> &Option<Branch<HO>> {
        match dir {
            Dir::Left => &self.left,
            Dir::Right => &self.right,
        }
    }
    fn with_new_child<H: NodeHasher<HO>>(
        self,
        h: &H,
        dir: Dir,
        child: Branch<HO>,
    ) -> (InteriorNode<HO>, HO) {
        match dir {
            Dir::Left => (InteriorNode::new(h, Some(child), self.right), self.hash),
            Dir::Right => (InteriorNode::new(h, self.left, Some(child)), self.hash),
        }
    }
    fn with_new_child_hash<H: NodeHasher<HO>>(
        self,
        h: &H,
        dir: Dir,
        hash: HO,
    ) -> (InteriorNode<HO>, HO) {
        let b = self.branch(dir).as_ref().unwrap();
        // TODO, shouldn't need to clone the prefix
        let nb = Branch::new(b.prefix.clone(), hash);
        self.with_new_child(h, dir, nb)
    }
}

#[derive(Clone)]
pub struct LeafNode<HO> {
    value: Vec<u8>,
    hash: HO,
}
impl<HO> LeafNode<HO> {
    fn new<H: NodeHasher<HO>>(hasher: &H, k: &[u8], v: Vec<u8>) -> LeafNode<HO> {
        let h = Self::calc_hash(hasher, k, &v);
        LeafNode { value: v, hash: h }
    }
    fn calc_hash<H: NodeHasher<HO>>(hasher: &H, k: &[u8], v: &[u8]) -> HO {
        hasher.calc_hash(&[k, v])
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Branch<HO> {
    prefix: KeyVec,
    hash: HO,
}
impl<HO> Branch<HO> {
    fn new(prefix: KeyVec, hash: HO) -> Self {
        assert!(!prefix.is_empty());
        Branch { prefix, hash }
    }
    fn dir(&self) -> Dir {
        Dir::from(self.prefix[0])
    }
    fn assert_dir(b: &Option<Branch<HO>>, d: Dir) {
        if let Some(b) = b {
            assert_eq!(d, b.dir(), "{:?} prefix is invalid {}", d, b.prefix);
        }
    }
}
impl<HO: Debug> Debug for Branch<HO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {:?}", self.prefix, self.hash)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
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
}
impl Display for Dir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dir::Left => f.write_str("Left"),
            Dir::Right => f.write_str("Right"),
        }
    }
}
pub struct ReadProof<HO> {
    key: Vec<u8>,
    leaf: Option<LeafNode<HO>>,
    // The path in root -> leaf order of the nodes traversed to get to the leaf. Or if the leaf
    // doesn't exist the furtherest existing node in the path of the key.
    path: Vec<InteriorNode<HO>>,
    // The direction to take for each item in the path. i.e. to get from path[0] to path[1] it
    // followed the dirs[0] direction in path[0]. This will be 1 smaller than the path.
    dirs: Vec<Dir>,
}
impl<HO: HashOutput> ReadProof<HO> {
    fn new(key: &[u8], root: InteriorNode<HO>) -> Self {
        ReadProof {
            key: key.to_vec(),
            leaf: None,
            path: vec![root],
            dirs: Vec::new(),
        }
    }
    fn add_to_path(&mut self, n: InteriorNode<HO>, d: Dir) {
        self.path.push(n);
        self.dirs.push(d);
    }
    fn prefix_of_path(&self) -> KeyVec {
        let mut p = KeyVec::with_capacity(self.key.len());
        for (n, d) in zip(&self.path, &self.dirs) {
            if let Some(b) = n.branch(*d) {
                p.extend(&b.prefix);
            }
        }
        p
    }

    // verify returns tree if the Proof is valid. This includes the
    // path check and hash verification.
    fn verify<H: NodeHasher<HO>>(&self, h: &H) -> bool {
        // Do some basic sanity checks of the Proof struct first.
        if self.key.is_empty() {
            return false;
        }
        if self.path.len() != self.dirs.len() + 1 {
            return false;
        }
        // Verify the provided path is for the key.
        // 1. Verify the path all the way to the last interior node.
        let pp = self.prefix_of_path();
        let key = KeySlice::from_slice(&self.key);
        if pp.len() >= key.len() || !key.starts_with(&pp) {
            return false;
        }
        // 2. Verify the tail of the path. This depends on if there's
        // a leaf or not.
        let key_tail = &key[pp.len()..];
        let tail_node = self
            .path
            .last()
            .expect("we verified above that path contains at least one item");
        match &self.leaf {
            // If there's a leaf, then the last interior node should have
            // a branch that points the leaf. The branches key prefix
            // should match what's left of the key.
            Some(_) => match tail_node.branch(Dir::from(key_tail[0])) {
                None => {
                    return false;
                }
                Some(b) => {
                    if key_tail != b.prefix {
                        return false;
                    }
                }
            },
            None => {
                // If there's no leaf then we need to verify that there isn't
                // a branch from the tail node that could lead to our key. This
                // prevents an attack where a tail intermedite node is removed
                // from the proof to try and claim the key doesn't exist.
                match tail_node.branch(Dir::from(key_tail[0])) {
                    None => {
                        // The branch that would lead to the leaf if it existed
                        // is empty, so that's fine.
                    }
                    Some(b) => {
                        // This branch shouldn't lead to a node that could
                        // contain the leaf.
                        if key_tail.starts_with(&b.prefix) {
                            return false;
                        }
                    }
                }
            }
        }

        // Verify all the hashes match.
        if let Some(leaf) = &self.leaf {
            let exp_hash = LeafNode::calc_hash(h, &self.key, &leaf.value);
            if exp_hash != leaf.hash {
                return false;
            }
        }
        for n in &self.path {
            let exp_hash = InteriorNode::calc_hash(h, &n.left, &n.right);
            if exp_hash != n.hash {
                return false;
            }
        }
        true
    }
}

pub struct Delta<HO> {
    add: Vec<InteriorNode<HO>>,
    leaf: LeafNode<HO>,
    remove: Vec<HO>,
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
            writeln!(f, "remove {:?}", n)?;
        }
        Ok(())
    }
}
impl<HO> Delta<HO> {
    fn new(new_leaf: LeafNode<HO>) -> Self {
        Delta {
            leaf: new_leaf,
            add: Vec::new(),
            remove: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum InsertError {
    InvalidProof,
}

#[derive(Clone)]
pub enum Node<HO> {
    Interior(InteriorNode<HO>),
    Leaf(LeafNode<HO>),
}

#[derive(Debug)]
pub enum TreeStoreError {
    NoSuchRecord,
}

pub trait TreeStoreReader<HO> {
    fn fetch(&self, k: &[u8]) -> Result<Node<HO>, TreeStoreError>;
}

pub trait HashOutput: Copy + Eq + Debug {
    fn as_u8(&self) -> &[u8];
}

pub trait NodeHasher<HO> {
    fn calc_hash(&self, parts: &[&[u8]]) -> HO;
}

fn common_prefix<'a, 'b, U: BitStore, O: BitOrder>(
    a: &'a BitSlice<U, O>,
    b: &'b BitSlice<U, O>,
) -> &'a BitSlice<U, O> {
    assert_eq!(a.len(), b.len());
    match zip(a.iter(), b.iter()).position(|(x, y)| x != y) {
        None => a,
        Some(p) => &a[..p],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::{collections::HashMap, hash::Hasher};

    #[test]
    fn get_nothing() {
        let (tree, root, store) = new_empty_tree();
        let p = tree.read(&store, &root, &[1, 2, 3]).unwrap();
        assert_eq!(1, p.path.len());
        assert_eq!(root, p.path[0].hash);
        assert!(p.leaf.is_none());
    }

    #[test]
    fn first_insert() {
        let (mut tree, mut root, mut store) = new_empty_tree();
        let rp = tree.read(&store, &root, &[1, 2, 3]).unwrap();
        let d = tree.insert(rp, [42].to_vec()).unwrap();
        assert_eq!(1, d.add.len());
        assert_eq!([42].to_vec(), d.leaf.value);
        assert_eq!(root, d.remove[0]);
        root = store.apply(d).unwrap();

        let p = tree.read(&store, &root, &[1, 2, 3]).unwrap();
        assert_eq!([42].to_vec(), p.leaf.as_ref().unwrap().value);
        assert_eq!(1, p.path.len());
        assert_eq!(root, p.path[0].hash);
    }

    #[test]
    fn insert_some() {
        let (mut tree, mut root, mut store) = new_empty_tree();
        root = tree_insert(&mut tree, &mut store, root, &[2, 6, 8], [42].to_vec());
        root = tree_insert(&mut tree, &mut store, root, &[4, 4, 6], [43].to_vec());
        root = tree_insert(&mut tree, &mut store, root, &[0, 2, 3], [44].to_vec());

        let p = tree.read(&store, &root, &[2, 6, 8]).unwrap();
        assert_eq!([42].to_vec(), p.leaf.unwrap().value);
        assert_eq!(3, p.path.len());
        assert_eq!(root, p.path[0].hash);
    }

    #[test]
    fn update_some() {
        let (mut tree, mut root, mut store) = new_empty_tree();
        root = tree_insert(&mut tree, &mut store, root, &[2, 6, 8], [42].to_vec());
        root = tree_insert(&mut tree, &mut store, root, &[4, 4, 6], [43].to_vec());
        // now do a read/write for an existing key
        root = tree_insert(&mut tree, &mut store, root, &[4, 4, 6], [44].to_vec());

        let rp = tree.read(&store, &root, &[4, 4, 6]).unwrap();
        assert_eq!([44].to_vec(), rp.leaf.unwrap().value);
    }

    #[test]
    fn test_insert_lots() {
        let (mut tree, mut root, mut store) = new_empty_tree();
        let seed = [0u8; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut key = [0u8; 4];
        let mut expected = HashMap::new();
        for i in 0..150 {
            rng.fill_bytes(&mut key);
            expected.insert(key.to_vec(), i);

            // write our new key/value
            root = tree_insert(&mut tree, &mut store, root, &key, [i].to_vec());

            // verify we can read all the key/values we've stored.
            for (k, v) in expected.iter() {
                let p = tree.read(&store, &root, k).unwrap();
                assert_eq!([*v].to_vec(), p.leaf.unwrap().value);
            }
            // if i == 16 {
            //     dot::tree_to_dot(root, &store, "many.dot").unwrap();
            // }
        }
    }

    #[test]
    fn test_read_proof_verify() {
        let (mut tree, mut root, mut store) = new_empty_tree();
        root = tree_insert(&mut tree, &mut store, root, &[1], [1].to_vec());
        root = tree_insert(&mut tree, &mut store, root, &[5], [2].to_vec());

        let mut p = tree.read(&store, &root, &[5]).unwrap();
        assert!(p.verify(&tree.hasher));

        // claim there's no leaf
        p.leaf = None;
        assert!(!p.verify(&tree.hasher));

        let mut p = tree.read(&store, &root, &[5]).unwrap();
        // truncate the tail of the path to claim there's no leaf
        p.leaf = None;
        p.path.pop();
        p.dirs.pop();
        assert!(!p.verify(&tree.hasher));

        let mut p = tree.read(&store, &root, &[5]).unwrap();
        // futz with the path
        p.key[0] = 2;
        assert!(!p.verify(&tree.hasher));

        // futz with the value (checks the hash)
        let mut p = tree.read(&store, &root, &[5]).unwrap();
        if let Some(ref mut l) = p.leaf {
            l.value[0] += 1;
        }
        assert!(!p.verify(&tree.hasher));

        // futz with a node (checks the hash)
        let mut p = tree.read(&store, &root, &[5]).unwrap();
        if let Some(ref mut b) = &mut p.path[0].left {
            b.prefix.pop();
        }
        assert!(!p.verify(&tree.hasher));
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

    fn new_empty_tree() -> (Tree<TestHasher, TestHash>, TestHash, MemStore<TestHash>) {
        let t = Tree::new(TestHasher {});
        let root_node = t.empty_root();
        let mut store = MemStore::new();
        let root_hash = root_node.hash;
        store.insert(root_hash, Node::Interior(root_node));
        (t, root_hash, store)
    }

    // helper to insert a value into the tree and update the store
    fn tree_insert(
        tree: &mut Tree<TestHasher, TestHash>,
        store: &mut MemStore<TestHash>,
        root: TestHash,
        key: &[u8],
        val: Vec<u8>,
    ) -> TestHash {
        let rp = tree.read(store, &root, key).unwrap();
        let d = tree.insert(rp, val).unwrap();
        store.apply(d).unwrap()
    }

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
        // Returns the new root hash.
        fn apply(&mut self, delta: Delta<HO>) -> Result<HO, TreeStoreError> {
            self.insert(delta.leaf.hash, Node::Leaf(delta.leaf));
            let root_hash = delta.add.last().unwrap().hash;
            for a in delta.add {
                self.insert(a.hash, Node::Interior(a));
            }
            for h in delta.remove {
                self.nodes.remove(h.as_u8());
            }
            Ok(root_hash)
        }
        fn insert(&mut self, k: HO, n: Node<HO>) {
            self.nodes.insert(k.as_u8().to_vec(), n);
        }
    }
    impl<HO: Clone> TreeStoreReader<HO> for MemStore<HO> {
        fn fetch(&self, k: &[u8]) -> Result<Node<HO>, TreeStoreError> {
            match self.nodes.get(k) {
                None => Err(TreeStoreError::NoSuchRecord),
                Some(n) => Ok(n.clone()),
            }
        }
    }
    struct TestHasher {}
    impl NodeHasher<TestHash> for TestHasher {
        fn calc_hash(&self, parts: &[&[u8]]) -> TestHash {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            for p in parts {
                h.write(*p);
            }
            TestHash(h.finish().to_le_bytes())
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
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
