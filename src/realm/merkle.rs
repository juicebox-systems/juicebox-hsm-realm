#![allow(dead_code)]

use bitvec::{order::Msb0, prelude::BitOrder, slice::BitSlice, store::BitStore, vec::BitVec};
use std::{
    collections::{HashMap, VecDeque},
    fmt::{Debug, Display},
    hash::Hash,
    iter::zip,
    marker::PhantomData,
};

use crate::realm::merkle::agent::Node;

pub mod agent;
pub mod dot;
mod overlay;

type KeyVec = BitVec<u8, Msb0>;
type KeySlice = BitSlice<u8, Msb0>;

// TODO
//  probably a bunch of stuff that should be pub but isn't
//  blake hasher
//
//  split
//      "simple split" where the root is split into 2
//      "complex split" split on arbitary keys
//  int node hash uses whole bytes of prefix path. needs to distingush between 0001 and 00010
//  compact_keyslice_str should be a wrapper type?
//  remove hash from nodes rely on hash being in parent?
//  docs
//  more tests

pub struct Tree<H: NodeHasher<HO>, HO> {
    hasher: H,
    overlay: overlay::TreeOverlay<HO>,
    _marker: PhantomData<HO>,
}
impl<H: NodeHasher<HO>, HO: HashOutput> Tree<H, HO> {
    pub fn new_tree(hasher: H) -> (Self, InteriorNode<HO>) {
        let root = InteriorNode::new(&hasher, None, None);
        let t = Tree {
            hasher,
            overlay: overlay::TreeOverlay::new(root.hash, 15),
            _marker: PhantomData,
        };
        (t, root)
    }

    pub fn with_existing_root(hasher: H, root: HO) -> Self {
        Tree {
            hasher,
            overlay: overlay::TreeOverlay::new(root, 15),
            _marker: PhantomData,
        }
    }

    // Insert a new value for the leaf described by the read proof. Returns a set
    // of changes that need making to the tree storage. In the event the insert results
    // in no changes (i.e. the insert is inserting the same value as its current value)
    // None is returned.
    pub fn insert(
        &mut self,
        rp: ReadProof<HO>,
        v: Vec<u8>,
    ) -> Result<Option<Delta<HO>>, InsertError> {
        if !rp.verify(&self.hasher) {
            return Err(InsertError::InvalidProof);
        }
        if !self.overlay.roots.contains(&rp.path[0].hash) {
            return Err(InsertError::StaleProof);
        }
        // Convert the proof into a map of hash -> node.
        let (proof_nodes, key) = rp.make_node_map();

        let mut delta = Delta::new(LeafNode::new(&self.hasher, &key, v));
        let key = KeySlice::from_slice(&key);
        match self.insert_into_tree(&proof_nodes, &mut delta, self.overlay.latest_root, key) {
            Err(e) => Err(e),
            Ok(None) => Ok(None),
            Ok(Some(_)) => {
                self.overlay.add_delta(&delta);
                Ok(Some(delta))
            }
        }
    }

    fn insert_into_tree(
        &self,
        proof_nodes: &HashMap<HO, Node<HO>>,
        delta: &mut Delta<HO>,
        node: HO,
        key: &KeySlice,
    ) -> Result<Option<HO>, InsertError> {
        //
        match self
            .overlay
            .nodes
            .get(&node)
            .or_else(|| proof_nodes.get(&node))
        {
            None => Err(InsertError::StaleProof),
            Some(Node::Leaf(l)) => {
                if l.hash != delta.leaf.hash {
                    delta.remove.push(l.hash);
                    Ok(Some(delta.leaf.hash))
                } else {
                    Ok(None)
                }
            }
            Some(Node::Interior(int)) => {
                let dir = Dir::from(key[0]);
                match int.branch(dir) {
                    None => {
                        // There's no existing entry for the branch we want to use. We update it to point to the new leaf.
                        let new_b = Branch::new(key.into(), delta.leaf.hash);
                        let updated_n = int.with_new_child(&self.hasher, dir, new_b);
                        let new_hash = updated_n.hash;
                        delta.add.push(updated_n);
                        delta.remove.push(int.hash);
                        Ok(Some(new_hash))
                    }
                    Some(b) => {
                        if key.starts_with(&b.prefix) {
                            // The branch goes along our keypath, head down the path.
                            return match self.insert_into_tree(
                                proof_nodes,
                                delta,
                                b.hash,
                                &key[b.prefix.len()..],
                            ) {
                                Err(e) => Err(e),
                                Ok(None) => Ok(None),
                                Ok(Some(child_hash)) => {
                                    let updated_n =
                                        int.with_new_child_hash(&self.hasher, dir, child_hash);
                                    let new_hash = updated_n.hash;
                                    delta.add.push(updated_n);
                                    delta.remove.push(int.hash);
                                    Ok(Some(new_hash))
                                }
                            };
                        }
                        // Branch points to somewhere else.
                        // We need to create a new child interior node from this branch that
                        // contains (new_leaf, prev_branch_dest).
                        // The current branch should have its prefix shortened to the common prefix.
                        let kp = &key[..b.prefix.len()];
                        let comm = common_prefix(kp, &b.prefix);
                        let new_child = InteriorNode::construct(
                            &self.hasher,
                            Some(Branch::new(key[comm.len()..].into(), delta.leaf.hash)),
                            Some(Branch::new(b.prefix[comm.len()..].into(), b.hash)),
                        );
                        let updated_n = int.with_new_child(
                            &self.hasher,
                            dir,
                            Branch::new(comm.into(), new_child.hash),
                        );
                        let new_hash = updated_n.hash;
                        delta.add.push(new_child);
                        delta.add.push(updated_n);
                        delta.remove.push(int.hash);
                        Ok(Some(new_hash))
                    }
                }
            }
        }
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
        &self,
        h: &H,
        dir: Dir,
        child: Branch<HO>,
    ) -> InteriorNode<HO> {
        match dir {
            Dir::Left => InteriorNode::new(h, Some(child), self.right.clone()),
            Dir::Right => InteriorNode::new(h, self.left.clone(), Some(child)),
        }
    }
    fn with_new_child_hash<H: NodeHasher<HO>>(
        &self,
        h: &H,
        dir: Dir,
        hash: HO,
    ) -> InteriorNode<HO> {
        let b = self.branch(dir).as_ref().unwrap();
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
    path: VecDeque<InteriorNode<HO>>,
}
impl<HO: HashOutput> ReadProof<HO> {
    fn new(key: &[u8], root: InteriorNode<HO>) -> Self {
        let mut p = ReadProof {
            key: key.to_vec(),
            leaf: None,
            path: VecDeque::new(),
        };
        p.path.push_back(root);
        p
    }
    // returns the key prefix of the contained path. It does not include
    // any prefix that decends from the last node.
    fn prefix_to_path_tail(&self) -> KeyVec {
        let mut key = KeySlice::from_slice(&self.key);
        let mut p = KeyVec::with_capacity(key.len());
        for (i, n) in self.path.iter().enumerate() {
            // don't add anything from the last node
            if i < self.path.len() - 1 {
                if let Some(b) = n.branch(Dir::from(key[0])) {
                    key = &key[b.prefix.len()..];
                    p.extend(&b.prefix);
                }
            }
        }
        p
    }

    // verify returns tree if the Proof is valid. This includes the
    // path check and hash verification.
    fn verify<H: NodeHasher<HO>>(&self, h: &H) -> bool {
        // Do some basic sanity checks of the Proof struct first.
        if self.key.is_empty() || self.path.is_empty() {
            return false;
        }
        // Verify the provided path is for the key.
        // 1. Verify the path all the way to the last interior node.
        let pp = self.prefix_to_path_tail();
        let key = KeySlice::from_slice(&self.key);
        if pp.len() >= key.len() || !key.starts_with(&pp) {
            return false;
        }
        // 2. Verify the tail of the path. This depends on if there's
        // a leaf or not.
        let key_tail = &key[pp.len()..];
        let tail_node = self
            .path
            .back()
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

    // Consumes the proof returning a hashmap containing all the nodes in the proof along with the key.
    fn make_node_map(self) -> (HashMap<HO, Node<HO>>, Vec<u8>) {
        let mut proof_nodes = HashMap::with_capacity(self.path.len() + 1);
        if let Some(l) = self.leaf {
            proof_nodes.insert(l.hash, Node::Leaf(l));
        }
        for n in self.path {
            proof_nodes.insert(n.hash, Node::Interior(n));
        }
        (proof_nodes, self.key)
    }
}

pub struct Delta<HO> {
    // Nodes are in tail -> root order.
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
    fn root(&self) -> &HO {
        &self
            .add
            .last()
            .expect("add should contain at least a new root")
            .hash
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum InsertError {
    InvalidProof,
    // The ReadProof is too old, calculate a newer one and try again.
    StaleProof,
}

pub trait HashOutput: Hash + Copy + Eq + Debug {
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
    use super::{
        agent::{read, Node, TreeStoreError, TreeStoreReader},
        *,
    };
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::{collections::HashMap, hash::Hasher};

    #[test]
    fn get_nothing() {
        let (tree, root, store) = new_empty_tree();
        let p = read(&store, &root, &[1, 2, 3]).unwrap();
        assert_eq!(1, p.path.len());
        assert_eq!(root, p.path[0].hash);
        assert!(p.leaf.is_none());
        check_tree_invariants(&tree.hasher, root, &store);
    }

    #[test]
    fn first_insert() {
        let (mut tree, mut root, mut store) = new_empty_tree();
        let rp = read(&store, &root, &[1, 2, 3]).unwrap();
        let d = tree.insert(rp, [42].to_vec()).unwrap().unwrap();
        assert_eq!(1, d.add.len());
        assert_eq!([42].to_vec(), d.leaf.value);
        assert_eq!(root, d.remove[0]);
        root = store.apply(d);
        check_tree_invariants(&tree.hasher, root, &store);

        let p = read(&store, &root, &[1, 2, 3]).unwrap();
        assert_eq!([42].to_vec(), p.leaf.as_ref().unwrap().value);
        assert_eq!(1, p.path.len());
        assert_eq!(root, p.path[0].hash);
        check_tree_invariants(&tree.hasher, root, &store);
    }

    #[test]
    fn insert_some() {
        let (mut tree, mut root, mut store) = new_empty_tree();
        root = tree_insert(&mut tree, &mut store, root, &[2, 6, 8], [42].to_vec());
        root = tree_insert(&mut tree, &mut store, root, &[4, 4, 6], [43].to_vec());
        root = tree_insert(&mut tree, &mut store, root, &[0, 2, 3], [44].to_vec());

        let p = read(&store, &root, &[2, 6, 8]).unwrap();
        assert_eq!([42].to_vec(), p.leaf.unwrap().value);
        assert_eq!(3, p.path.len());
        assert_eq!(root, p.path[0].hash);
        check_tree_invariants(&tree.hasher, root, &store);
    }

    #[test]
    fn update_some() {
        let (mut tree, mut root, mut store) = new_empty_tree();
        root = tree_insert(&mut tree, &mut store, root, &[2, 6, 8], [42].to_vec());
        root = tree_insert(&mut tree, &mut store, root, &[4, 4, 6], [43].to_vec());
        // now do a read/write for an existing key
        root = tree_insert(&mut tree, &mut store, root, &[4, 4, 6], [44].to_vec());

        let rp = read(&store, &root, &[4, 4, 6]).unwrap();
        assert_eq!([44].to_vec(), rp.leaf.unwrap().value);
        check_tree_invariants(&tree.hasher, root, &store);

        // writing the same value again shouldn't do anything dumb, like cause the leaf to be deleted.
        root = tree_insert(&mut tree, &mut store, root, &[4, 4, 6], [44].to_vec());
        let rp = read(&store, &root, &[4, 4, 6]).unwrap();
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
                let p = read(&store, &root, k).unwrap();
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

        let mut p = read(&store, &root, &[5]).unwrap();
        assert!(p.verify(&tree.hasher));

        // claim there's no leaf
        p.leaf = None;
        assert!(!p.verify(&tree.hasher));

        let mut p = read(&store, &root, &[5]).unwrap();
        // truncate the tail of the path to claim there's no leaf
        p.leaf = None;
        p.path.pop_back();
        assert!(!p.verify(&tree.hasher));

        let mut p = read(&store, &root, &[5]).unwrap();
        // futz with the path
        p.key[0] = 2;
        assert!(!p.verify(&tree.hasher));

        // futz with the value (checks the hash)
        let mut p = read(&store, &root, &[5]).unwrap();
        if let Some(ref mut l) = p.leaf {
            l.value[0] += 1;
        }
        assert!(!p.verify(&tree.hasher));

        // futz with a node (checks the hash)
        let mut p = read(&store, &root, &[5]).unwrap();
        if let Some(ref mut b) = &mut p.path[0].left {
            b.prefix.pop();
        }
        assert!(!p.verify(&tree.hasher));
    }

    #[test]
    fn test_insert_pipeline() {
        let (mut tree, mut root, mut store) = new_empty_tree();
        root = tree_insert(&mut tree, &mut store, root, &[1], [1].to_vec());
        let rp_1 = read(&store, &root, &[1]).unwrap();
        let rp_2 = read(&store, &root, &[2]).unwrap();
        let rp_3 = read(&store, &root, &[3]).unwrap();
        let d1 = tree.insert(rp_1, [11].to_vec()).unwrap().unwrap();
        let d2 = tree.insert(rp_2, [12].to_vec()).unwrap().unwrap();
        let d3 = tree.insert(rp_3, [13].to_vec()).unwrap().unwrap();
        root = store.apply(d1);
        check_tree_invariants(&tree.hasher, root, &store);
        root = store.apply(d2);
        check_tree_invariants(&tree.hasher, root, &store);
        root = store.apply(d3);
        check_tree_invariants(&tree.hasher, root, &store);

        let rp_1 = read(&store, &root, &[1]).unwrap();
        assert_eq!([11].to_vec(), rp_1.leaf.unwrap().value);
        let rp_2 = read(&store, &root, &[2]).unwrap();
        assert_eq!([12].to_vec(), rp_2.leaf.unwrap().value);
        let rp_3 = read(&store, &root, &[3]).unwrap();
        assert_eq!([13].to_vec(), rp_3.leaf.unwrap().value);
    }

    #[test]
    fn test_stale_proof() {
        let (mut tree, mut root, mut store) = new_empty_tree();
        root = tree_insert(&mut tree, &mut store, root, &[1], [1].to_vec());
        let rp_1 = read(&store, &root, &[1]).unwrap();
        for i in 0..20 {
            root = tree_insert(&mut tree, &mut store, root, &[2], [i].to_vec());
        }
        let d = tree
            .insert(rp_1, [11].to_vec())
            .expect_err("should of failed");
        assert_eq!(InsertError::StaleProof, d);
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
        let (t, root_node) = Tree::new_tree(TestHasher {});
        let mut store = MemStore::new();
        let root_hash = root_node.hash;
        store.insert(root_hash, Node::Interior(root_node));
        check_tree_invariants(&t.hasher, root_hash, &store);
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
        let rp = read(store, &root, key).unwrap();
        let new_root = match tree.insert(rp, val).unwrap() {
            None => root,
            Some(d) => store.apply(d),
        };
        check_tree_invariants(&tree.hasher, new_root, store);
        new_root
    }

    // walks the tree starting at root verifying all the invariants are all true
    //      1. only the root may have an empty branch
    //      2. the left branch prefix always starts with a 0
    //      3. the right branch prefix always starts with a 1
    //      5. the leaf -> root hashes are verified.
    fn check_tree_invariants<HO: HashOutput>(
        hasher: &impl NodeHasher<HO>,
        root: HO,
        store: &impl TreeStoreReader<HO>,
    ) {
        let root_hash = check_tree_node_invariants(hasher, true, root, KeySlice::empty(), store);
        assert_eq!(root_hash, root);
    }
    fn check_tree_node_invariants<HO: HashOutput>(
        hasher: &impl NodeHasher<HO>,
        is_at_root: bool,
        node: HO,
        path: &KeySlice,
        store: &impl TreeStoreReader<HO>,
    ) -> HO {
        match store.fetch(node.as_u8()).unwrap() {
            Node::Leaf(l) => {
                let exp_hash = LeafNode::calc_hash(hasher, &path.to_bitvec().into_vec(), &l.value);
                assert_eq!(exp_hash, l.hash);
                exp_hash
            }
            Node::Interior(int) => {
                match &int.left {
                    None => assert!(is_at_root),
                    Some(b) => {
                        assert!(!b.prefix.is_empty());
                        assert!(!b.prefix[0]);
                        let mut new_path = path.to_bitvec();
                        new_path.extend(&b.prefix);
                        let exp_child_hash =
                            check_tree_node_invariants(hasher, false, b.hash, &new_path, store);
                        assert_eq!(exp_child_hash, b.hash);
                    }
                }
                match &int.right {
                    None => assert!(is_at_root),
                    Some(b) => {
                        assert!(!b.prefix.is_empty());
                        assert!(b.prefix[0]);
                        let mut new_path = path.to_bitvec();
                        new_path.extend(&b.prefix);
                        let exp_child_hash =
                            check_tree_node_invariants(hasher, false, b.hash, &new_path, store);
                        assert_eq!(exp_child_hash, b.hash);
                    }
                }
                let exp_hash = InteriorNode::calc_hash(hasher, &int.left, &int.right);
                assert_eq!(exp_hash, int.hash);
                exp_hash
            }
        }
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
