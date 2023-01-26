#![allow(dead_code)]

use bitvec::prelude::*;
use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    hash::Hash,
    iter::{once, zip},
};

use self::agent::{Node, StoreDelta};
use self::overlay::TreeOverlay;

pub mod agent;
pub mod dot;
mod overlay;

pub type KeyVec = BitVec<u8, Msb0>;
pub type KeySlice = BitSlice<u8, Msb0>;

// TODO
//  probably a bunch of stuff that should be pub but isn't
//  blake hasher
//
//  split
//      "complex split" split on arbitrary keys
//  merge
//      merge a simple split back into one tree
//
//  compact_keyslice_str should be a wrapper type?
//  remove hash from nodes rely on hash being in parent?
//  docs
//  more tests

pub struct Tree<H: NodeHasher<HO>, HO> {
    hasher: H,
    key_size: usize,
    overlay: TreeOverlay<HO>,
}
impl<H: NodeHasher<HO>, HO: HashOutput> Tree<H, HO> {
    // Creates a new empty tree. Returns the root hash along with the storage delta required to create the tree.
    // If this tree is a partition of a larger tree, then pass the prefix of this partition.
    pub fn new_tree(hasher: &H, tree_prefix: &KeyVec) -> (HO, StoreDelta<HO>) {
        let root = InteriorNode::new(hasher, tree_prefix, None, None);
        (
            root.hash,
            StoreDelta {
                add: vec![Node::Interior(root)],
                remove: Vec::new(),
            },
        )
    }

    // Create a new Tree instance for a previously constructed tree given the root hash
    // of the tree's content. key_size should be the total size of a key in bits including
    // any prefix from being a partition.
    pub fn with_existing_root(hasher: H, key_size: usize, root: HO) -> Self {
        assert!(key_size % 8 == 0);
        Tree {
            hasher,
            key_size,
            overlay: TreeOverlay::new(root, 15),
        }
    }

    // Return the most recent value for the RecordId in the read proof.
    pub fn latest_value(&self, rp: ReadProof<HO>) -> Result<Option<Vec<u8>>, TreeError> {
        if !rp.verify(&self.hasher) {
            return Err(TreeError::InvalidProof);
        }
        self.overlay.latest_value(rp)
    }

    // Insert a new value for the leaf described by the read proof. Returns a set
    // of changes that need making to the tree storage. In the event the insert results
    // in no changes (i.e. the insert is inserting the same value as its current value)
    // None is returned.
    pub fn insert(
        &mut self,
        rp: ReadProof<HO>,
        v: Vec<u8>,
    ) -> Result<Option<Delta<HO>>, TreeError> {
        if rp.key.len() * 8 != self.key_size {
            return Err(TreeError::InvalidKey);
        }
        if !rp.verify(&self.hasher) {
            return Err(TreeError::InvalidProof);
        }
        if !self.overlay.roots.contains(&rp.path[0].hash) {
            return Err(TreeError::StaleProof);
        }
        let prefix_size = rp.prefix_size;
        // Convert the proof into a map of hash -> node.
        let (proof_nodes, key) = rp.make_node_map();

        let mut delta = Delta::new(LeafNode::new(&self.hasher, &key, v));
        match self.insert_into_tree(
            &proof_nodes,
            &mut delta,
            self.overlay.latest_root,
            KeySlice::from_slice(&key),
            prefix_size,
        ) {
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
        whole_key: &KeySlice,
        // key_pos represents the point where the key is split between the prefix leading to this node,
        // and the tail of key left to traverse.
        key_pos: usize,
    ) -> Result<Option<HO>, TreeError> {
        //
        match self
            .overlay
            .nodes
            .get(&node)
            .or_else(|| proof_nodes.get(&node))
        {
            None => Err(TreeError::StaleProof),
            Some(Node::Leaf(l)) => {
                if l.hash != delta.leaf.hash {
                    delta.remove.push(l.hash);
                    Ok(Some(delta.leaf.hash))
                } else {
                    Ok(None)
                }
            }
            Some(Node::Interior(int)) => {
                let dir = Dir::from(whole_key[key_pos]);
                match int.branch(dir) {
                    None => {
                        // There's no existing entry for the branch we want to use. We update it to point to the new leaf.
                        let new_b = Branch::new(whole_key[key_pos..].into(), delta.leaf.hash);
                        let updated_n = int.with_new_child(
                            &self.hasher,
                            &whole_key[..key_pos].into(),
                            dir,
                            new_b,
                        );
                        let new_hash = updated_n.hash;
                        delta.add.push(updated_n);
                        delta.remove.push(int.hash);
                        Ok(Some(new_hash))
                    }
                    Some(b) => {
                        if whole_key[key_pos..].starts_with(&b.prefix) {
                            // The branch goes along our keypath, head down the path.
                            match self.insert_into_tree(
                                proof_nodes,
                                delta,
                                b.hash,
                                whole_key,
                                key_pos + b.prefix.len(),
                            ) {
                                Err(e) => Err(e),
                                Ok(None) => Ok(None),
                                Ok(Some(child_hash)) => {
                                    let updated_n = int.with_new_child_hash(
                                        &self.hasher,
                                        &whole_key[..key_pos].into(),
                                        dir,
                                        child_hash,
                                    );
                                    let new_hash = updated_n.hash;
                                    delta.add.push(updated_n);
                                    delta.remove.push(int.hash);
                                    Ok(Some(new_hash))
                                }
                            }
                        } else {
                            // Branch points to somewhere else.
                            // We need to create a new child interior node from this branch that
                            // contains (new_leaf, prev_branch_dest).
                            // The current branch should have its prefix shortened to the common prefix.
                            let kp = &whole_key[key_pos..key_pos + b.prefix.len()];
                            let comm = common_prefix(kp, &b.prefix);
                            let new_child = InteriorNode::construct(
                                &self.hasher,
                                &whole_key[..key_pos + comm.len()].into(),
                                Some(Branch::new(
                                    whole_key[key_pos + comm.len()..].into(),
                                    delta.leaf.hash,
                                )),
                                Some(Branch::new(b.prefix[comm.len()..].into(), b.hash)),
                            );
                            let updated_n = int.with_new_child(
                                &self.hasher,
                                &whole_key[..key_pos].into(),
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

    // Splits the current tree in half by removing the root and promoting its children to be
    // new roots. Note that this will invalidate any read proofs generated before the split.
    // It requires a read proof for any key that's owned by this tree, doesn't need to have a value.
    // This consumes self. You'll need to construct new Tree instance(s) from the returned
    // splits.
    pub fn split_tree(
        &mut self,
        current_prefix: &KeySlice,
        rp: ReadProof<HO>,
    ) -> Result<SplitResult<HO>, TreeError> {
        // The ReadProof deals with an edge case where there have been no writes since
        // 'self' was constructed.
        if !rp.verify(&self.hasher) {
            return Err(TreeError::InvalidProof);
        }
        if !self.overlay.roots.contains(&rp.path[0].hash) {
            return Err(TreeError::StaleProof);
        }
        let root_node = if rp.path[0].hash == self.overlay.latest_root {
            &rp.path[0]
        } else {
            match self.overlay.nodes.get(&self.overlay.latest_root) {
                None => return Err(TreeError::StaleProof),
                Some(Node::Leaf(_)) => panic!("unexpected leaf at root of tree"),
                Some(Node::Interior(int)) => int,
            }
        };
        let mut delta = StoreDelta::new();
        delta.remove.push(self.overlay.latest_root);
        let left = self.make_branch_root(current_prefix, &root_node.left, Dir::Left, &mut delta);
        let right = self.make_branch_root(current_prefix, &root_node.right, Dir::Right, &mut delta);
        let r = SplitResult {
            old_root: self.overlay.latest_root,
            left,
            right,
            delta,
        };
        Ok(r)
    }

    fn make_branch_root(
        &self,
        current_prefix: &KeySlice,
        b: &Option<Branch<HO>>,
        d: Dir,
        delta: &mut StoreDelta<HO>,
    ) -> SplitRoot<HO> {
        let mut new_prefix = current_prefix.to_bitvec();
        new_prefix.push(d == Dir::Right);
        match b {
            None => {
                // There's no existing child for this branch, so we need to make a new root node.
                let new_root = InteriorNode::new(&self.hasher, &new_prefix, None, None);
                let root_hash = new_root.hash;
                delta.add.push(Node::Interior(new_root));
                SplitRoot {
                    root_hash,
                    prefix: new_prefix,
                }
            }
            Some(b) => {
                // If the prefix is only a single bit, then the existing child can become the new root.
                if b.prefix.len() == 1 {
                    SplitRoot {
                        root_hash: b.hash,
                        prefix: new_prefix,
                    }
                } else {
                    // If there's a longer prefix then we need a new root node that points to the existing child and
                    // consumes the first bit of its prefix.
                    let new_root = InteriorNode::construct(
                        &self.hasher,
                        &new_prefix,
                        None,
                        Some(Branch::new(b.prefix[1..].into(), b.hash)),
                    );
                    let root_hash = new_root.hash;
                    delta.add.push(Node::Interior(new_root));
                    SplitRoot {
                        root_hash,
                        prefix: new_prefix,
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
        key_prefix: &KeyVec,
        left: Option<Branch<HO>>,
        right: Option<Branch<HO>>,
    ) -> InteriorNode<HO> {
        Branch::assert_dir(&left, Dir::Left);
        Branch::assert_dir(&right, Dir::Right);
        let hash = Self::calc_hash(h, key_prefix, &left, &right);
        InteriorNode { left, right, hash }
    }
    // construct returns a new InteriorNode with the supplied children. It will determine
    // which should be left and right. If you know which should be left & right use new instead.
    // TODO: get rid of new and always use this?
    fn construct<H: NodeHasher<HO>>(
        h: &H,
        key_prefix: &KeyVec,
        a: Option<Branch<HO>>,
        b: Option<Branch<HO>>,
    ) -> InteriorNode<HO> {
        match (&a, &b) {
            (None, None) => Self::new(h, key_prefix, None, None),
            (Some(x), _) => {
                let (l, r) = if x.dir() == Dir::Left { (a, b) } else { (b, a) };
                Self::new(h, key_prefix, l, r)
            }
            (_, Some(x)) => {
                let (l, r) = if x.dir() == Dir::Left { (b, a) } else { (a, b) };
                Self::new(h, key_prefix, l, r)
            }
        }
    }
    fn calc_hash<H: NodeHasher<HO>>(
        h: &H,
        key_prefix: &KeyVec,
        left: &Option<Branch<HO>>,
        right: &Option<Branch<HO>>,
    ) -> HO {
        let mut parts: [&[u8]; 9] = [&[], &[], &[], &[], &[], &[42], &[], &[], &[]];
        let kp_len = key_prefix.len().to_le_bytes();
        parts[0] = &kp_len;
        parts[1] = key_prefix.as_raw_slice();
        let left_len;
        if let Some(b) = left {
            left_len = b.prefix.len().to_le_bytes();
            parts[2] = &left_len;
            parts[3] = b.prefix.as_raw_slice();
            parts[4] = b.hash.as_u8();
        }
        let right_len;
        if let Some(b) = right {
            right_len = b.prefix.len().to_le_bytes();
            parts[6] = &right_len;
            parts[7] = b.prefix.as_raw_slice();
            parts[8] = b.hash.as_u8();
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
        key_prefix: &KeyVec,
        dir: Dir,
        child: Branch<HO>,
    ) -> InteriorNode<HO> {
        match dir {
            Dir::Left => InteriorNode::new(h, key_prefix, Some(child), self.right.clone()),
            Dir::Right => InteriorNode::new(h, key_prefix, self.left.clone(), Some(child)),
        }
    }
    fn with_new_child_hash<H: NodeHasher<HO>>(
        &self,
        h: &H,
        key_prefix: &KeyVec,
        dir: Dir,
        hash: HO,
    ) -> InteriorNode<HO> {
        let b = self.branch(dir).as_ref().unwrap();
        let nb = Branch::new(b.prefix.clone(), hash);
        self.with_new_child(h, key_prefix, dir, nb)
    }
}

#[derive(Debug, Clone)]
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
        write!(
            f,
            "{} -> {:?}",
            dot::compact_keyslice_str(&self.prefix, " "),
            self.hash
        )
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

#[derive(Debug, Clone)]
pub struct ReadProof<HO> {
    // Key is the full key.
    pub key: Vec<u8>,
    // The number of bits from the start of the key that are the partition prefix for the tree
    // partition.
    prefix_size: usize,
    leaf: Option<LeafNode<HO>>,
    // The path in root -> leaf order of the nodes traversed to get to the leaf. Or if the leaf
    // doesn't exist the furthest existing node in the path of the key.
    path: Vec<InteriorNode<HO>>,
}
impl<HO: HashOutput> ReadProof<HO> {
    fn new(key: &[u8], prefix_size: usize, root: InteriorNode<HO>) -> Self {
        let mut p = ReadProof {
            key: key.to_vec(),
            prefix_size,
            leaf: None,
            path: Vec::new(),
        };
        p.path.push(root);
        p
    }

    pub fn root_hash(&self) -> HO {
        self.path[0].hash
    }

    pub fn leaf_value(&self) -> Option<&Vec<u8>> {
        self.leaf.as_ref().map(|l| &l.value)
    }

    // Verify returns tree if the Proof is valid. This includes the
    // path check and hash verification.
    pub fn verify<H: NodeHasher<HO>>(&self, h: &H) -> bool {
        // Do some basic sanity checks of the Proof struct first.
        if self.key.is_empty() || self.path.is_empty() || self.prefix_size >= self.key.len() * 8 {
            return false;
        }
        // Verify the leaf hash matches
        if let Some(leaf) = &self.leaf {
            let exp_hash = LeafNode::calc_hash(h, &self.key, &leaf.value);
            if exp_hash != leaf.hash {
                return false;
            }
        }
        // We can't directly verify that key[..prefix_size] is correct, however as the
        // entire key prefix is in each hash, the hash verifications will spot if someone
        // tampers with that leading part of the key.
        self.verify_path(
            h,
            KeySlice::from_slice(&self.key),
            self.prefix_size,
            &self.path[0],
            &self.path[1..],
        )
        .is_ok()
    }

    // Walks down the path and
    //      1. verifies the key & path match.
    //      2. verifies the terminal conditions are correct.
    //          a. If there's a leaf the last interior node should have a branch to it.
    //          b. If there's no leaf, the last interior node should not have a branch
    //             that could possibly lead to the key.
    //      3. recalculates & verifies the hashes on the way back up.
    fn verify_path<H: NodeHasher<HO>>(
        &self,
        h: &H,
        whole_key: &KeySlice,
        key_pos: usize,
        node: &InteriorNode<HO>,
        path_tail: &[InteriorNode<HO>],
    ) -> Result<HO, ()> {
        let dir = Dir::from(whole_key[key_pos]);
        match node.branch(dir).as_ref() {
            None => {
                match &self.leaf {
                    Some(_) => {
                        // If there's no branch, there can't be a leaf.
                        Err(())
                    }
                    None => {
                        // We reached an empty branch and there's no existing leaf.
                        // We should be at the bottom of the path.
                        if !path_tail.is_empty() {
                            return Err(());
                        }
                        // verify this nodes hash.
                        let ch = InteriorNode::calc_hash(
                            h,
                            &whole_key[..key_pos].into(),
                            &node.left,
                            &node.right,
                        );
                        if ch != node.hash {
                            return Err(());
                        }
                        Ok(ch)
                    }
                }
            }
            Some(b) => {
                if path_tail.is_empty() {
                    // This is the last InteriorNode on the path. This should point
                    // to the leaf, or to a different key altogether.
                    match &self.leaf {
                        Some(lh) => {
                            // The branch prefix should point to the remainder of the key
                            // and it should have the leaf's hash.
                            if (whole_key[key_pos..] != b.prefix) || (lh.hash != b.hash) {
                                return Err(());
                            }
                            let nh = node.with_new_child_hash(
                                h,
                                &whole_key[..key_pos].into(),
                                dir,
                                lh.hash,
                            );
                            if nh.hash != node.hash {
                                return Err(());
                            }
                            Ok(nh.hash)
                        }
                        None => {
                            // This branch should not be able to lead to the key.
                            if whole_key[key_pos..].starts_with(&b.prefix) {
                                return Err(());
                            }
                            let nh = InteriorNode::calc_hash(
                                h,
                                &whole_key[..key_pos].into(),
                                &node.left,
                                &node.right,
                            );
                            if nh != node.hash {
                                return Err(());
                            }
                            Ok(nh)
                        }
                    }
                } else {
                    // keep going down
                    if whole_key[key_pos..key_pos + b.prefix.len()] != b.prefix {
                        return Err(());
                    }
                    let child_h = self.verify_path(
                        h,
                        whole_key,
                        key_pos + b.prefix.len(),
                        &path_tail[0],
                        &path_tail[1..],
                    )?;
                    if child_h != b.hash {
                        return Err(());
                    }
                    let nh =
                        node.with_new_child_hash(h, &whole_key[..key_pos].into(), dir, child_h);
                    if nh.hash != node.hash {
                        return Err(());
                    }
                    Ok(nh.hash)
                }
            }
        }
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

// The result of performing a split operation on the tree. The tree is split
// into 2 halves.
pub struct SplitResult<HO> {
    // The previous root hash.
    pub old_root: HO,
    // The new root of the tree that is being kept.
    pub left: SplitRoot<HO>,
    // The new root for the tree that is being given away to another group/partition.
    pub right: SplitRoot<HO>,
    // The delta that needs applying to the store to perform the split.
    pub delta: StoreDelta<HO>,
}
pub struct SplitRoot<HO> {
    // The new root hash of this split off branch.
    pub root_hash: HO,
    // The new full key prefix to this new tree.
    pub prefix: KeyVec,
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
        StoreDelta {
            add: self
                .add
                .into_iter()
                .map(|n| Node::Interior(n))
                .chain(once(Node::Leaf(self.leaf)))
                .collect(),
            remove: self.remove,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TreeError {
    InvalidProof,
    // The ReadProof is too old, calculate a newer one and try again.
    StaleProof,
    // Invalid key. The supplied key is not the correct size.
    InvalidKey,
}

pub trait HashOutput: Hash + Copy + Eq + Debug {
    fn as_u8(&self) -> &[u8];
}

pub trait NodeHasher<HO> {
    fn calc_hash(&self, parts: &[&[u8]]) -> HO;
}

fn common_prefix<'a, U: BitStore, O: BitOrder>(
    a: &'a BitSlice<U, O>,
    b: &BitSlice<U, O>,
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
        let (tree, root, store) = new_empty_tree(&KeyVec::new(), 24);
        let p = read(&store, &root, &[1, 2, 3], 0).unwrap();
        assert_eq!(1, p.path.len());
        assert_eq!(root, p.path[0].hash);
        assert!(p.leaf.is_none());
        check_tree_invariants(&tree.hasher, &BitVec::new(), root, &store);
    }

    #[test]
    fn first_insert() {
        let (mut tree, mut root, mut store) = new_empty_tree(&KeyVec::new(), 24);
        let rp = read(&store, &root, &[1, 2, 3], 0).unwrap();
        let d = tree.insert(rp, [42].to_vec()).unwrap().unwrap();
        assert_eq!(1, d.add.len());
        assert_eq!([42].to_vec(), d.leaf.value);
        assert_eq!(root, d.remove[0]);
        root = store.apply(d);
        check_tree_invariants(&tree.hasher, &BitVec::new(), root, &store);

        let p = read(&store, &root, &[1, 2, 3], 0).unwrap();
        assert_eq!([42].to_vec(), p.leaf.as_ref().unwrap().value);
        assert_eq!(1, p.path.len());
        assert_eq!(root, p.path[0].hash);
        check_tree_invariants(&tree.hasher, &BitVec::new(), root, &store);
    }

    #[test]
    fn insert_some() {
        let prefix = KeyVec::new();
        let (mut tree, mut root, mut store) = new_empty_tree(&prefix, 24);
        root = tree_insert(
            &mut tree,
            &mut store,
            root,
            &[2, 6, 8],
            &prefix,
            [42].to_vec(),
        );
        root = tree_insert(
            &mut tree,
            &mut store,
            root,
            &[4, 4, 6],
            &prefix,
            [43].to_vec(),
        );
        root = tree_insert(
            &mut tree,
            &mut store,
            root,
            &[0, 2, 3],
            &prefix,
            [44].to_vec(),
        );

        let p = read(&store, &root, &[2, 6, 8], prefix.len()).unwrap();
        assert_eq!([42].to_vec(), p.leaf.unwrap().value);
        assert_eq!(3, p.path.len());
        assert_eq!(root, p.path[0].hash);
        check_tree_invariants(&tree.hasher, &prefix, root, &store);
    }

    #[test]
    fn update_some() {
        let mut prefix = KeyVec::new();
        prefix.push(false);
        prefix.push(false);
        let (mut tree, mut root, mut store) = new_empty_tree(&prefix, 24);
        root = tree_insert(
            &mut tree,
            &mut store,
            root,
            &[2, 6, 8],
            &prefix,
            [42].to_vec(),
        );
        root = tree_insert(
            &mut tree,
            &mut store,
            root,
            &[4, 4, 6],
            &prefix,
            [43].to_vec(),
        );
        // now do a read/write for an existing key
        root = tree_insert(
            &mut tree,
            &mut store,
            root,
            &[4, 4, 6],
            &prefix,
            [44].to_vec(),
        );

        let rp = read(&store, &root, &[4, 4, 6], prefix.len()).unwrap();
        assert_eq!([44].to_vec(), rp.leaf.unwrap().value);
        check_tree_invariants(&tree.hasher, &prefix, root, &store);

        // writing the same value again shouldn't do anything dumb, like cause the leaf to be deleted.
        root = tree_insert(
            &mut tree,
            &mut store,
            root,
            &[4, 4, 6],
            &prefix,
            [44].to_vec(),
        );
        let rp = read(&store, &root, &[4, 4, 6], prefix.len()).unwrap();
        assert_eq!([44].to_vec(), rp.leaf.unwrap().value);
    }

    #[test]
    fn test_insert_lots_empty_prefix() {
        test_insert_lots_with_prefix(&KeyVec::new());
    }
    #[test]
    fn test_insert_lots_prefix_1bit() {
        let p1 = bitvec![u8, Msb0; 0];
        test_insert_lots_with_prefix(&p1);
    }
    #[test]
    fn test_insert_lots_prefix_2bit() {
        let p2 = bitvec![u8, Msb0; 1, 0];
        test_insert_lots_with_prefix(&p2);
    }

    fn test_insert_lots_with_prefix(prefix: &KeyVec) {
        let (mut tree, mut root, mut store) = new_empty_tree(prefix, 32);
        let seed = [0u8; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut random_key = [0u8; 4];
        let mut expected = HashMap::new();
        for i in 0..150 {
            rng.fill_bytes(&mut random_key);
            // We need to ensure our generated keys have the correct prefix.
            let mut k = KeyVec::from_slice(&random_key);
            k[..prefix.len()].copy_from_bitslice(&prefix);
            let key = k.into_vec();
            expected.insert(key.clone(), i);

            // write our new key/value
            root = tree_insert(&mut tree, &mut store, root, &key, prefix, [i].to_vec());

            // verify we can read all the key/values we've stored.
            for (k, v) in expected.iter() {
                let p = read(&store, &root, &k, prefix.len()).unwrap();
                assert_eq!([*v].to_vec(), p.leaf.unwrap().value);
            }
            // if i == 16 {
            //     dot::tree_to_dot(root, &store, "many.dot").unwrap();
            // }
        }
    }

    #[test]
    fn test_split_empty() {
        test_split(&[]);
    }
    #[test]
    fn test_split_empty_one_side() {
        test_split(&[&[1]]);
    }
    #[test]
    fn test_split_empty_one_side_with_one_bit_prefix() {
        test_split(&[&[0], &[0b00100000], &[0b01000000]]);
    }
    #[test]
    fn test_split_1bit() {
        // test split where the root has branches with single bit prefixes.
        test_split(&[&[0], &[0b10000000]]);
    }
    #[test]
    fn test_split_multiple_bits() {
        // test split where the root has branches with multiple bits in the prefixes.
        test_split(&[&[0], &[0b00010000]]);
    }
    #[test]
    fn test_split_mixed() {
        // test split where the root has only one branch with multiple bits in its prefix.
        test_split(&[&[0], &[0b10000000], &[0b11000000]]);
    }
    fn test_split(keys: &[&[u8]]) {
        let prefix = KeyVec::new();
        let key_size = 8;
        let (mut tree, mut root, mut store) = new_empty_tree(&prefix, key_size);
        let mut values = Vec::with_capacity(keys.len());
        for (i, left) in keys.iter().enumerate() {
            let v = i.to_le_bytes().to_vec();
            root = tree_insert(&mut tree, &mut store, root, left, &prefix, v.clone());
            values.push(v);
        }
        let rp = read(&store, &root, &[0], prefix.len()).unwrap();
        let split = tree.split_tree(&prefix, rp).unwrap();
        assert_eq!(root, split.old_root);
        store.apply_store_delta(split.delta);
        check_tree_invariants(
            &tree.hasher,
            &split.left.prefix,
            split.left.root_hash,
            &store,
        );
        check_tree_invariants(
            &tree.hasher,
            &split.right.prefix,
            split.right.root_hash,
            &store,
        );
        fn read_all<HO: HashOutput>(
            store: &MemStore<HO>,
            left_root: HO,
            right_root: HO,
            keys: &[&[u8]],
            values: &[Vec<u8>],
        ) {
            for (k, v) in zip(keys, values) {
                let root = if k[0] & 128 == 0 {
                    left_root
                } else {
                    right_root
                };
                let rp = read(store, &root, k, 1).unwrap();
                assert_eq!(v, &rp.leaf.unwrap().value);
            }
        }
        read_all(
            &store,
            split.left.root_hash,
            split.right.root_hash,
            keys,
            &values,
        );
        let mut tree = Tree::with_existing_root(tree.hasher, key_size, split.left.root_hash);
        root = tree_insert(
            &mut tree,
            &mut store,
            split.left.root_hash,
            &[0b00000011],
            &split.left.prefix,
            [42].to_vec(),
        );
        read_all(&store, root, split.right.root_hash, keys, &values);
        let rp = read(&store, &root, &[0b00000011], 1).unwrap();
        assert_eq!([42].to_vec(), rp.leaf.unwrap().value);
    }

    #[test]
    fn test_read_proof_verify() {
        let prefix = KeyVec::new();
        let (mut tree, mut root, mut store) = new_empty_tree(&prefix, 8);
        root = tree_insert(&mut tree, &mut store, root, &[1], &prefix, [1].to_vec());
        root = tree_insert(&mut tree, &mut store, root, &[5], &prefix, [2].to_vec());

        let mut p = read(&store, &root, &[5], prefix.len()).unwrap();
        assert!(p.verify(&tree.hasher));

        // claim there's no leaf
        p.leaf = None;
        assert!(!p.verify(&tree.hasher));

        let mut p = read(&store, &root, &[5], prefix.len()).unwrap();
        // truncate the tail of the path to claim there's no leaf
        p.leaf = None;
        p.path.pop();
        assert!(!p.verify(&tree.hasher));

        let mut p = read(&store, &root, &[5], prefix.len()).unwrap();
        // futz with the path
        p.key[0] = 2;
        assert!(!p.verify(&tree.hasher));

        // futz with the value (checks the hash)
        let mut p = read(&store, &root, &[5], prefix.len()).unwrap();
        if let Some(ref mut l) = p.leaf {
            l.value[0] += 1;
        }
        assert!(!p.verify(&tree.hasher));

        // futz with a node (checks the hash)
        let mut p = read(&store, &root, &[5], prefix.len()).unwrap();
        if let Some(ref mut b) = &mut p.path[0].left {
            b.prefix.pop();
        }
        assert!(!p.verify(&tree.hasher));
    }

    #[test]
    fn test_insert_pipeline() {
        let prefix = KeyVec::new();
        let (mut tree, mut root, mut store) = new_empty_tree(&prefix, 8);
        root = tree_insert(&mut tree, &mut store, root, &[1], &prefix, [1].to_vec());
        let rp_1 = read(&store, &root, &[1], prefix.len()).unwrap();
        let rp_2 = read(&store, &root, &[2], prefix.len()).unwrap();
        let rp_3 = read(&store, &root, &[3], prefix.len()).unwrap();
        let d1 = tree.insert(rp_1, [11].to_vec()).unwrap().unwrap();
        let d2 = tree.insert(rp_2, [12].to_vec()).unwrap().unwrap();
        let d3 = tree.insert(rp_3, [13].to_vec()).unwrap().unwrap();
        root = store.apply(d1);
        check_tree_invariants(&tree.hasher, &prefix, root, &store);
        root = store.apply(d2);
        check_tree_invariants(&tree.hasher, &prefix, root, &store);
        root = store.apply(d3);
        check_tree_invariants(&tree.hasher, &prefix, root, &store);

        let rp_1 = read(&store, &root, &[1], prefix.len()).unwrap();
        assert_eq!([11].to_vec(), rp_1.leaf.unwrap().value);
        let rp_2 = read(&store, &root, &[2], prefix.len()).unwrap();
        assert_eq!([12].to_vec(), rp_2.leaf.unwrap().value);
        let rp_3 = read(&store, &root, &[3], prefix.len()).unwrap();
        assert_eq!([13].to_vec(), rp_3.leaf.unwrap().value);
    }

    #[test]
    fn test_stale_proof() {
        let mut prefix = KeyVec::new();
        prefix.push(true);
        let (mut tree, mut root, mut store) = new_empty_tree(&prefix, 8);
        root = tree_insert(
            &mut tree,
            &mut store,
            root,
            &[0b10000000],
            &prefix,
            [1].to_vec(),
        );
        let rp_1 = read(&store, &root, &[0b10000000], prefix.len()).unwrap();
        for i in 0..20 {
            root = tree_insert(
                &mut tree,
                &mut store,
                root,
                &[0b11000000],
                &prefix,
                [i].to_vec(),
            );
        }
        let d = tree
            .insert(rp_1, [11].to_vec())
            .expect_err("should of failed");
        assert_eq!(TreeError::StaleProof, d);
    }

    #[test]
    fn test_empty_root_prefix_hash() {
        let h = TestHasher {};
        let root = InteriorNode::new(&h, &BitVec::new(), None, None);
        let p0 = bitvec![u8, Msb0; 0];
        let root_p0 = InteriorNode::new(&h, &p0, None, None);
        let p1 = bitvec![u8, Msb0; 1];
        let root_p1 = InteriorNode::new(&h, &p1, None, None);
        assert_ne!(root.hash, root_p0.hash);
        assert_ne!(root.hash, root_p1.hash);
        assert_ne!(root_p0.hash, root_p1.hash);
    }

    #[test]
    fn test_node_prefix_hash() {
        let h = TestHasher {};
        let b1 = Some(Branch::new(
            KeyVec::from_element(0b00000000),
            TestHash([1, 2, 3, 4, 5, 6, 7, 8]),
        ));
        let b2 = Some(Branch::new(
            KeyVec::from_element(0b11111111),
            TestHash([1, 2, 3, 4, 5, 6, 7, 8]),
        ));
        // Two identical interior nodes, but different prefixes should hash differently.
        let n1 = InteriorNode::new(&h, &KeyVec::from_element(0), b1.clone(), b2.clone());
        let n2 = InteriorNode::new(&h, &KeyVec::from_element(1), b1.clone(), b2.clone());
        assert_ne!(n1.hash, n2.hash);
    }

    #[test]
    fn test_branch_prefix_hash() {
        let h = TestHasher {};
        let k1 = KeyVec::from_element(0b00110000);
        let k2 = KeyVec::from_element(0b11010000);
        let a = InteriorNode::new(
            &h,
            &KeyVec::from_element(1),
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
            &KeyVec::from_element(1),
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
        let k1 = vec![1, 2];
        let k2 = vec![1, 4];
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

    fn new_empty_tree(
        prefix: &KeyVec,
        key_size: usize,
    ) -> (Tree<TestHasher, TestHash>, TestHash, MemStore<TestHash>) {
        let h = TestHasher {};
        let (root_hash, delta) = Tree::new_tree(&h, prefix);
        let mut store = MemStore::new();
        store.apply_store_delta(delta);
        check_tree_invariants(&h, prefix, root_hash, &store);
        let t = Tree::with_existing_root(h, key_size, root_hash);
        (t, root_hash, store)
    }

    // helper to insert a value into the tree and update the store
    fn tree_insert(
        tree: &mut Tree<TestHasher, TestHash>,
        store: &mut MemStore<TestHash>,
        root: TestHash,
        key: &[u8],
        prefix: &KeyVec,
        val: Vec<u8>,
    ) -> TestHash {
        // spot stupid test bugs
        assert!(
            KeySlice::from_slice(key).starts_with(prefix),
            "test bug, key should start with the correct prefix",
        );
        let rp = read(store, &root, key, prefix.len()).unwrap();
        let new_root = match tree.insert(rp, val).unwrap() {
            None => root,
            Some(d) => store.apply(d),
        };
        check_tree_invariants(&tree.hasher, prefix, new_root, store);
        new_root
    }

    // walks the tree starting at root verifying all the invariants are all true
    //      1. only the root may have an empty branch
    //      2. the left branch prefix always starts with a 0
    //      3. the right branch prefix always starts with a 1
    //      5. the leaf -> root hashes are verified.
    fn check_tree_invariants<HO: HashOutput>(
        hasher: &impl NodeHasher<HO>,
        key_prefix: &KeyVec,
        root: HO,
        store: &impl TreeStoreReader<HO>,
    ) {
        let root_hash = check_tree_node_invariants(hasher, true, root, key_prefix, store);
        assert_eq!(root_hash, root);
    }
    fn check_tree_node_invariants<HO: HashOutput>(
        hasher: &impl NodeHasher<HO>,
        is_at_root: bool,
        node: HO,
        path: &KeyVec,
        store: &impl TreeStoreReader<HO>,
    ) -> HO {
        match store.fetch(&node).unwrap() {
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
                        let mut new_path = path.clone();
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
                        let mut new_path = path.clone();
                        new_path.extend(&b.prefix);
                        let exp_child_hash =
                            check_tree_node_invariants(hasher, false, b.hash, &new_path, store);
                        assert_eq!(exp_child_hash, b.hash);
                    }
                }
                let exp_hash = InteriorNode::calc_hash(hasher, &path, &int.left, &int.right);
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
        fn apply_store_delta(&mut self, d: StoreDelta<HO>) {
            for n in d.add {
                self.insert(n.hash(), n);
            }
            for r in d.remove {
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
