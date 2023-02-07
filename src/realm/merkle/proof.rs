use std::collections::HashMap;

use super::super::hsm::types::{OwnedRange, RecordId};
use super::agent::Node;
use super::overlay::TreeOverlay;
use super::{Dir, HashOutput, InteriorNode, KeySlice, LeafNode, NodeHasher};

#[derive(Debug, PartialEq, Eq)]
pub enum ProofError {
    Invalid,
    // The ReadProof is too old, calculate a newer one and try again.
    Stale,
}

#[derive(Debug, Clone)]
pub struct ReadProof<HO> {
    pub key: RecordId,
    // The key_range for the tree that the proof was read from.
    pub range: OwnedRange,
    pub leaf: Option<LeafNode<HO>>,
    // The path in root -> leaf order of the nodes traversed to get to the leaf. Or if the leaf
    // doesn't exist the furthest existing node in the path of the key.
    pub path: Vec<InteriorNode<HO>>,
}
impl<HO: HashOutput> ReadProof<HO> {
    pub fn new(key: RecordId, range: OwnedRange, root: InteriorNode<HO>) -> Self {
        ReadProof {
            key,
            range,
            leaf: None,
            path: vec![root],
        }
    }

    pub fn root_hash(&self) -> &HO {
        &self.path[0].hash
    }

    // Verify the ReadProof. This includes the hash verification and the key
    // path check. It returns a VerifiedProof that can be used for subsequent
    // operations that need the proof.
    pub fn verify<'a, H: NodeHasher<HO>>(
        self,
        hasher: &H,
        overlay: &'a TreeOverlay<HO>,
    ) -> Result<VerifiedProof<'a, HO>, ProofError> {
        // Ensure the root hash is one the overlay knows about.
        if !overlay.roots.contains(self.root_hash()) {
            return Err(ProofError::Stale);
        }
        self.verify_foreign_proof(hasher, overlay)
    }

    pub fn verify_foreign_proof<'a, H: NodeHasher<HO>>(
        self,
        hasher: &H,
        overlay: &'a TreeOverlay<HO>,
    ) -> Result<VerifiedProof<'a, HO>, ProofError> {
        // Do some basic sanity checks of the Proof struct first.
        if self.path.is_empty() || !self.range.contains(&self.key) {
            return Err(ProofError::Invalid);
        }
        // Verify the leaf hash matches
        if let Some(leaf) = &self.leaf {
            let exp_hash = LeafNode::calc_hash(hasher, &self.key, &leaf.value);
            if exp_hash != leaf.hash {
                return Err(ProofError::Invalid);
            }
        }
        self.verify_path(
            hasher,
            KeySlice::from_slice(&self.key.0),
            true,
            &self.path[0],
            &self.path[1..],
        )
        .map(|_| ())?;

        Ok(VerifiedProof::new(self, overlay))
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
        key_tail: &KeySlice,
        is_root: bool,
        node: &InteriorNode<HO>,
        path_tail: &[InteriorNode<HO>],
    ) -> Result<HO, ProofError> {
        let dir = Dir::from(key_tail[0]);
        match node.branch(dir).as_ref() {
            None => {
                match &self.leaf {
                    Some(_) => {
                        // If there's no branch, there can't be a leaf.
                        Err(ProofError::Invalid)
                    }
                    None => {
                        // We reached an empty branch and there's no existing leaf.
                        // We should be at the bottom of the path.
                        if !path_tail.is_empty() {
                            return Err(ProofError::Invalid);
                        }
                        // verify this nodes hash.
                        let ch = InteriorNode::calc_hash(
                            h,
                            &self.range,
                            is_root,
                            &node.left,
                            &node.right,
                        );
                        if ch != node.hash {
                            return Err(ProofError::Invalid);
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
                            if (key_tail != b.prefix) || (lh.hash != b.hash) {
                                return Err(ProofError::Invalid);
                            }
                            let nh =
                                node.with_new_child_hash(h, &self.range, is_root, dir, lh.hash);
                            if nh.hash != node.hash {
                                return Err(ProofError::Invalid);
                            }
                            Ok(nh.hash)
                        }
                        None => {
                            // This branch should not be able to lead to the key.
                            if key_tail.starts_with(&b.prefix) {
                                return Err(ProofError::Invalid);
                            }
                            let nh = InteriorNode::calc_hash(
                                h,
                                &self.range,
                                is_root,
                                &node.left,
                                &node.right,
                            );
                            if nh != node.hash {
                                return Err(ProofError::Invalid);
                            }
                            Ok(nh)
                        }
                    }
                } else {
                    // keep going down
                    if key_tail[..b.prefix.len()] != b.prefix {
                        return Err(ProofError::Invalid);
                    }
                    let child_h = self.verify_path(
                        h,
                        &key_tail[b.prefix.len()..],
                        false,
                        &path_tail[0],
                        &path_tail[1..],
                    )?;
                    if child_h != b.hash {
                        return Err(ProofError::Invalid);
                    }
                    let nh = node.with_new_child_hash(h, &self.range, is_root, dir, child_h);
                    if nh.hash != node.hash {
                        return Err(ProofError::Invalid);
                    }
                    Ok(nh.hash)
                }
            }
        }
    }
}

pub struct VerifiedProof<'a, HO> {
    pub key: RecordId,
    // The key range of the tree that the proof was read from.
    pub range: OwnedRange,
    pub leaf: Option<LeafNode<HO>>,
    path: Vec<InteriorNode<HO>>,
    nodes: HashMap<HO, usize>,
    overlay: &'a TreeOverlay<HO>,
}
impl<'a, HO: HashOutput> VerifiedProof<'a, HO> {
    fn new(proof: ReadProof<HO>, overlay: &'a TreeOverlay<HO>) -> Self {
        let path_len = proof.path.len();
        let mut r = Self {
            key: proof.key,
            range: proof.range,
            leaf: proof.leaf,
            path: proof.path,
            nodes: HashMap::with_capacity(path_len),
            overlay,
        };
        for (i, n) in r.path.iter().enumerate() {
            // TODO: this works, requires that path is never subsequently mutated.
            // trying to make nodes be HashMap<HO,&InteriorNode<HO>> and store
            // the reference to the vec entries directly ends up in lifetime hell.
            r.nodes.insert(n.hash, i);
        }
        r
    }
    pub fn path_len(&self) -> usize {
        self.path.len()
    }
    pub fn path(&self) -> Vec<&InteriorNode<HO>> {
        self.path.iter().collect()
    }
    pub fn get(&self, node_hash: &HO) -> Result<BorrowedNode<'_, HO>, ProofError> {
        // Look in overlay first.
        self.overlay
            .nodes
            .get(node_hash)
            .map(|n| match n {
                Node::Interior(int) => BorrowedNode::Interior(int),
                Node::Leaf(l) => BorrowedNode::Leaf(l),
            })
            // Or look in the nodes from the proof
            .or_else(|| match self.nodes.get(node_hash) {
                Some(path_idx) => Some(BorrowedNode::Interior(&self.path[*path_idx])),
                None => match &self.leaf {
                    Some(l) if &l.hash == node_hash => Some(BorrowedNode::Leaf(l)),
                    None | Some(_) => None,
                },
            })
            .ok_or(ProofError::Stale)
    }

    // Return the latest value for the record id in the Proof.
    pub fn latest_value(&self) -> Result<Option<Vec<u8>>, ProofError> {
        let mut v = None;
        self.walk_latest_path(|_head, _tail, _int| {}, |leaf| v = Some(leaf.value.clone()))?;
        Ok(v)
    }

    // Will walk down the most current path for the key in the Proof. The
    // callback is called at each node visited on the path, starting at root.
    pub fn walk_latest_path<FI, FL>(
        &'a self,
        mut int_cb: FI,
        mut leaf_cb: FL,
    ) -> Result<(), ProofError>
    where
        // |key_head, key_tail, node|
        // key_head is the part of the key traversed to reach this node. This starts
        // empty and will get longer at each subsequent call. It's the entire key prefix
        // up to that point, not the prefix of the last branch.
        // key_tail is the remainder of the key that has not been traversed yet. This
        // starts as the full key and gets shorter at each subsequent call.
        // concat(key_head,key_tail) is always the entire key.
        FI: FnMut(&KeySlice, &KeySlice, &'a InteriorNode<HO>),
        FL: FnMut(&'a LeafNode<HO>),
    {
        let full_key = KeySlice::from_slice(&self.key.0);
        let mut current_hash = self.overlay.latest_root;
        let mut key_pos = 0;
        loop {
            match self.get(&current_hash)? {
                BorrowedNode::Leaf(leaf) => {
                    assert!(key_pos == full_key.len());
                    leaf_cb(leaf);
                    return Ok(());
                }
                BorrowedNode::Interior(int) => {
                    let key_tail = &full_key[key_pos..];
                    int_cb(&full_key[..key_pos], key_tail, int);
                    let d = Dir::from(key_tail[0]);
                    match int.branch(d) {
                        None => return Ok(()),
                        Some(b) => {
                            if !key_tail.starts_with(&b.prefix) {
                                return Ok(());
                            }
                            key_pos += b.prefix.len();
                            current_hash = b.hash;
                        }
                    }
                }
            }
        }
    }
}

pub enum BorrowedNode<'a, HO> {
    Interior(&'a InteriorNode<HO>),
    Leaf(&'a LeafNode<HO>),
}
