use std::collections::HashMap;
use std::ops::Deref;

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
    pub fn verify<H: NodeHasher<HO>>(
        self,
        hasher: &H,
        overlay: &TreeOverlay<HO>,
    ) -> Result<VerifiedProof<HO>, ProofError> {
        // Ensure the root hash is one the overlay knows about.
        if !overlay.roots.contains(self.root_hash()) {
            return Err(ProofError::Stale);
        }
        self.verify_foreign_proof(hasher)
            .map(|vp| vp.update_to_latest(overlay))
    }

    pub fn verify_foreign_proof<H: NodeHasher<HO>>(
        self,
        hasher: &H,
    ) -> Result<VerifiedProof<HO>, ProofError> {
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

        Ok(VerifiedProof(self))
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

pub struct VerifiedProof<HO>(ReadProof<HO>);
impl<HO> Deref for VerifiedProof<HO> {
    type Target = ReadProof<HO>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<HO: HashOutput> VerifiedProof<HO> {
    fn update_to_latest(mut self, overlay: &TreeOverlay<HO>) -> VerifiedProof<HO> {
        assert!(
            overlay.roots.contains(self.root_hash()),
            "verify should of already checked this"
        );
        if self.root_hash() == &overlay.latest_root {
            return self;
        }
        let mut proof_nodes = HashMap::with_capacity(self.path.len() + 1);
        let mut old_path = Vec::new();
        std::mem::swap(&mut old_path, &mut self.0.path);
        let old_path_len = old_path.len();

        for n in old_path {
            proof_nodes.insert(n.hash, Node::Interior(n));
        }
        if let Some(l) = self.0.leaf {
            proof_nodes.insert(l.hash, Node::Leaf(l));
        }
        let fetch = |hash| match overlay.nodes.get(&hash) {
            Some(Node::Interior(int)) => Node::Interior(int.clone()),
            Some(Node::Leaf(leaf)) => Node::Leaf(leaf.clone()),
            None => match proof_nodes.get(&hash) {
                Some(n) => n.clone(),
                None => panic!("should of found hash {hash:?} in the overlay or proof"),
            },
        };

        let mut new_proof = ReadProof {
            key: self.0.key.clone(),
            range: self.0.range.clone(),
            leaf: None,
            path: Vec::with_capacity(old_path_len),
        };
        let mut key = KeySlice::from_slice(&self.0.key.0);
        let mut current_hash = overlay.latest_root;
        loop {
            match fetch(current_hash) {
                Node::Interior(int) => {
                    let d = Dir::from(key[0]);
                    let done = match int.branch(d) {
                        None => true,
                        Some(b) => {
                            if !key.starts_with(&b.prefix) {
                                true
                            } else {
                                key = &key[b.prefix.len()..];
                                current_hash = b.hash;
                                false
                            }
                        }
                    };
                    new_proof.path.push(int);
                    if done {
                        break;
                    };
                }
                Node::Leaf(leaf) => {
                    assert!(key.is_empty());
                    new_proof.leaf = Some(leaf);
                    break;
                }
            }
        }
        VerifiedProof(new_proof)
    }
}
