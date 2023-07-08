extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::mem;

use super::overlay::TreeOverlay;
use super::NodeHasher;
use super::{Bits, InteriorNodeExt, NodeHashBuilder};
use crate::hash::{HashExt, HashMap, NotRandomized};
use hsm_api::merkle::{Dir, HashOutput, InteriorNode, KeySlice, KeyVec, LeafNode, Node, ReadProof};
use hsm_api::{OwnedRange, RecordId};

#[derive(Debug, PartialEq, Eq)]
pub enum ProofError {
    Invalid,
    // The ReadProof is too old, calculate a newer one and try again.
    Stale,
}

pub fn new<HO>(
    key: RecordId,
    range: OwnedRange,
    root_hash: HO,
    root: InteriorNode<HO>,
) -> ReadProof<HO> {
    ReadProof {
        key,
        range,
        root_hash,
        leaf: None,
        path: vec![root],
    }
}

// Verify the ReadProof. This includes the hash verification and the key
// path check. It returns a VerifiedProof that can be used for subsequent
// operations that need the proof. The returned proof has been updated to
// reflect that latest state of the tree from the overlay.
pub fn verify<H: NodeHasher>(
    proof: ReadProof<H::Output>,
    overlay: &TreeOverlay<H::Output>,
) -> Result<VerifiedProof<H::Output>, ProofError> {
    // Ensure the root hash is one the overlay knows about.
    if !overlay.roots.contains(&proof.root_hash) {
        return Err(ProofError::Stale);
    }
    verify_proof::<H>(&proof)
        .map(|leaf_hash| VerifiedProof::new_make_latest(proof, overlay, leaf_hash))
}

// Verify the ReadProof. This includes the hash verification and the key
// path check. It returns a VerifiedProof that can be used for subsequent
// operations that need the proof.
pub fn verify_foreign_proof<H: NodeHasher>(
    proof: ReadProof<H::Output>,
) -> Result<VerifiedProof<H::Output>, ProofError> {
    verify_proof::<H>(&proof).map(|_| VerifiedProof::new_already_latest(proof))
}

// Returns the leaf hash
fn verify_proof<H: NodeHasher>(
    proof: &ReadProof<H::Output>,
) -> Result<Option<H::Output>, ProofError> {
    // Do some basic sanity checks of the Proof struct first.
    if proof.path.is_empty() || !proof.range.contains(&proof.key) {
        return Err(ProofError::Invalid);
    }
    verify_path::<H>(
        proof,
        proof.key.to_bitvec().as_ref(),
        true,
        proof.root_hash,
        &proof.path[0],
        &proof.path[1..],
    )
    .map(|(_, leaf)| leaf)
}

// Walks down the path and
//      1. verifies the key & path match.
//      2. verifies the terminal conditions are correct.
//          a. If there's a leaf the last interior node should have a branch to it.
//          b. If there's no leaf, the last interior node should not have a branch
//             that could possibly lead to the key.
//      3. recalculates & verifies the hashes on the way back up.
fn verify_path<H: NodeHasher>(
    proof: &ReadProof<H::Output>,
    key_tail: KeySlice,
    is_root: bool,
    hash: H::Output,
    node: &InteriorNode<H::Output>,
    path_tail: &[InteriorNode<H::Output>],
) -> Result<(H::Output, Option<H::Output>), ProofError> {
    let dir = Dir::from(key_tail[0]);
    match node.branch(dir).as_ref() {
        None => {
            match &proof.leaf {
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
                    let ch = InteriorNode::calc_hash::<H>(
                        &proof.range,
                        is_root,
                        &node.left,
                        &node.right,
                    );
                    if ch != hash {
                        return Err(ProofError::Invalid);
                    }
                    Ok((ch, None))
                }
            }
        }
        Some(b) => {
            if path_tail.is_empty() {
                // This is the last InteriorNode on the path. This should point
                // to the leaf, or to a different key altogether.
                match &proof.leaf {
                    Some(lh) => {
                        // The branch prefix should point to the remainder of the key
                        // and it should have the leaf's hash.
                        let leaf_hash = NodeHashBuilder::<H>::Leaf(&proof.key, &lh.value).build();
                        if (key_tail != b.prefix) || (leaf_hash != b.hash) {
                            return Err(ProofError::Invalid);
                        }
                        let (nh, _) =
                            node.with_new_child_hash::<H>(&proof.range, is_root, dir, leaf_hash);
                        if nh != hash {
                            return Err(ProofError::Invalid);
                        }
                        Ok((nh, Some(leaf_hash)))
                    }
                    None => {
                        // This branch should not be able to lead to the key.
                        if key_tail.starts_with(&b.prefix) {
                            return Err(ProofError::Invalid);
                        }
                        let nh = InteriorNode::calc_hash::<H>(
                            &proof.range,
                            is_root,
                            &node.left,
                            &node.right,
                        );
                        if nh != hash {
                            return Err(ProofError::Invalid);
                        }
                        Ok((nh, None))
                    }
                }
            } else {
                // keep going down
                if key_tail.slice(..b.prefix.len()) != b.prefix {
                    return Err(ProofError::Invalid);
                }
                let (child_h, leaf_h) = verify_path::<H>(
                    proof,
                    key_tail.slice(b.prefix.len()..),
                    false,
                    b.hash,
                    &path_tail[0],
                    &path_tail[1..],
                )?;
                if child_h != b.hash {
                    return Err(ProofError::Invalid);
                }
                let (nh, _) = node.with_new_child_hash::<H>(&proof.range, is_root, dir, child_h);
                if nh != hash {
                    return Err(ProofError::Invalid);
                }
                Ok((nh, leaf_h))
            }
        }
    }
}

#[derive(Debug)]
pub struct PathStep<HO> {
    // The hash of the node
    pub hash: HO,
    pub node: InteriorNode<HO>,
    // The full key prefix to this node.
    pub prefix: KeyVec,
    // The branch direction to take to reach the next node in the path.
    pub next_dir: Dir,
}

#[derive(Debug)]
#[non_exhaustive] // Don't allow creation from outside this module.
pub struct VerifiedProof<HO> {
    pub path: Vec<PathStep<HO>>,
    pub leaf: Option<LeafNode>,
    pub key: RecordId,
    pub range: OwnedRange,
}

impl<HO: HashOutput> VerifiedProof<HO> {
    fn new_already_latest(proof: ReadProof<HO>) -> VerifiedProof<HO> {
        let mut vp = VerifiedProof {
            path: Vec::with_capacity(proof.path.len()),
            leaf: proof.leaf,
            key: proof.key,
            range: proof.range,
        };
        let key = vp.key.to_bitvec();
        let mut key_pos = 0;
        let mut current_hash = proof.root_hash;
        for n in proof.path {
            let d = Dir::from(key[key_pos]);
            vp.path.push(PathStep {
                node: n,
                hash: current_hash,
                prefix: key.slice(..key_pos).to_bitvec(),
                next_dir: d,
            });
            match vp.path.last().unwrap().node.branch(d) {
                None => {
                    break;
                }
                Some(b) => {
                    if key.slice(key_pos..).starts_with(&b.prefix) {
                        key_pos += b.prefix.len();
                        current_hash = b.hash;
                    } else {
                        break;
                    }
                }
            }
        }
        vp
    }

    fn new_make_latest(
        mut proof: ReadProof<HO>,
        overlay: &TreeOverlay<HO>,
        leaf_hash: Option<HO>,
    ) -> VerifiedProof<HO> {
        assert!(
            overlay.roots.contains(&proof.root_hash),
            "verify should have already checked this"
        );
        if proof.root_hash == overlay.latest_root {
            return Self::new_already_latest(proof);
        }

        // This map doesn't need mitigation from HashDoS attacks because its
        // keys correspond to a hashes of nodes in a path that's been verified
        // to be part of the Merkle tree.
        //
        // It's best to avoid randomization here for performance. This is
        // called when processing every record update request.
        let mut proof_nodes: HashMap<HO, Node<HO>, NotRandomized> =
            HashMap::with_capacity(proof.path.len() + 1);

        let mut old_path = Vec::new();
        mem::swap(&mut old_path, &mut proof.path);
        let old_path_len = old_path.len();

        if let Some(l) = proof.leaf {
            proof_nodes.insert(
                leaf_hash.expect("The proof has a leaf, verify should have given us the leaf hash"),
                Node::Leaf(l),
            );
        }
        let full_key = proof.key.to_bitvec();
        let mut key = full_key.as_ref();
        let mut current_hash = proof.root_hash;
        for n in old_path {
            let next_hash = match n.branch(Dir::from(key[0])) {
                Some(b) => {
                    key = key.slice(b.prefix.len()..);
                    Some(b.hash)
                }
                None => None,
            };
            proof_nodes.insert(current_hash, Node::Interior(n));
            current_hash = match next_hash {
                None => break,
                Some(h) => h,
            }
        }
        let fetch = |hash| match overlay.nodes.get(&hash) {
            Some(Node::Interior(int)) => Node::Interior(int.clone()),
            Some(Node::Leaf(leaf)) => Node::Leaf(leaf.clone()),
            None => match proof_nodes.get(&hash) {
                Some(n) => n.clone(),
                None => panic!("should have found hash {hash:?} in the overlay or proof"),
            },
        };

        let mut vp = VerifiedProof {
            path: Vec::with_capacity(old_path_len),
            leaf: None,
            key: proof.key,
            range: proof.range,
        };
        let mut key_pos = 0;
        let mut current_hash = overlay.latest_root;
        loop {
            match fetch(current_hash) {
                Node::Interior(int) => {
                    let prefix = full_key.slice(..key_pos);
                    let key_tail = full_key.slice(key_pos..);
                    let d = Dir::from(key_tail[0]);
                    let int_hash = current_hash;
                    let done = match int.branch(d) {
                        None => true,
                        Some(b) => {
                            if !key_tail.starts_with(&b.prefix) {
                                true
                            } else {
                                key_pos += b.prefix.len();
                                current_hash = b.hash;
                                false
                            }
                        }
                    };
                    vp.path.push(PathStep {
                        node: int,
                        hash: int_hash,
                        prefix: prefix.to_bitvec(),
                        next_dir: d,
                    });
                    if done {
                        break;
                    };
                }
                Node::Leaf(leaf) => {
                    assert_eq!(key_pos, full_key.len());
                    vp.leaf = Some(leaf);
                    break;
                }
            }
        }
        vp
    }

    pub fn root_hash(&self) -> &HO {
        &self.path[0].hash
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{new_empty_tree, rec_id, tree_insert, TestHasher};
    use super::verify;
    use super::ProofError;
    use bitvec::Bits;
    use hsm_api::OwnedRange;

    #[test]
    fn verify_proof() {
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

        let p = store.read(&range, &root, &rid5).unwrap();
        assert!(verify::<TestHasher>(p, &tree.overlay).is_ok());

        // claim there's no leaf
        let mut p = store.read(&range, &root, &rid5).unwrap();
        p.leaf = None;
        assert!(verify::<TestHasher>(p, &tree.overlay).is_err());

        let mut p = store.read(&range, &root, &rid5).unwrap();
        // truncate the tail of the path to claim there's no leaf
        p.leaf = None;
        p.path.pop();
        assert!(verify::<TestHasher>(p, &tree.overlay).is_err());

        let mut p = store.read(&range, &root, &rid5).unwrap();
        // futz with the path
        p.key.0[0] = 2;
        assert!(verify::<TestHasher>(p, &tree.overlay).is_err());

        // futz with the value (checks the hash)
        let mut p = store.read(&range, &root, &rid5).unwrap();
        if let Some(ref mut l) = p.leaf {
            l.value[0] += 1;
        }
        assert!(verify::<TestHasher>(p, &tree.overlay).is_err());

        // futz with a node (checks the hash)
        let mut p = store.read(&range, &root, &rid5).unwrap();
        if let Some(ref mut b) = &mut p.path[0].left {
            b.prefix = b.prefix.slice(..b.prefix.len() - 1).to_bitvec()
        }
        assert!(verify::<TestHasher>(p, &tree.overlay).is_err());
    }

    #[test]
    fn stale_proof() {
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
        let rp_1 = store.read(&range, &root, &rec_id(&[0b10000000])).unwrap();
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
}
