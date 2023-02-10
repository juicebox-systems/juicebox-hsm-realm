use super::{
    common_prefix,
    proof::{ProofError, VerifiedProof},
    Branch, Delta, HashOutput, InteriorNode, KeySlice, LeafNode, NodeHasher, Tree,
};

impl<H: NodeHasher<HO>, HO: HashOutput> Tree<H, HO> {
    // Insert a new value for the leaf described by the read proof. Returns a set
    // of changes that need making to the tree storage. In the event the insert results
    // in no changes (i.e. the insert is inserting the same value as its current value)
    // None is returned.
    pub fn insert(
        &mut self,
        mut proof: VerifiedProof<HO>,
        v: Vec<u8>,
    ) -> Result<Option<Delta<HO>>, ProofError> {
        //
        if proof.root_hash() != &self.overlay.latest_root {
            return Err(ProofError::Stale);
        }
        if let Some(leaf) = &proof.leaf {
            if leaf.value == v {
                return Ok(None);
            }
        }
        let mut delta = Delta::new(LeafNode::new(&self.hasher, &proof.key, v));
        let key = KeySlice::from_slice(&proof.key.0);

        let last = proof
            .path
            .pop()
            .expect("There should always be at least the root node in the path");
        let mut child_hash = match last.node.branch(last.next_dir) {
            None => {
                // update node to have empty branch point to the new leaf.
                let b = Branch::new(key[last.prefix.len()..].into(), delta.leaf.hash);
                let updated_n =
                    last.node
                        .with_new_child(&self.hasher, &proof.range, true, last.next_dir, b);
                let hash = updated_n.hash;
                delta.add.push(updated_n);
                delta.remove.push(last.node.hash);
                hash
            }
            Some(b) => {
                if key[last.prefix.len()..] == b.prefix {
                    // this points to the existing leaf, just need to update it.
                    let updated_n = last.node.with_new_child_hash(
                        &self.hasher,
                        &proof.range,
                        last.prefix.is_empty(),
                        last.next_dir,
                        delta.leaf.hash,
                    );
                    let new_hash = updated_n.hash;
                    delta.add.push(updated_n);
                    delta.remove.push(last.node.hash);
                    new_hash
                } else {
                    // This points somewhere else. Add a child node that contains(b.dest, new_leaf) and update n to point to it
                    let comm = common_prefix(&key[last.prefix.len()..], &b.prefix);
                    assert!(!comm.is_empty());
                    let new_child = InteriorNode::construct(
                        &self.hasher,
                        &proof.range,
                        false,
                        Some(Branch::new(
                            key[last.prefix.len() + comm.len()..].into(),
                            delta.leaf.hash,
                        )),
                        Some(Branch::new(b.prefix[comm.len()..].into(), b.hash)),
                    );
                    let updated_n = last.node.with_new_child(
                        &self.hasher,
                        &proof.range,
                        last.prefix.is_empty(),
                        last.next_dir,
                        Branch::new(comm.into(), new_child.hash),
                    );
                    let new_hash = updated_n.hash;
                    delta.add.push(new_child);
                    delta.add.push(updated_n);
                    delta.remove.push(last.node.hash);
                    new_hash
                }
            }
        };
        // now roll the hash back up the path.
        for parent in proof.path.iter().rev() {
            let updated_n = parent.node.with_new_child_hash(
                &self.hasher,
                &proof.range,
                parent.prefix.is_empty(),
                parent.next_dir,
                child_hash,
            );
            child_hash = updated_n.hash;
            delta.add.push(updated_n);
            delta.remove.push(parent.node.hash);
        }
        self.overlay.add_delta(&delta);
        Ok(Some(delta))
    }
}
