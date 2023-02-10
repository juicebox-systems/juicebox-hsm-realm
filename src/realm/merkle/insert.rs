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

#[cfg(test)]
mod tests {

    use std::collections::BTreeMap;

    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    use super::super::super::hsm::types::OwnedRange;
    use super::super::agent::read;
    use super::super::tests::{check_tree_invariants, new_empty_tree, rec_id, tree_insert};

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
    fn insert_lots() {
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
    fn pipeline() {
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
}
