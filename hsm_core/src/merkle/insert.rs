extern crate alloc;

use alloc::vec::Vec;

use super::{
    new_leaf,
    proof::{ProofError, VerifiedProof},
    Branch, InteriorNode, InteriorNodeExt, NodeHasher, Tree,
};
use bitvec::Bits;
use hsm_api::merkle::{DeltaBuilder, Node, NodeKey, StoreDelta};

impl<H: NodeHasher> Tree<H> {
    // Insert a new value for the leaf described by the read proof. Returns the
    // new root hash and a set of changes that need making to the tree storage.
    // In the event the insert results in no changes (i.e. the insert is
    // inserting the same value as its current value) the current root hash and
    // no delta is returned.
    pub fn insert(
        &mut self,
        mut proof: VerifiedProof<H::Output>,
        v: Vec<u8>,
    ) -> Result<(H::Output, StoreDelta<H::Output>), ProofError> {
        if proof.root_hash() != &self.overlay.latest_root {
            return Err(ProofError::Stale);
        }
        let mut delta = DeltaBuilder::new();
        if let Some(leaf) = &proof.leaf {
            if leaf.value == v {
                return Ok((self.overlay.latest_root, StoreDelta::default()));
            }
            let last_int = proof.path.last().unwrap();
            let leaf_hash = last_int
                .node
                .branch(last_int.next_dir)
                .as_ref()
                .unwrap()
                .hash;
            delta.remove(NodeKey::new(proof.key.to_bitvec(), leaf_hash));
        }
        let (leaf_hash, leaf) = new_leaf::<H>(&proof.key, v);
        delta.add(
            NodeKey::new(proof.key.to_bitvec(), leaf_hash),
            Node::Leaf(leaf),
        );
        let key = proof.key.to_bitvec();

        let last = proof
            .path
            .pop()
            .expect("There should always be at least the root node in the path");
        let mut child_hash = match last.node.branch(last.next_dir) {
            None => {
                // update node to have empty branch point to the new leaf.
                let b = Branch::new(key.slice(last.prefix.len()..).into(), leaf_hash);
                let (hash, updated_n) =
                    last.node
                        .with_new_child::<H>(&proof.range, true, last.next_dir, b);
                delta.add(
                    NodeKey::new(last.prefix.clone(), hash),
                    Node::Interior(updated_n),
                );
                delta.remove(NodeKey::new(last.prefix, last.hash));
                hash
            }
            Some(b) => {
                if key.slice(last.prefix.len()..) == b.prefix {
                    // this points to the existing leaf, just need to update it.
                    let (new_hash, updated_n) = last.node.with_new_child_hash::<H>(
                        &proof.range,
                        last.prefix.is_empty(),
                        last.next_dir,
                        leaf_hash,
                    );
                    delta.add(
                        NodeKey::new(last.prefix.clone(), new_hash),
                        Node::Interior(updated_n),
                    );
                    delta.remove(NodeKey::new(last.prefix, last.hash));
                    new_hash
                } else {
                    // This points somewhere else. Add a child node that contains(b.dest, new_leaf) and update n to point to it
                    let key_tail = key.slice(last.prefix.len()..);
                    let comm = key_tail.common_prefix(&b.prefix);
                    assert!(!comm.is_empty());
                    let (child_hash, new_child) = InteriorNode::construct::<H>(
                        &proof.range,
                        false,
                        Some(Branch::new(
                            key.slice(last.prefix.len() + comm.len()..).into(),
                            leaf_hash,
                        )),
                        Some(Branch::new(b.prefix.slice(comm.len()..).into(), b.hash)),
                    );
                    let (new_hash, updated_n) = last.node.with_new_child::<H>(
                        &proof.range,
                        last.prefix.is_empty(),
                        last.next_dir,
                        Branch::new(comm.to_bitvec(), child_hash),
                    );
                    delta.add(
                        NodeKey::new(
                            key.slice(..last.prefix.len() + comm.len()).to_bitvec(),
                            child_hash,
                        ),
                        Node::Interior(new_child),
                    );
                    delta.add(
                        NodeKey::new(last.prefix.clone(), new_hash),
                        Node::Interior(updated_n),
                    );
                    delta.remove(NodeKey::new(last.prefix, last.hash));
                    new_hash
                }
            }
        };
        // now roll the hash back up the path.
        let mut updated_n;
        for parent in proof.path.into_iter().rev() {
            (child_hash, updated_n) = parent.node.with_new_child_hash::<H>(
                &proof.range,
                parent.prefix.is_empty(),
                parent.next_dir,
                child_hash,
            );
            delta.add(
                NodeKey::new(parent.prefix.clone(), child_hash),
                Node::Interior(updated_n),
            );
            delta.remove(NodeKey::new(parent.prefix, parent.hash));
        }
        let final_delta = delta.build();
        self.overlay.add_delta(child_hash, &final_delta);
        Ok((child_hash, final_delta))
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use std::collections::BTreeMap;

    use super::super::testing::{check_tree_invariants, new_empty_tree, tree_insert, TestHasher};
    use super::super::tests::tree_size;
    use hsm_api::merkle::{KeyVec, Node, NodeKey};
    use hsm_api::{OwnedRange, RecordId};

    #[test]
    fn first_insert() {
        let range = OwnedRange::full();
        let (mut tree, root, mut store) = new_empty_tree(&range);
        let rp = store
            .read(&range, &root, &RecordId::min_id().with(&[1, 2, 3]))
            .unwrap();
        let (new_root, d) = tree
            .insert(tree.latest_proof(rp).unwrap(), [42].to_vec())
            .unwrap();
        assert_eq!(2, d.adds().len());
        let (leaf_key, leaf_node) = d
            .adds()
            .iter()
            .find(|(_, n)| matches!(n, Node::Leaf(_)))
            .unwrap();
        if let Node::Leaf(leaf) = leaf_node {
            assert_eq!([42].to_vec(), leaf.value);
        }
        assert_eq!(
            leaf_key.prefix,
            RecordId::min_id().with(&[1, 2, 3]).to_bitvec()
        );
        assert!(d.removes().contains(&NodeKey::new(KeyVec::new(), root)));
        store.apply_store_delta(new_root, d);
        check_tree_invariants::<TestHasher>(&range, new_root, &store);

        let p = store
            .read(&range, &new_root, &RecordId::min_id().with(&[1, 2, 3]))
            .unwrap();
        assert_eq!([42].to_vec(), p.leaf.as_ref().unwrap().value);
        assert_eq!(1, p.path.len());
        assert_eq!(new_root, p.root_hash);
    }

    #[test]
    fn new_records() {
        let range = OwnedRange::full();
        let (mut tree, mut root, mut store) = new_empty_tree(&range);
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &RecordId::min_id().with(&[2, 6, 8]),
            [42].to_vec(),
            true,
        );
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &RecordId::min_id().with(&[4, 4, 6]),
            [43].to_vec(),
            true,
        );
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &RecordId::min_id().with(&[0, 2, 3]),
            [44].to_vec(),
            false,
        );

        let p = store
            .read(&range, &root, &RecordId::min_id().with(&[2, 6, 8]))
            .unwrap();
        assert_eq!([42].to_vec(), p.leaf.unwrap().value);
        assert_eq!(3, p.path.len());
        assert_eq!(root, p.root_hash);
        check_tree_invariants::<TestHasher>(&range, root, &store);
        assert_eq!(tree_size(KeyVec::new(), root, &store).unwrap(), store.len());
    }

    #[test]
    fn update_existing() {
        let range = OwnedRange {
            start: RecordId::min_id().with(&[1]),
            end: RecordId::min_id().with(&[6]),
        };
        let (mut tree, mut root, mut store) = new_empty_tree(&range);
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &RecordId::min_id().with(&[2, 6, 8]),
            [42].to_vec(),
            false,
        );
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &RecordId::min_id().with(&[4, 4, 6]),
            [43].to_vec(),
            false,
        );
        // now do a read/write for an existing key
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &RecordId::min_id().with(&[4, 4, 6]),
            [44].to_vec(),
            false,
        );

        let rp = store
            .read(&range, &root, &RecordId::min_id().with(&[4, 4, 6]))
            .unwrap();
        assert_eq!([44].to_vec(), rp.leaf.unwrap().value);
        check_tree_invariants::<TestHasher>(&range, root, &store);

        // writing the same value again shouldn't do anything dumb, like cause the leaf to be deleted.
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &RecordId::min_id().with(&[4, 4, 6]),
            [44].to_vec(),
            false,
        );
        let rp = store
            .read(&range, &root, &RecordId::min_id().with(&[4, 4, 6]))
            .unwrap();
        assert_eq!([44].to_vec(), rp.leaf.unwrap().value);
        check_tree_invariants::<TestHasher>(&range, root, &store);
        assert_eq!(tree_size(KeyVec::new(), root, &store).unwrap(), store.len());
    }

    #[test]
    fn lots() {
        let range = OwnedRange::full();
        let (mut tree, mut root, mut store) = new_empty_tree(&range);
        let seed = [0u8; 32];
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let mut random_key = [0u8; 4];
        let mut expected = BTreeMap::new();

        const LOTS_COUNT: u8 = if cfg!(target_arch = "powerpc") {
            20
        } else {
            150
        };
        for i in 0..LOTS_COUNT {
            rng.fill_bytes(&mut random_key);
            let key = RecordId::min_id().with(&random_key);
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
                let p = store.read(&range, &root, k).unwrap();
                assert_eq!([*v].to_vec(), p.leaf.unwrap().value);
            }
            // if i == 16 {
            //     dot::tree_to_dot(root, &store, "many.dot").unwrap();
            // }
        }
        check_tree_invariants::<TestHasher>(&range, root, &store);
        assert_eq!(tree_size(KeyVec::new(), root, &store).unwrap(), store.len());
    }

    #[test]
    fn pipeline() {
        let range = OwnedRange::full();
        let (mut tree, mut root, mut store) = new_empty_tree(&range);
        let rid1 = RecordId::min_id().with(&[1]);
        let rid2 = RecordId::min_id().with(&[2]);
        let rid3 = RecordId::min_id().with(&[3]);
        root = tree_insert(
            &mut tree,
            &mut store,
            &range,
            root,
            &rid1,
            [1].to_vec(),
            false,
        );

        let rp_1 = store.read(&range, &root, &rid1).unwrap();
        let rp_2 = store.read(&range, &root, &rid2).unwrap();
        let rp_3 = store.read(&range, &root, &rid3).unwrap();
        let (root1, d1) = tree
            .insert(tree.latest_proof(rp_1).unwrap(), [11].to_vec())
            .unwrap();
        let (root2, d2) = tree
            .insert(tree.latest_proof(rp_2).unwrap(), [12].to_vec())
            .unwrap();
        let (root3, d3) = tree
            .insert(tree.latest_proof(rp_3).unwrap(), [13].to_vec())
            .unwrap();
        store.apply_store_delta(root1, d1);
        check_tree_invariants::<TestHasher>(&range, root1, &store);
        assert_eq!(
            tree_size(KeyVec::new(), root1, &store).unwrap(),
            store.len()
        );

        store.apply_store_delta(root2, d2);
        check_tree_invariants::<TestHasher>(&range, root2, &store);
        assert_eq!(
            tree_size(KeyVec::new(), root2, &store).unwrap(),
            store.len()
        );

        store.apply_store_delta(root3, d3);
        check_tree_invariants::<TestHasher>(&range, root3, &store);
        assert_eq!(
            tree_size(KeyVec::new(), root3, &store).unwrap(),
            store.len()
        );

        let rp_1 = store.read(&range, &root3, &rid1).unwrap();
        assert_eq!([11].to_vec(), rp_1.leaf.unwrap().value);
        let rp_2 = store.read(&range, &root3, &rid2).unwrap();
        assert_eq!([12].to_vec(), rp_2.leaf.unwrap().value);
        let rp_3 = store.read(&range, &root3, &rid3).unwrap();
        assert_eq!([13].to_vec(), rp_3.leaf.unwrap().value);
    }
}
