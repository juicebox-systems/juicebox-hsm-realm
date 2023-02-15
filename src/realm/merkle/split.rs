use tracing::info;

use super::super::hsm::types::{OwnedRange, RecordId};
use super::{
    agent::{DeltaBuilder, Node, NodeKey},
    concat,
    proof::{ProofError, ReadProof},
    Branch, Dir, HashOutput, InteriorNode, KeySlice, KeyVec, NodeHasher, SplitResult, SplitRoot,
    Tree,
};

impl<H: NodeHasher<HO>, HO: HashOutput> Tree<H, HO> {
    // Splits the current tree into two at the key in the proof. This key
    // becomes the first key in the new right side.
    pub fn range_split(self, proof: ReadProof<HO>) -> Result<SplitResult<HO>, ProofError> {
        assert!(proof.key > RecordId::min_id());

        let proof = proof.verify(&self.hasher, &self.overlay)?;

        // Find the split node. We start at the bottom of the path. If the key is greater than the
        // left branch and smaller or equal to the right branch then this is the split node. If its
        // not, we have to walk back up the path to find the split node.
        let key = KeySlice::from_slice(&proof.key.0);
        enum SplitLocation {
            PathIndex(usize),
            SideOfRoot(Dir),
        }
        let split_loc = {
            let last = proof
                .path
                .last()
                .expect("path should always contain at least one node");
            let gt_left = match &last.node.left {
                None => true,
                Some(b) => key > concat(&last.prefix, &b.prefix),
            };
            let lte_right = match &last.node.right {
                None => true,
                Some(b) => key <= concat(&last.prefix, &b.prefix),
            };

            if gt_left && lte_right {
                // this is the one.
                SplitLocation::PathIndex(proof.path.len() - 1)
            } else {
                let dir = if !gt_left { Dir::Left } else { Dir::Right };
                // Need to walk back up to find a node where the branch takes the opposite side.
                // This makes a lot more sense if you look at a picture of a tree.
                match proof
                    .path
                    .iter()
                    .rposition(|step| step.next_dir == dir.opposite())
                {
                    Some(idx) => SplitLocation::PathIndex(idx),
                    None => SplitLocation::SideOfRoot(dir),
                }
            }
        };

        let left_range = OwnedRange {
            start: proof.range.start.clone(),
            end: proof.key.prev().unwrap(),
        };
        let right_range = OwnedRange {
            start: proof.key.clone(),
            end: proof.range.end.clone(),
        };
        let mut delta = DeltaBuilder::new();
        match split_loc {
            SplitLocation::SideOfRoot(side) => {
                // The split point is either before everything in the tree, or after everything in the tree.
                // This splits into the current tree (with new hash for partition change) plus a new empty root.
                info!("starting split to {side} of root node");
                let root = &proof.path[0].node;
                let (left_node, right_node) = match side {
                    Dir::Left => (
                        InteriorNode::new(&self.hasher, &left_range, true, None, None),
                        root.root_with_new_partition(&self.hasher, &right_range),
                    ),
                    Dir::Right => (
                        root.root_with_new_partition(&self.hasher, &left_range),
                        InteriorNode::new(&self.hasher, &right_range, true, None, None),
                    ),
                };
                let left = SplitRoot {
                    root_hash: left_node.hash,
                    range: left_range,
                };
                let right = SplitRoot {
                    root_hash: right_node.hash,
                    range: right_range,
                };
                delta.add(
                    NodeKey::new(KeyVec::new(), left.root_hash),
                    Node::Interior(left_node),
                );
                delta.add(
                    NodeKey::new(KeyVec::new(), right.root_hash),
                    Node::Interior(right_node),
                );
                delta.remove(NodeKey::new(KeyVec::new(), root.hash));
                Ok(SplitResult {
                    old_root: root.hash,
                    left,
                    right,
                    delta: delta.build(),
                })
            }
            SplitLocation::PathIndex(0) => {
                // Simple case, split is in the middle of the root node.
                info!("starting split at root node");
                let root = &proof.path[0].node;
                let left_node =
                    InteriorNode::new(&self.hasher, &left_range, true, root.left.clone(), None);
                let right_node =
                    InteriorNode::new(&self.hasher, &right_range, true, None, root.right.clone());
                let left = SplitRoot {
                    root_hash: left_node.hash,
                    range: left_range,
                };
                let right = SplitRoot {
                    root_hash: right_node.hash,
                    range: right_range,
                };
                delta.add(
                    NodeKey::new(KeyVec::new(), left.root_hash),
                    Node::Interior(left_node),
                );
                delta.add(
                    NodeKey::new(KeyVec::new(), right.root_hash),
                    Node::Interior(right_node),
                );
                delta.remove(NodeKey::new(KeyVec::new(), root.hash));
                Ok(SplitResult {
                    old_root: root.hash,
                    left,
                    right,
                    delta: delta.build(),
                })
            }
            SplitLocation::PathIndex(split_idx) => {
                let split = &proof.path[split_idx].node;
                info!(
                    "starting split. split is at path[{split_idx}] with hash {:?}",
                    split.hash
                );
                let mut left = split.left.clone().unwrap();
                let mut right = split.right.clone().unwrap();
                delta.remove(NodeKey::new(
                    proof.path[split_idx].prefix.clone(),
                    split.hash,
                ));

                for path_idx in (0..split_idx).rev() {
                    let parent = &proof.path[path_idx].node;
                    let parent_d = proof.path[path_idx].next_dir;
                    let parent_b = parent.branch(parent_d).as_ref().unwrap();
                    (left, right) = {
                        // If we came down the right branch, then the left gets a new node
                        // and the right gets a prefix placeholder. Or visa versa.
                        let (gets_new_node, new_node_range, extends_prefix) = match parent_d {
                            Dir::Left => (right, &right_range, left),
                            Dir::Right => (left, &left_range, right),
                        };
                        let new_node = parent.with_new_child(
                            &self.hasher,
                            new_node_range,
                            path_idx == 0,
                            parent_d,
                            Branch::new(
                                concat(&parent_b.prefix, &gets_new_node.prefix),
                                gets_new_node.hash,
                            ),
                        );
                        let new_node_res = Branch::new(KeyVec::new(), new_node.hash);
                        delta.add(
                            NodeKey::new(proof.path[path_idx].prefix.clone(), new_node.hash),
                            Node::Interior(new_node),
                        );
                        let ext_prefix_res = Branch::new(
                            concat(&parent_b.prefix, &extends_prefix.prefix),
                            extends_prefix.hash,
                        );
                        match parent_d {
                            Dir::Left => (ext_prefix_res, new_node_res),
                            Dir::Right => (new_node_res, ext_prefix_res),
                        }
                    };
                    delta.remove(NodeKey::new(
                        proof.path[path_idx].prefix.clone(),
                        parent.hash,
                    ));
                }
                let left_root = if !left.prefix.is_empty() {
                    let n =
                        InteriorNode::construct(&self.hasher, &left_range, true, None, Some(left));
                    let h = n.hash;
                    delta.add(NodeKey::new(KeyVec::new(), h), Node::Interior(n));
                    h
                } else {
                    left.hash
                };
                let right_root = if !right.prefix.is_empty() {
                    let n = InteriorNode::construct(
                        &self.hasher,
                        &right_range,
                        true,
                        None,
                        Some(right),
                    );
                    let h = n.hash;
                    delta.add(NodeKey::new(KeyVec::new(), h), Node::Interior(n));
                    h
                } else {
                    right.hash
                };
                Ok(SplitResult {
                    old_root: self.overlay.latest_root,
                    left: SplitRoot {
                        root_hash: left_root,
                        range: left_range,
                    },
                    right: SplitRoot {
                        root_hash: right_root,
                        range: right_range,
                    },
                    delta: delta.build(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::realm::merkle::tests::check_delta_invariants;

    use super::super::super::hsm::types::{OwnedRange, RecordId};
    use super::super::{
        agent::{read, read_tree_side},
        tests::{
            check_tree_invariants, new_empty_tree, rec_id, tree_insert, tree_size, TestHasher,
        },
        {dot, Dir, KeySlice},
    };

    #[tokio::test]
    async fn one_bit() {
        // test split where the root has branches with single bit prefixes.
        let keys = [rec_id(&[0]), rec_id(&[0b11110000])];
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[0b1000000])).await;
    }
    #[tokio::test]
    async fn multiple_bits() {
        // test split where the root has branches with multiple bits in the prefixes.
        let keys = [rec_id(&[0]), rec_id(&[0b00010000])];
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[0b1000000])).await;
    }
    #[tokio::test]
    async fn root_one_branch() {
        // test split where the root has only one branch with multiple bits in its prefix.
        let keys = [rec_id(&[0]), rec_id(&[0, 0, 5]), rec_id(&[0, 0, 6])];
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[0b1000000])).await;
    }

    #[tokio::test]
    async fn on_key_with_record() {
        let keys: Vec<_> = (0u8..10).map(|k| rec_id(&[k])).collect();
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[5])).await;
    }

    #[tokio::test]
    async fn on_key_with_no_record() {
        let keys: Vec<_> = (0u8..100).step_by(10).map(|k| rec_id(&[k])).collect();
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[10, 0, 0, 5])).await;
    }

    #[tokio::test]
    async fn one_side_ends_up_empty() {
        let keys: Vec<_> = (10u8..100).step_by(10).map(|k| rec_id(&[k])).collect();
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[5])).await;
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[101])).await;
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[200])).await;
    }

    #[tokio::test]
    async fn one_key_only() {
        test_arb_split_merge(OwnedRange::full(), &[rec_id(&[20])], &rec_id(&[4])).await;
        test_arb_split_merge(OwnedRange::full(), &[rec_id(&[20])], &rec_id(&[24])).await;
    }

    #[tokio::test]
    async fn empty_tree() {
        test_arb_split_merge(OwnedRange::full(), &[], &rec_id(&[4])).await;
    }

    #[tokio::test]
    async fn dense_root() {
        let k = &[
            0u8, 0b11111111, 0b01111111, 0b10111100, 0b10001111, 0b01011100, 0b00111100,
            0b11001100, 0b11100000, 0b11110001,
        ];
        let keys: Vec<_> = k.iter().map(|k| rec_id(&[*k])).collect();
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[4])).await;
        test_arb_split_merge(OwnedRange::full(), &keys, &keys[3]).await;
    }

    #[tokio::test]
    async fn lob_sided_tree() {
        let k = &[
            0u8, 0b11111111, 0b11111110, 0b11111100, 0b11111000, 0b11110000, 0b11110001,
        ];
        let keys: Vec<_> = k.iter().map(|k| rec_id(&[*k])).collect();
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[4])).await;
        test_arb_split_merge(OwnedRange::full(), &keys, &keys[3]).await;
    }

    #[tokio::test]
    async fn on_and_between_all_keys() {
        let keys: Vec<_> = (2u8..251).step_by(10).map(|k| rec_id(&[k])).collect();
        test_arb_split_merge(OwnedRange::full(), &keys, &rec_id(&[1])).await;
        for k in &keys {
            test_arb_split_merge(OwnedRange::full(), &keys, k).await;
            let mut kk = k.clone();
            kk.0[22] = 5;
            test_arb_split_merge(OwnedRange::full(), &keys, &kk).await;
        }
    }

    // Creates a new tree populated with 'keys'. splits it into 2 at 'split'. verifies the split was correct
    // then merges them back together and verifies you got back to the start.
    async fn test_arb_split_merge(range: OwnedRange, keys: &[RecordId], split: &RecordId) {
        let (mut tree, mut root, mut store) = new_empty_tree(&range).await;
        for k in keys {
            root = tree_insert(&mut tree, &mut store, &range, root, k, vec![k.0[0]], true).await;
        }
        check_tree_invariants(&tree.hasher, &range, root, &store).await;
        assert_eq!(
            tree_size(KeySlice::empty(), root, &store).await.unwrap(),
            store.len()
        );
        let pre_split_root_hash = root;
        let pre_split_store = store.clone();

        let proof = read(&store, &range, &root, split).await.unwrap();
        let s = tree.range_split(proof).unwrap();
        check_delta_invariants(s.right.root_hash, &s.delta);
        store.apply_store_delta(s.left.root_hash, s.delta);
        check_tree_invariants(&TestHasher {}, &s.left.range, s.left.root_hash, &store).await;
        check_tree_invariants(&TestHasher {}, &s.right.range, s.right.root_hash, &store).await;
        assert_eq!(
            tree_size(KeySlice::empty(), s.left.root_hash, &store)
                .await
                .unwrap()
                + tree_size(KeySlice::empty(), s.right.root_hash, &store)
                    .await
                    .unwrap(),
            store.len()
        );

        let (mut tree_l, mut root_l, mut store_l) = new_empty_tree(&s.left.range).await;
        let (mut tree_r, mut root_r, mut store_r) = new_empty_tree(&s.right.range).await;
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
                )
                .await;
            } else {
                root_r = tree_insert(
                    &mut tree_r,
                    &mut store_r,
                    &s.right.range,
                    root_r,
                    k,
                    vec![k.0[0]],
                    true,
                )
                .await;
            }
        }
        check_tree_invariants(&TestHasher {}, &s.left.range, root_l, &store_l).await;
        check_tree_invariants(&TestHasher {}, &s.right.range, root_r, &store_r).await;

        if root_l != s.left.root_hash {
            dot::tree_to_dot(root_l, &store_l, "expected_left.dot")
                .await
                .unwrap();
            dot::tree_to_dot(s.left.root_hash, &store, "actual_left.dot")
                .await
                .unwrap();
            dot::tree_to_dot(s.right.root_hash, &store, "actual_right.dot")
                .await
                .unwrap();
            dot::tree_to_dot(root, &pre_split_store, "before_split.dot")
                .await
                .unwrap();
            panic!("left tree after split at {split:?} not as expected, see expected_left.dot & actual_left.dot for details");
        }
        if root_r != s.right.root_hash {
            dot::tree_to_dot(root_r, &store_r, "expected_right.dot")
                .await
                .unwrap();
            dot::tree_to_dot(s.left.root_hash, &store, "actual_left.dot")
                .await
                .unwrap();
            dot::tree_to_dot(s.right.root_hash, &store, "actual_right.dot")
                .await
                .unwrap();
            dot::tree_to_dot(root, &pre_split_store, "before_split.dot")
                .await
                .unwrap();
            panic!("right tree after split at {split:?} not as expected, see expected_right.dot & actual_right.dot for details");
        }

        let left_proof = read_tree_side(&store_l, &s.left.range, &root_l, Dir::Right)
            .await
            .unwrap();
        let right_proof = read_tree_side(&store_r, &s.right.range, &root_r, Dir::Left)
            .await
            .unwrap();

        let merged = tree_l.merge(left_proof, right_proof).unwrap();
        store_l.add_from_other_store(store_r);
        store_l.apply_store_delta(merged.root_hash, merged.delta);
        if pre_split_root_hash != merged.root_hash {
            dot::tree_to_dot(pre_split_root_hash, &pre_split_store, "before_split.dot")
                .await
                .unwrap();
            dot::tree_to_dot(merged.root_hash, &store_l, "after_merge.dot")
                .await
                .unwrap();
            assert_eq!(
                pre_split_root_hash, merged.root_hash,
                "tree after split then merge should be the same as before the initial split"
            );
        }
        check_tree_invariants(&tree_r.hasher, &merged.range, merged.root_hash, &store_l).await;
        assert_eq!(
            tree_size(KeySlice::empty(), merged.root_hash, &store_l)
                .await
                .unwrap(),
            store_l.len()
        );
    }
}
