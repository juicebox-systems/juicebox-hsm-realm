use tracing::info;

use super::super::hsm::types::{OwnedRange, RecordId};
use super::{
    agent::{DeltaBuilder, Node},
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
                delta.add(Node::Interior(left_node));
                delta.add(Node::Interior(right_node));
                delta.remove(&root.hash);
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
                delta.add(Node::Interior(left_node));
                delta.add(Node::Interior(right_node));
                delta.remove(&root.hash);
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
                delta.remove(&split.hash);

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
                        delta.add(Node::Interior(new_node));
                        let ext_prefix_res = Branch::new(
                            concat(&parent_b.prefix, &extends_prefix.prefix),
                            extends_prefix.hash,
                        );
                        match parent_d {
                            Dir::Left => (ext_prefix_res, new_node_res),
                            Dir::Right => (new_node_res, ext_prefix_res),
                        }
                    };
                    delta.remove(&parent.hash);
                }
                let left_root = if !left.prefix.is_empty() {
                    let n =
                        InteriorNode::construct(&self.hasher, &left_range, true, None, Some(left));
                    let h = n.hash;
                    delta.add(Node::Interior(n));
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
                    delta.add(Node::Interior(n));
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
