extern crate alloc;

use alloc::vec::Vec;
use tracing::{info, trace};

use crate::merkle::InteriorNodeExt;

use super::proof;
use super::{
    proof::PathStep, Branch, HashOutput, InteriorNode, KeyVec, MergeError, MergeResult, NodeHasher,
    Tree,
};
use bitvec::Bits;
use hsm_api::merkle::{DeltaBuilder, Node, NodeKey, ReadProof};
use hsm_api::OwnedRange;

impl<H: NodeHasher> Tree<H> {
    // Merge an adjacent tree into this tree. Requires a read proof from both
    // trees. The tree to the left (in key order) should provide a right leaning
    // proof. The tree to the right should provide a left leaning proof. Note:
    // the root hash in other_proof must be verified by the caller to be the
    // latest hash for that tree, it can't be validated here.
    pub fn merge(
        self,
        my_proof: ReadProof<H::Output>,
        other_proof: ReadProof<H::Output>,
    ) -> Result<MergeResult<H::Output>, MergeError> {
        let mine = proof::verify::<H>(my_proof, &self.overlay).map_err(MergeError::Proof)?;
        let other = proof::verify_foreign_proof::<H>(other_proof).map_err(MergeError::Proof)?;

        let new_range = match mine.range.join(&other.range) {
            None => return Err(MergeError::NotAdjacentRanges),
            Some(p) => p,
        };
        info!("merging trees {} and {}", mine.range, other.range);

        let (left, right) = if mine.range.start < other.range.start {
            (&mine.path, &other.path)
        } else {
            (&other.path, &mine.path)
        };

        // We walk both proofs and collect up all the branches with their full key prefix to the nodes
        // that are not the branches on the path. I.e. all the other things pointed to by the path.
        // the nodes from the path get added to the delete set of the delta.
        fn collect<HO: HashOutput>(
            path: &[PathStep<HO>],
            branches: &mut Vec<Branch<HO>>,
            delta: &mut DeltaBuilder<HO>,
        ) {
            for (is_last, n) in path
                .iter()
                .enumerate()
                .map(|(i, n)| (i == path.len() - 1, n))
            {
                // We want the branch in the opposite direction of the walk.
                if let Some(b) = n.node.branch(n.next_dir.opposite()) {
                    let bp = n.prefix.concat(&b.prefix);
                    branches.push(Branch::new(bp, b.hash));
                }
                if is_last {
                    // For the last interior node we always want both branches.
                    if let Some(b) = n.node.branch(n.next_dir) {
                        let bp = n.prefix.concat(&b.prefix);
                        branches.push(Branch::new(bp, b.hash));
                    }
                }
                delta.remove(NodeKey::new(n.prefix.clone(), n.hash));
            }
        }

        let mut delta = DeltaBuilder::new();
        let mut branches = Vec::with_capacity(left.len() + right.len() + 2);
        collect(left, &mut branches, &mut delta);
        collect(right, &mut branches, &mut delta);
        branches.sort_by(|a, b| a.prefix.cmp(&b.prefix));

        for b in &branches {
            trace!(branch=?b, "branch to merge");
        }

        // Will recursively split branches into 0/1 groups and create join's once they're down to 2 branches.
        // Assumes branches is sorted by prefix low to high.
        fn reduce_to_tree<H: NodeHasher>(
            partition: &OwnedRange,
            bit_pos_start: usize,
            bit_pos: usize,
            branches: &[Branch<H::Output>],
            delta: &mut DeltaBuilder<H::Output>,
        ) -> Branch<H::Output> {
            assert!(!branches.is_empty());
            if branches.len() == 1 {
                let b = &branches[0];
                return Branch::new(b.prefix.slice(bit_pos_start..).into(), b.hash);
            }
            match branches.iter().position(|b| b.prefix[bit_pos]) {
                // everything is 0
                None => reduce_to_tree::<H>(partition, bit_pos_start, bit_pos + 1, branches, delta),
                // everything is 1
                Some(0) => {
                    reduce_to_tree::<H>(partition, bit_pos_start, bit_pos + 1, branches, delta)
                }
                Some(idx) => {
                    let left = reduce_to_tree::<H>(
                        partition,
                        bit_pos,
                        bit_pos + 1,
                        &branches[..idx],
                        delta,
                    );
                    let right = reduce_to_tree::<H>(
                        partition,
                        bit_pos,
                        bit_pos + 1,
                        &branches[idx..],
                        delta,
                    );
                    let (hash, n) = InteriorNode::construct::<H>(
                        partition,
                        bit_pos == 0,
                        Some(left),
                        Some(right),
                    );
                    delta.add(
                        NodeKey::new(branches[0].prefix.slice(..bit_pos).into(), hash),
                        Node::Interior(n),
                    );
                    Branch::new(
                        branches[0].prefix.slice(bit_pos_start..bit_pos).into(),
                        hash,
                    )
                }
            }
        }

        // Handle edge case where we're merging two empty trees, branches will be empty.
        let root_hash = if branches.is_empty() {
            let (hash, root) = InteriorNode::new_with_hash::<H>(&new_range, true, None, None);
            delta.add(NodeKey::new(KeyVec::new(), hash), Node::Interior(root));
            hash
        } else {
            let res = reduce_to_tree::<H>(&new_range, 0, 0, &branches, &mut delta);
            if res.prefix.is_empty() {
                res.hash
            } else {
                let (hash, n) = InteriorNode::construct::<H>(&new_range, true, Some(res), None);
                delta.add(NodeKey::new(KeyVec::new(), hash), Node::Interior(n));
                hash
            }
        };
        info!(?root_hash, %new_range, "merged trees");
        Ok(MergeResult {
            range: new_range,
            root_hash,
            delta: delta.build(),
        })
    }
}

// See split.rs for merge related tests
