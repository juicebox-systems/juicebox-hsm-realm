use std::collections::HashSet;
use std::path::Path;

use super::TreeIndex;
use bitvec::bitvec;
use bitvec::Bits;
use hsm_api::merkle::KeyVec;
use hsm_api::RecordId;
use hsm_core::merkle::dot::{hash_id, DotGraph};

pub fn doc_merge(dir: &Path) {
    let dir = dir.join("merge");

    let tree = super::split::make_split_tree();
    let (left_tree, right_tree) = tree.split(RecordId::min_id().with(&[0b00001011]));

    // Highlight the left/right proofs.

    // 00001010 is the right most key in the left tree, highlight every node that's on the path.
    let left_proof_key = RecordId::min_id().with(&[0b00001010]);
    left_tree.highlight_record_id_to_dot(left_proof_key.clone(), &dir, "merge_left_proof.dot");

    // 00001111 is the left most key in the right tree, highlight every node that's on the path.
    let right_proof_key = RecordId::min_id().with(&[0b00001111]);
    right_tree.highlight_record_id_to_dot(right_proof_key.clone(), &dir, "merge_right_proof.dot");

    // highlight the branches of interest
    let highlight_branches = |mut dot: DotGraph, index: &TreeIndex, key: &KeyVec, filename| {
        let mut proof_nodes = HashSet::new();
        for l in 0..key.len() {
            if let Some(n) = index.prefixes.get(&key.slice(..l).to_bitvec()) {
                proof_nodes.insert(hash_id(n));
            }
        }
        for (from, to, edge) in dot.edges.iter_mut() {
            if proof_nodes.contains(from) && !proof_nodes.contains(to) {
                edge.set("fillcolor", "green4");
                edge.set("color", "green4");
                edge.set("fontcolor", "green4");
            } else {
                edge.set("color", "gray54");
                edge.set("fontcolor", "gray54");
            }
        }
        dot.write(&dir, filename).unwrap();
    };

    let left_index = TreeIndex::build(&left_tree);
    highlight_branches(
        left_tree.as_dot(),
        &left_index,
        &left_proof_key.to_bitvec(),
        "left_branches.dot",
    );

    let right_index = TreeIndex::build(&right_tree);
    highlight_branches(
        right_tree.as_dot(),
        &right_index,
        &right_proof_key.to_bitvec(),
        "right_branches.dot",
    );

    let tree = super::split::make_split_tree();
    let colors = [
        (bitvec![0, 0, 0, 0, 1, 0], "\"#FFAC53\""),
        (bitvec![0, 0, 0, 0, 1], "\"#b1f2eb\""),
        (bitvec![0, 0, 0, 0], "\"#F259FF\""),
        (bitvec![0, 0], "\"#4680DC\""),
        (bitvec![], "\"#00c000\""),
    ];
    let index = TreeIndex::build(&tree);
    let mut dot = tree.as_dot();
    for (prefix, color) in colors {
        let hash = index.prefixes.get(&prefix).unwrap();
        dot.node_mut(&hash_id(hash))
            .unwrap()
            .1
            .set("fillcolor", color);
    }
    dot.write(&dir, "final.dot").unwrap();
}
