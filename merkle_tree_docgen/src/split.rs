use std::path::Path;

use super::{DocTree, TreeIndex};
use bitvec::bitvec;
use bitvec::Bits;
use hsm_api::merkle::{Dir, KeyVec, Node};
use hsm_api::OwnedRange;
use hsm_core::merkle::dot::{hash_id, DotAttributes, DotGraph};
use hsm_core::merkle::testing::{rec_id, TestHash};

pub fn doc_splits_intro(dir: &Path) {
    let dir = dir.join("splits");

    let tree = make_split_tree();
    let index = TreeIndex::build(&tree);
    let mut dot = tree.as_dot();

    let split_prefix = bitvec![0, 0, 0, 0, 1];
    let split_hash = index.prefixes.get(&split_prefix).unwrap();
    dot.node_mut(&hash_id(split_hash))
        .unwrap()
        .1
        .set("fillcolor", "gold1");
    dot.write(&dir, "intro_before.dot").unwrap();

    let (left_tree, right_tree) = tree.split(rec_id(&[0b00001011]));

    left_tree.write_dot(&dir, "intro_after_left.dot");

    right_tree.write_dot(&dir, "intro_after_right.dot");

    super::dot_to_png(&dir);
}

pub(crate) fn make_split_tree() -> DocTree {
    let mut tree = DocTree::new(OwnedRange::full());
    tree.insert(rec_id(&[0]), vec![1]);
    tree.insert(rec_id(&[0b00001000]), vec![2]);
    tree.insert(rec_id(&[0b00001010]), vec![3]);
    tree.insert(rec_id(&[0b00001111]), vec![4]);
    tree.insert(rec_id(&[0b00111011]), vec![5]);
    tree.insert(rec_id(&[0b11001000]), vec![6]);
    tree.insert(rec_id(&[0b11110000]), vec![7]);
    tree.insert(rec_id(&[0b11111010]), vec![8]);
    tree
}

pub fn doc_splits_details(dir: &Path) {
    let dir = dir.join("split_details");

    let tree = make_split_tree();
    let index = TreeIndex::build(&tree);
    let mut dot = tree.as_dot();

    let prefix = bitvec![0, 0, 0, 0, 1, 0];
    let hash = index.prefixes.get(&prefix).unwrap();
    dot.node_mut(&hash_id(hash))
        .unwrap()
        .1
        .set("fillcolor", "gold1");
    dot.write(&dir, "1_same_side.dot").unwrap();

    let mut dot = tree.as_dot();
    let prefix = bitvec![0, 0, 0, 0, 1];
    let hash = index.prefixes.get(&prefix).unwrap();
    dot.node_mut(&hash_id(hash))
        .unwrap()
        .1
        .set("fillcolor", "gold1");
    dot.write(&dir, "2_start.dot").unwrap();

    let mut dot = tree.as_dot();
    let split_key = bitvec![0, 0, 0, 0, 1, 0, 1, 1];
    let split_node_prefix = bitvec![0, 0, 0, 0, 1];
    let mut split_hash = index.prefixes.get(&split_node_prefix).unwrap();
    split_dot_tree_at(
        &tree,
        &index,
        &mut dot,
        &split_node_prefix,
        split_hash,
        &split_key,
    );

    dot.write(&dir, "3_split_1.dot").unwrap();

    // split the parents, write a file for each step up the tree.
    let mut file_num = 4;
    let mut hashes = vec![*split_hash];
    while let Some(parent) = index.parents.get(split_hash) {
        split_dot_tree_at(&tree, &index, &mut dot, &parent.0, &parent.1, &split_key);
        dot.write(&dir, format!("{file_num}_split_{}.dot", file_num - 2))
            .unwrap();
        split_hash = &parent.1;
        hashes.push(*split_hash);
        file_num += 1;
    }

    // highlight nodes that can be compressed.
    hashes.pop();
    for hash in hashes {
        highlight_if_compressible(hash_id(&hash), &mut dot);
        highlight_if_compressible(format!("{}_2", hash_id(&hash)), &mut dot);
    }
    // Remove the dotted edges connect the split nodes.
    // These edges are all in their own subgraphs called split_{hash}, so we can just delete those graphs.
    dot.graphs.retain(|g| !g.name.starts_with("split_"));
    dot.write(&dir, "7_split_collapse.dot").unwrap();

    // Show the 2 trees with the right hashes and the 3 recalculated nodes highlighted.
    // We'll do an actual split and show the results rather than trying to mutate
    // the last dot version.
    let (left_tree, right_tree) = tree.split(rec_id(split_key.as_bytes()));

    let mut left = left_tree.as_dot();
    left.node_mut(&hash_id(&left_tree.root))
        .unwrap()
        .1
        .set("fillcolor", "gold1");

    let Node::Interior(left_root) = left_tree.get_node(&KeyVec::new(), &left_tree.root) else {
        panic!()
    };

    let left_branch = left_root.branch(Dir::Left).as_ref().unwrap();
    left.node_mut(&hash_id(&left_branch.hash))
        .unwrap()
        .1
        .set("fillcolor", "gold1");

    let mut right = right_tree.as_dot();
    right
        .node_mut(&hash_id(&right_tree.root))
        .unwrap()
        .1
        .set("fillcolor", "gold1");

    let Node::Interior(right_root) = right_tree.get_node(&KeyVec::new(), &right_tree.root) else {
        panic!()
    };
    let left_branch = right_root.branch(Dir::Left).as_ref().unwrap();
    right
        .node_mut(&hash_id(&left_branch.hash))
        .unwrap()
        .1
        .set("fillcolor", "gold1");

    left.merge(right);
    left.write(&dir, "8_finished.dot").unwrap();

    super::dot_to_png(&dir);
}

fn highlight_if_compressible(node_id: String, dot: &mut DotGraph) {
    let children = dot
        .edges
        .iter()
        // don't count the edge between the split nodes.
        .filter(|(from, to, _)| from == &node_id && !from.starts_with(to))
        .count();

    if children == 1 {
        dot.node_mut(&node_id)
            .unwrap()
            .1
            .set("fillcolor", "purple")
            .set("fontcolor", "white");
    }
}

fn split_dot_tree_at(
    tree: &DocTree,
    index: &TreeIndex,
    dot: &mut DotGraph,
    prefix: &KeyVec,
    node: &TestHash,
    split_key: &KeyVec,
) {
    // highlight the node we're splitting in gold1 aka yellow.
    let node_name = hash_id(node);
    let node_dot = dot.node_mut(&node_name).unwrap();
    node_dot.1.set("fillcolor", "gold1");

    // make a copy of the node
    let attr = node_dot.1.clone();
    let split_node_name = format!("{node_name}_2");
    dot.nodes.insert(0, (split_node_name.clone(), attr));

    // move a child edge to the other side of the split
    // if the child was also split, move to the split side of the child.
    let Node::Interior(int) = tree.get_node(prefix, node) else {
        panic!()
    };
    let dir = Dir::from(split_key.at(prefix.len()));

    let child_hash = int.branch(dir).as_ref().unwrap().hash;
    let found = match dir {
        Dir::Left => match dot.edge_mut(&node_name, &format!("{}_2", hash_id(&child_hash))) {
            Some(e) => {
                e.0 = split_node_name.clone();
                true
            }
            None => false,
        },
        Dir::Right => match dot.edge_mut(&node_name, &format!("{}_2", hash_id(&child_hash))) {
            Some(e) => {
                e.0 = split_node_name.clone();
                // we also need to move the left branch in this case
                let child_hash = int.branch(Dir::Left).as_ref().unwrap().hash;
                if let Some(e) = dot.edge_mut(&node_name, &hash_id(&child_hash)) {
                    e.0 = split_node_name.clone();
                }
                true
            }
            None => false,
        },
    };
    if !found {
        // This happens for the first level that's split.
        dot.edge_mut(&node_name, &hash_id(&child_hash)).unwrap().0 = split_node_name.clone()
    }

    // copy the edge leading to the node. (which won't exist for the root node)
    if let Some(parent) = index.parents.get(node) {
        let parent_node_name = hash_id(&parent.1);
        let idx = dot
            .edges
            .iter()
            .position(|(from, to, _)| from == &parent_node_name && to == &node_name)
            .unwrap();

        let attr = dot.edges[idx].2.clone();
        dot.edges
            .insert(idx, (parent_node_name, split_node_name.clone(), attr));
    }

    // create the subgraph and edge that causes the 2 nodes to be next to each other.
    let sg = dot.graph_mut(&format!("split_{node:?}"));
    sg.attributes.set("rank", "same");
    let mut attr = DotAttributes::default();
    attr.set("style", "dotted");
    attr.set("arrowhead", "none");
    attr.set("arrowtail", "none");
    attr.set("dir", "both");
    sg.add_edge(split_node_name, node_name, attr);
}
