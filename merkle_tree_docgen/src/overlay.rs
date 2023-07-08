use std::path::Path;

use super::{dot_to_png, format_branch_label, DocTree, RecordIdHighlighter};
use bitvec::Bits;
use hsm_api::merkle::{Dir, KeyVec, Node};
use hsm_api::{OwnedRange, RecordId};
use hsmcore::merkle::dot::{hash_id, DotAttributes, DotGraph, DotVisitor, Visitor};
use hsmcore::merkle::proof::VerifiedProof;
use hsmcore::merkle::testing::{rec_id, TestHash, TestHasher};
use hsmcore::merkle::Tree;

pub fn tree_overlay(dir: &Path) {
    let dir = dir.join("overlay");
    new_value(&dir);
    proof_value(&dir);
    dot_to_png(&dir);
}

fn new_value(dir: &Path) {
    let mut tree = DocTree::new(OwnedRange::full());
    // need to reset to a smaller overlay
    tree.tree = Tree::<TestHasher>::with_existing_root(tree.root, 5);

    let proof_key = rec_id(&[0b00101100]);
    tree.insert(rec_id(&[0b10000000]), vec![1]);
    tree.insert(rec_id(&[0b00100110]), vec![1]);
    tree.insert(rec_id(&[0b00000100]), vec![1]);
    tree.insert(rec_id(&[0b01110000]), vec![1]);
    tree.insert(rec_id(&[0b00011100]), vec![1]);
    tree.insert(rec_id(&[0b00000001]), vec![1]);
    tree.insert(rec_id(&[0b00101100]), vec![1]);
    tree.insert(rec_id(&[0b01001000]), vec![2]);
    let proof = tree.tree.latest_proof(tree.proof(&proof_key)).unwrap();

    tree.insert(proof_key.clone(), vec![4]);
    tree.insert(rec_id(&[0b00101101]), vec![3]);
    tree.insert(rec_id(&[0b11001000]), vec![4]);

    let mut dot = DotGraph::new("overlay");
    // setting this enables rank=same to work on clusters not just subgraphs
    dot.attributes.set("newrank", "true");
    add_roots(&mut dot, &tree);
    add_proof(&mut dot, proof);
    add_overlay(&mut dot, &tree, proof_key);

    dot.write(dir, "new_value.dot").unwrap();
}

fn proof_value(dir: &Path) {
    let mut tree = DocTree::new(OwnedRange::full());
    // need to reset to a smaller overlay
    tree.tree = Tree::<TestHasher>::with_existing_root(tree.root, 5);

    let proof_key = rec_id(&[0b00101100]);
    tree.insert(proof_key.clone(), vec![1]);
    tree.insert(rec_id(&[0b10000000]), vec![1]);
    tree.insert(rec_id(&[0b00100110]), vec![1]);
    tree.insert(rec_id(&[0b00000100]), vec![1]);
    tree.insert(rec_id(&[0b01110000]), vec![1]);
    tree.insert(rec_id(&[0b00000001]), vec![1]);
    tree.insert(rec_id(&[0b01001000]), vec![2]);
    let proof = tree.tree.latest_proof(tree.proof(&proof_key)).unwrap();

    tree.insert(rec_id(&[0b00011100]), vec![1]);
    tree.insert(rec_id(&[0b11001000]), vec![4]);

    let mut dot = DotGraph::new("overlay");
    // setting this enables rank=same to work on clusters not just subgraphs
    dot.attributes.set("newrank", "true");
    add_roots(&mut dot, &tree);
    add_proof(&mut dot, proof);
    add_overlay(&mut dot, &tree, proof_key);

    dot.write(dir, "proof_value.dot").unwrap();
}

fn add_roots(dot: &mut DotGraph, tree: &DocTree) {
    let roots = dot.graph_mut("cluster_roots");
    roots.attributes.set("rank", "same");
    roots.attributes.set("label", "\"root hashes\"");

    let mut node_attr = DotAttributes::default();
    node_attr.set("shape", "box");
    node_attr.set("fillcolor", "darkseagreen");
    node_attr.set("style", "filled");

    let roots_to_show = &tree.roots[tree.roots.len() - 5..];
    for r in roots_to_show {
        node_attr.set("label", format!("\"root\\n{:?}\"", r));
        roots.add_node(hash_id(r), node_attr.clone());
    }
    for r in roots_to_show.windows(2) {
        roots.add_edge(hash_id(&r[0]), hash_id(&r[1]), DotAttributes::default());
    }
}

fn add_proof(dot: &mut DotGraph, proof: VerifiedProof<TestHash>) {
    let mut v = DotVisitor::new("cluster_proof");
    v.id_builder = proof_hash_id;
    v.branch_builder = format_branch_label;
    let proof_nodes = |hash: &TestHash| {
        for step in &proof.path {
            if step.hash == *hash {
                return Some(Node::Interior(step.node.clone()));
            }
        }
        let last_step = proof.path.last().unwrap();
        if let Some(leaf) = &proof.leaf {
            let leaf_hash = last_step
                .node
                .branch(last_step.next_dir)
                .as_ref()
                .unwrap()
                .hash;
            if hash == &leaf_hash {
                return Some(Node::Leaf(leaf.clone()));
            }
        }
        None
    };
    let proof_root = Node::Interior(proof.path[0].node.clone());
    visit_nodes(
        &KeyVec::new(),
        &proof.path[0].hash,
        &proof_root,
        &proof_nodes,
        &mut v,
    );
    v.dot.attributes.set("label", "proof");
    dot.add_graph(v.dot);

    // Connect from root hash in root list to proof root hash.
    // This edge needs to be in the top level graph, not one of the clusters.
    // Otherwise weird things happen with the placement of the root nodes.
    let mut edge_attr = DotAttributes::default();
    edge_attr.set("style", "dotted");
    edge_attr.set("arrowsize", "0.7");
    let root = proof.path[0].hash;
    dot.add_edge(hash_id(&root), proof_hash_id(&root), edge_attr);
}

fn proof_hash_id(hash: &TestHash) -> String {
    format!("p{}", hash_id(hash))
}

fn add_overlay(dot: &mut DotGraph, tree: &DocTree, proof_key: RecordId) {
    let overlay = tree.tree.overlay();

    if let Some(node) = overlay.nodes.get(&tree.root) {
        let mut v = DotVisitor::new("cluster_overlay");
        v.id_builder = overlay_id;
        v.branch_builder = format_branch_label;
        visit_nodes(
            &KeyVec::new(),
            &tree.root,
            node,
            &|h| overlay.nodes.get(h).cloned(),
            &mut v,
        );
        let mut overlay_dot = v.dot;

        let mut v = RecordIdHighlighter::new(proof_key, &mut overlay_dot);
        v.id_builder = overlay_id;
        visit_nodes(
            &KeyVec::new(),
            &tree.root,
            node,
            &|h| overlay.nodes.get(h).cloned(),
            &mut v,
        );

        // add the edge from the root nodes root to the overlay.
        let mut edge_attr = DotAttributes::default();
        edge_attr.set("style", "dotted");
        edge_attr.set("arrowsize", "0.7");
        dot.add_edge(hash_id(&tree.root), overlay_id(&tree.root), edge_attr);
        overlay_dot.attributes.set("label", "\"overlay nodes\"");
        dot.add_graph(overlay_dot);
    }
}

fn overlay_id(hash: &TestHash) -> String {
    format!("o{}", hash_id(hash))
}

fn visit_nodes(
    prefix: &KeyVec,
    hash: &TestHash,
    node: &Node<TestHash>,
    nodes: &impl Fn(&TestHash) -> Option<Node<TestHash>>,
    visitor: &mut impl Visitor<TestHash>,
) {
    visitor.visit_node(prefix, hash, node);
    if let Node::Interior(int) = node {
        if let Some(b) = int.branch(Dir::Left) {
            visitor.visit_branch(prefix, hash, Dir::Left, b);
            if let Some(c) = nodes(&b.hash) {
                visit_nodes(&prefix.concat(&b.prefix), &b.hash, &c, nodes, visitor);
            } else {
                visitor.visit_missing_node(&prefix.concat(&b.prefix), &b.hash);
            }
        }
        if let Some(b) = int.branch(Dir::Right) {
            visitor.visit_branch(prefix, hash, Dir::Right, b);
            if let Some(c) = nodes(&b.hash) {
                visit_nodes(&prefix.concat(&b.prefix), &b.hash, &c, nodes, visitor);
            } else {
                visitor.visit_missing_node(&prefix.concat(&b.prefix), &b.hash);
            }
        }
    }
}
