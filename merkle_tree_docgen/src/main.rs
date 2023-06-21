use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use hsmcore::bitvec::{BitVec, Bits};
use hsmcore::hsm::types::{OwnedRange, RecordId};
use hsmcore::merkle::agent::{Node, StoreKey};
use hsmcore::merkle::dot::{
    hash_id, tree_to_dot_document, visit_tree_at, DotGraph, TreeStoreReader, Visitor,
};
use hsmcore::merkle::testing::{
    new_empty_tree, read, rec_id, tree_insert, MemStore, TestHash, TestHasher,
};
use hsmcore::merkle::{Branch, Dir, HashOutput, KeyVec, Tree};
use juicebox_sdk_core::types::RealmId;

const REALM: RealmId = RealmId([1; 16]);

mod merge;
mod split;

#[tokio::main]
async fn main() {
    let o = PathBuf::from("docs/merkle_tree");
    doc_intro(&o).await;
    doc_mutation(&o).await;
    doc_proofs(&o).await;
    split::doc_splits_intro(&o).await;
    split::doc_splits_details(&o).await;
    merge::doc_merge(&o).await;
}

async fn doc_intro(dir: &Path) {
    let dir = dir.join("intro");

    let mut tree = DocTree::new(OwnedRange::full()).await;
    tree.insert(rec_id(&[0b00000000]), vec![1]).await;
    tree.insert(rec_id(&[0b00001000]), vec![2]).await;
    tree.insert(rec_id(&[0b00001010]), vec![3]).await;
    tree.insert(rec_id(&[0b11001000]), vec![4]).await;
    tree.write_dot(&dir.join("first_example.dot")).await;
    dot_to_png(&dir);
}

async fn doc_mutation(dir: &Path) {
    let dir = dir.join("mutation");

    let mut tree = DocTree::new(OwnedRange::full()).await;
    tree.write_dot(&dir.join("empty_tree.dot")).await;

    tree.insert(rec_id(&[0b00001000]), vec![2]).await;
    tree.write_dot(&dir.join("1_leaf.dot")).await;

    tree.insert(rec_id(&[0]), vec![1]).await;
    tree.write_dot(&dir.join("2_leaves.dot")).await;

    tree.insert(rec_id(&[0b11001000]), vec![3]).await;
    tree.write_dot(&dir.join("3_leaves.dot")).await;

    tree.insert(rec_id(&[0b00001010]), vec![4]).await;
    tree.write_dot(&dir.join("4_leaves.dot")).await;

    dot_to_png(&dir);
}

async fn doc_proofs(dir: &Path) {
    let dir = dir.join("proofs");

    let mut tree = DocTree::new(OwnedRange::full()).await;
    tree.insert(rec_id(&[0]), vec![1]).await;
    tree.insert(rec_id(&[8]), vec![2]).await;
    tree.insert(rec_id(&[255]), vec![3]).await;

    tree.highlight_record_id_to_dot(rec_id(&[8]), &dir.join("inclusion_proof.dot"))
        .await;

    tree.highlight_record_id_to_dot(rec_id(&[1]), &dir.join("noninclusion_proof.dot"))
        .await;

    dot_to_png(&dir);
}

struct DocTree {
    realm: RealmId,
    tree: Tree<TestHasher>,
    root: TestHash,
    store: MemStore<TestHash>,
    partition: OwnedRange,
}

impl DocTree {
    async fn new(part: OwnedRange) -> Self {
        let (tree, root, store) = new_empty_tree(&part).await;
        DocTree {
            realm: REALM,
            tree,
            root,
            store,
            partition: part,
        }
    }

    async fn get_node(&self, prefix: &KeyVec, hash: &TestHash) -> Node<TestHash> {
        self.store
            .read_node(&self.realm, StoreKey::new(prefix, hash))
            .await
            .unwrap()
    }

    async fn insert(&mut self, k: RecordId, v: Vec<u8>) {
        self.root = tree_insert(
            &mut self.tree,
            &mut self.store,
            &self.partition,
            &self.realm,
            self.root,
            &k,
            v,
            false,
        )
        .await;
    }

    async fn as_dot(&self) -> DotGraph {
        let mut dot = tree_to_dot_document(&self.realm, &self.store, self.root).await;
        visit_tree_at(
            &self.realm,
            &self.store,
            KeyVec::new(),
            self.root,
            &mut TruncPathLabels(&mut dot),
        )
        .await;
        dot
    }

    async fn write_dot(&self, output_file: &Path) {
        fs::write(output_file, format!("{}", self.as_dot().await)).unwrap();
    }

    async fn highlight_record_id_to_dot(&self, record_id: RecordId, output_file: &Path) {
        let mut dot = self.as_dot().await;
        let mut highligher = RecordIdHighlighter::new(record_id, &mut dot);
        visit_tree_at(
            &self.realm,
            &self.store,
            KeyVec::new(),
            self.root,
            &mut highligher,
        )
        .await;
        dot.write(output_file).unwrap();
    }

    async fn split(mut self, split_key: RecordId) -> (DocTree, DocTree) {
        let split_proof = read(
            &self.realm,
            &self.store,
            &self.partition,
            &self.root,
            &split_key,
        )
        .await
        .unwrap();

        let split = self.tree.range_split(split_proof).unwrap();
        self.store
            .apply_store_delta(split.left.root_hash, split.delta);

        let left_tree = DocTree {
            realm: self.realm,
            tree: Tree::<TestHasher>::with_existing_root(split.left.root_hash, 1),
            root: split.left.root_hash,
            store: self.store.clone(),
            partition: split.left.range,
        };
        let right_tree = DocTree {
            realm: self.realm,
            tree: Tree::<TestHasher>::with_existing_root(split.right.root_hash, 1),
            root: split.right.root_hash,
            store: self.store,
            partition: split.right.range,
        };
        (left_tree, right_tree)
    }
}

fn dot_to_png(dir: &Path) {
    let o = Command::new("bash")
        .arg("-c")
        .arg("dot -O -Tpng *.dot")
        .current_dir(dir)
        .output()
        .unwrap();
    if !o.status.success() {
        panic!(
            "failed to run dot program, ensure its installed and on the path. {}",
            o.status
        );
    }
}

// This truncates the path labels so that it looks like an 8 bit tree.
struct TruncPathLabels<'a>(&'a mut DotGraph);

impl<'a, HO: HashOutput> Visitor<HO> for TruncPathLabels<'a> {
    fn visit_node(&mut self, _prefix: &KeyVec, _hash: &HO, _node: &Node<HO>) {}
    fn visit_branch(&mut self, prefix: &KeyVec, node_hash: &HO, dir: Dir, branch: &Branch<HO>) {
        let edge = self
            .0
            .edge_mut(&hash_id(node_hash), &hash_id(&branch.hash))
            .unwrap();
        if prefix.len() + branch.prefix.len() > 8 {
            // this will blow up if you incorrectly have a key with a non-zero value after the first byte.
            let trunc = branch.prefix.slice(..8 - prefix.len());
            edge.2.set("label", format!("\"{:?}: {}\"", dir, trunc));
        }
    }
}

struct TreeIndex {
    prefixes: BTreeMap<KeyVec, TestHash>,
    parents: BTreeMap<TestHash, (KeyVec, TestHash)>,
}

impl TreeIndex {
    async fn build(t: &DocTree) -> Self {
        let mut index = TreeIndex {
            prefixes: BTreeMap::new(),
            parents: BTreeMap::new(),
        };
        visit_tree_at(&t.realm, &t.store, KeyVec::new(), t.root, &mut index).await;
        index
    }
}

impl Visitor<TestHash> for TreeIndex {
    fn visit_node(&mut self, prefix: &KeyVec, hash: &TestHash, _node: &Node<TestHash>) {
        self.prefixes.insert(prefix.clone(), *hash);
    }

    fn visit_branch(
        &mut self,
        prefix: &KeyVec,
        node_hash: &TestHash,
        _dir: Dir,
        branch: &Branch<TestHash>,
    ) {
        self.parents
            .insert(branch.hash, (prefix.clone(), *node_hash));
    }
}

struct RecordIdHighlighter<'a> {
    id: BitVec,
    dot: &'a mut DotGraph,
}

impl<'a> RecordIdHighlighter<'a> {
    fn new(id: RecordId, dot: &'a mut DotGraph) -> Self {
        Self {
            id: id.to_bitvec(),
            dot,
        }
    }
}

impl<'a, HO: HashOutput> Visitor<HO> for RecordIdHighlighter<'a> {
    fn visit_node(&mut self, prefix: &BitVec, hash: &HO, _node: &Node<HO>) {
        if self.id.starts_with(prefix) {
            let n = self.dot.node_mut(&hash_id(hash)).unwrap();
            n.1.set("fillcolor", "gold1");
        }
    }

    fn visit_branch(&mut self, prefix: &BitVec, node_hash: &HO, _dir: Dir, branch: &Branch<HO>) {
        let color = if self.id.starts_with(&prefix.concat(&branch.prefix)) {
            "black"
        } else {
            "gray75"
        };
        self.dot
            .edge_mut(&hash_id(node_hash), &hash_id(&branch.hash))
            .unwrap()
            .2
            .set("fontcolor", color)
            .set("color", color);
    }
}
