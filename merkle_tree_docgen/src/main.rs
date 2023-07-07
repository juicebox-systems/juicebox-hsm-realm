use clap::{Parser, ValueEnum};
use std::collections::BTreeMap;
use std::env::current_dir;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use bitvec::{BitVec, Bits};
use hsmcore::hsm::types::{OwnedRange, RecordId};
use hsmcore::merkle::agent::{Node, StoreKey};
use hsmcore::merkle::dot::{
    hash_id, visit_tree_at, DotGraph, DotVisitor, TreeStoreReader, Visitor,
};
use hsmcore::merkle::proof::ReadProof;
use hsmcore::merkle::testing::{
    new_empty_tree, read, rec_id, tree_insert, MemStore, TestHash, TestHasher,
};
use hsmcore::merkle::{Branch, Dir, HashOutput, KeyVec, Tree};
use juicebox_sdk_core::types::RealmId;

const REALM: RealmId = RealmId([1; 16]);

mod merge;
mod overlay;
mod split;

/// Generates figures and the final PDF in `docs/merkle_tree`.
///
/// Requires Graphviz and Docker (or a local Typst installation).
#[derive(Parser)]
struct Args {
    /// Typst installation.
    #[arg(long, value_enum, default_value_t = Typst::Docker)]
    typst: Typst,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    hsmcore::hash::set_global_rng_owned(rand_core::OsRng);

    let o = PathBuf::from("docs/merkle_tree");
    doc_intro(&o).await;
    doc_mutation(&o).await;
    doc_proofs(&o).await;
    split::doc_splits_intro(&o).await;
    split::doc_splits_details(&o).await;
    merge::doc_merge(&o).await;
    overlay::tree_overlay(&o).await;
    dot_to_png(&o.join("storage"));
    // generate the PDF.
    args.typst.compile();
}

async fn doc_intro(dir: &Path) {
    let dir = dir.join("intro");

    let mut tree = DocTree::new(OwnedRange::full()).await;
    tree.insert(rec_id(&[0b00000000]), vec![1]).await;
    tree.insert(rec_id(&[0b00001000]), vec![2]).await;
    tree.insert(rec_id(&[0b00001011]), vec![3]).await;
    tree.insert(rec_id(&[0b11001000]), vec![4]).await;
    tree.write_dot(&dir, "first_example.dot").await;
    dot_to_png(&dir);
}

async fn doc_mutation(dir: &Path) {
    let dir = dir.join("mutation");

    let mut tree = DocTree::new(OwnedRange::full()).await;
    tree.write_dot(&dir, "empty_tree.dot").await;

    tree.insert(rec_id(&[0b00001000]), vec![2]).await;
    tree.write_dot(&dir, "1_leaf.dot").await;

    tree.insert(rec_id(&[0]), vec![1]).await;
    tree.write_dot(&dir, "2_leaves.dot").await;

    tree.insert(rec_id(&[0b11001000]), vec![3]).await;
    tree.write_dot(&dir, "3_leaves.dot").await;

    tree.insert(rec_id(&[0b00001010]), vec![4]).await;
    tree.write_dot(&dir, "4_leaves.dot").await;

    dot_to_png(&dir);
}

async fn doc_proofs(dir: &Path) {
    let dir = dir.join("proofs");

    let mut tree = DocTree::new(OwnedRange::full()).await;
    tree.insert(rec_id(&[0]), vec![1]).await;
    tree.insert(rec_id(&[8]), vec![2]).await;
    tree.insert(rec_id(&[255]), vec![3]).await;

    tree.highlight_record_id_to_dot(rec_id(&[8]), &dir, "inclusion_proof.dot")
        .await;

    tree.highlight_record_id_to_dot(rec_id(&[1]), &dir, "noninclusion_proof.dot")
        .await;

    dot_to_png(&dir);
}

struct DocTree {
    realm: RealmId,
    tree: Tree<TestHasher>,
    root: TestHash,
    store: MemStore<TestHash>,
    partition: OwnedRange,
    roots: Vec<TestHash>,
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
            roots: vec![root],
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
        self.roots.push(self.root);
    }

    async fn proof(&self, k: &RecordId) -> ReadProof<TestHash> {
        read(&self.realm, &self.store, &self.partition, &self.root, k)
            .await
            .unwrap()
    }

    async fn as_dot(&self) -> DotGraph {
        let mut dot_visitor = DotVisitor::new("merkletree");
        dot_visitor.branch_builder = format_branch_label;
        visit_tree_at(
            &self.realm,
            &self.store,
            KeyVec::new(),
            self.root,
            &mut dot_visitor,
        )
        .await;
        dot_visitor.dot
    }

    async fn write_dot(&self, dir: &Path, name: impl AsRef<Path>) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(name), format!("{}", self.as_dot().await)).unwrap();
    }

    async fn highlight_record_id_to_dot(
        &self,
        record_id: RecordId,
        dir: &Path,
        output_filename: impl AsRef<Path>,
    ) {
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
        dot.write(dir, output_filename).unwrap();
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
            roots: vec![split.left.root_hash],
        };
        let right_tree = DocTree {
            realm: self.realm,
            tree: Tree::<TestHasher>::with_existing_root(split.right.root_hash, 1),
            root: split.right.root_hash,
            store: self.store,
            partition: split.right.range,
            roots: vec![split.right.root_hash],
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Typst {
    /// Run typst in a Docker container with a specific version bundled with
    /// specific fonts. This is recommended for reproducible PDFs.
    Docker,

    /// Run typst from the local $PATH.
    Path,
}

impl Typst {
    fn compile(self) {
        let mut command = match self {
            Self::Path => Command::new("typst"),
            Self::Docker => {
                let mut c = Command::new("docker");
                c.arg("run");
                c.arg("-i");
                c.arg("-v").arg(format!(
                    "{}:/root/docs",
                    current_dir().unwrap().join("docs").to_str().unwrap(),
                ));
                c.arg("ghcr.io/typst/typst:v0.5.0");
                c.arg("typst");
                c
            }
        };
        command.arg("compile").arg("docs/merkle_tree/merkle.typ");

        match command.output() {
            Err(err) => panic!(
                "failed to run typst from {}: {}",
                match self {
                    Self::Path => "$PATH",
                    Self::Docker => "a Docker image",
                },
                err
            ),

            Ok(output) => {
                if !output.status.success() {
                    panic!(
                        "typst ran but returned a failure exit code: {}\nStdout: {}\nStderr: {}\n",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr),
                    );
                }
            }
        }
    }
}

// This truncates the path labels so that it looks like an 8 bit tree.
struct TruncPathLabels<'a, HO> {
    dot: &'a mut DotGraph,
    id_builder: fn(&HO) -> String,
}

impl<'a, HO: HashOutput> Visitor<HO> for TruncPathLabels<'a, HO> {
    fn visit_node(&mut self, _prefix: &KeyVec, _hash: &HO, _node: &Node<HO>) {}
    fn visit_missing_node(&mut self, _prefix: &KeyVec, _node_hash: &HO) {}
    fn visit_branch(&mut self, prefix: &KeyVec, node_hash: &HO, dir: Dir, branch: &Branch<HO>) {
        if let Some(edge) = self.dot.edge_mut(
            &(self.id_builder)(node_hash),
            &(self.id_builder)(&branch.hash),
        ) {
            edge.2
                .set("label", format_branch_label(prefix, dir, branch));
        }
    }
}

fn format_branch_label<HO: HashOutput>(prefix: &KeyVec, dir: Dir, branch: &Branch<HO>) -> String {
    let display_path = if prefix.len() + branch.prefix.len() > 8 {
        // this will blow up if you incorrectly have a key with a non-zero value after the first byte.
        branch.prefix.slice(..8 - prefix.len())
    } else {
        branch.prefix.as_ref()
    };
    format!("\"{:?}: {}\"", dir, display_path)
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

struct RecordIdHighlighter<'a, HO> {
    id: BitVec,
    dot: &'a mut DotGraph,
    id_builder: fn(&HO) -> String,
}

impl<'a, HO: HashOutput> RecordIdHighlighter<'a, HO> {
    fn new(id: RecordId, dot: &'a mut DotGraph) -> Self {
        Self {
            id: id.to_bitvec(),
            dot,
            id_builder: hash_id,
        }
    }
}

impl<'a, HO: HashOutput> Visitor<HO> for RecordIdHighlighter<'a, HO> {
    fn visit_node(&mut self, prefix: &BitVec, hash: &HO, _node: &Node<HO>) {
        if self.id.starts_with(prefix) {
            let n = self.dot.node_mut(&(self.id_builder)(hash)).unwrap();
            n.1.set("fillcolor", "gold1");
        }
    }
    fn visit_missing_node(&mut self, _prefix: &KeyVec, _node_hash: &HO) {}

    fn visit_branch(&mut self, prefix: &BitVec, node_hash: &HO, _dir: Dir, branch: &Branch<HO>) {
        let color = if self.id.starts_with(&prefix.concat(&branch.prefix)) {
            "black"
        } else {
            "gray75"
        };
        self.dot
            .edge_mut(
                &(self.id_builder)(node_hash),
                &(self.id_builder)(&branch.hash),
            )
            .unwrap()
            .2
            .set("fontcolor", color)
            .set("color", color);
    }
}
