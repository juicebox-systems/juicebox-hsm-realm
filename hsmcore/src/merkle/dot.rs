extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{Display, Write};
use core::marker::PhantomData;
use std::path::Path;
use std::{fs, io};

use super::testing::MemStore;
use crate::merkle::{Branch, Dir, HashOutput, KeyVec};
use bitvec::Bits;
use bitvec::{BitVec, DisplayBits};
use hsm_api::merkle::Node;

// Creates a dot file for a visualization of the tree starting
// at the supplied root hash.
pub fn tree_to_dot<HO: HashOutput>(
    store: &MemStore<HO>,
    root: HO,
    dir: &Path,
    output_filename: impl AsRef<Path>,
) -> std::io::Result<()> {
    tree_to_dot_document(store, root).write(dir, output_filename)
}

pub fn tree_to_dot_document<HO: HashOutput>(reader: &MemStore<HO>, root: HO) -> DotGraph {
    let mut dot_visitor = DotVisitor::new("merkletree");
    visit_tree_at(reader, KeyVec::new(), root, &mut dot_visitor);
    dot_visitor.dot
}

pub trait Visitor<HO: HashOutput>: Sync {
    fn visit_node(&mut self, prefix: &KeyVec, node_hash: &HO, node: &Node<HO>);
    fn visit_missing_node(&mut self, _prefix: &KeyVec, node_hash: &HO) {
        panic!("node with hash {node_hash:?} should exist");
    }
    fn visit_branch(&mut self, prefix: &KeyVec, node_hash: &HO, dir: Dir, branch: &Branch<HO>);
}

pub fn visit_tree_at<HO: HashOutput>(
    store: &MemStore<HO>,
    prefix: KeyVec,
    h: HO,
    visitor: &mut (impl Visitor<HO> + Send),
) {
    match store.get_node(&h) {
        Err(_) => visitor.visit_missing_node(&prefix, &h),
        Ok(node) => {
            visitor.visit_node(&prefix, &h, &node);
            if let Node::Interior(int) = node {
                if let Some(ref b) = int.left {
                    visitor.visit_branch(&prefix, &h, Dir::Left, b);
                    visit_tree_at(store, prefix.concat(&b.prefix), b.hash, visitor);
                }
                if let Some(ref b) = int.right {
                    visitor.visit_branch(&prefix, &h, Dir::Right, b);
                    visit_tree_at(store, prefix.concat(&b.prefix), b.hash, visitor);
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphType {
    Digraph,
    Subgraph,
}

pub struct DotGraph {
    pub graph: GraphType,
    pub name: String,
    pub attributes: DotAttributes,
    // order is important, especially for edges, hence Vec rather than a Map.
    pub nodes: Vec<(String, DotAttributes)>,
    pub edges: Vec<(String, String, DotAttributes)>,
    pub graphs: Vec<DotGraph>,
}

impl DotGraph {
    pub fn new(name: impl Into<String>) -> Self {
        DotGraph {
            graph: GraphType::Digraph,
            name: name.into(),
            attributes: DotAttributes::default(),
            nodes: Vec::new(),
            edges: Vec::new(),
            graphs: Vec::new(),
        }
    }

    pub fn merge(&mut self, other: DotGraph) {
        self.attributes.0.extend(other.attributes.0);
        self.nodes.extend(other.nodes);
        self.edges.extend(other.edges);
        self.graphs.extend(other.graphs);
    }

    pub fn add_graph(&mut self, mut g: DotGraph) {
        g.graph = GraphType::Subgraph;
        self.graphs.push(g);
    }

    pub fn add_node(&mut self, name: impl Into<String>, attr: DotAttributes) {
        self.nodes.push((name.into(), attr));
    }

    pub fn add_edge(
        &mut self,
        from: impl Into<String>,
        to: impl Into<String>,
        attr: DotAttributes,
    ) {
        self.edges.push((from.into(), to.into(), attr));
    }

    pub fn node_mut(&mut self, name: &str) -> Option<&mut (String, DotAttributes)> {
        let r = self.nodes.iter_mut().find(|(n, _)| n == name);
        if r.is_some() {
            return r;
        }
        for g in self.graphs.iter_mut() {
            let r = g.node_mut(name);
            if r.is_some() {
                return r;
            }
        }
        None
    }

    pub fn edge_mut(
        &mut self,
        from: &str,
        to: &str,
    ) -> Option<&mut (String, String, DotAttributes)> {
        let e = self
            .edges
            .iter_mut()
            .find(|(f, t, _attr)| f == from && t == to);
        if e.is_some() {
            return e;
        }
        for g in self.graphs.iter_mut() {
            let e = g.edge_mut(from, to);
            if e.is_some() {
                return e;
            }
        }
        None
    }

    pub fn graph_mut(&mut self, name: &str) -> &mut DotGraph {
        let idx = match self.graphs.iter().position(|g| g.name == name) {
            None => {
                let mut g = DotGraph::new(name);
                g.graph = GraphType::Subgraph;
                self.graphs.push(g);
                self.graphs.len() - 1
            }
            Some(i) => i,
        };
        &mut self.graphs[idx]
    }

    pub fn write(&self, dir: &Path, name: impl AsRef<Path>) -> io::Result<()> {
        fs::create_dir_all(dir)?;
        fs::write(dir.join(name), format!("{self}"))
    }
}

impl Display for DotGraph {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "{:?} {} {{", self.graph, self.name)?;
        writeln!(f, "{:#}", self.attributes)?;
        for (name, node) in &self.nodes {
            writeln!(f, "{} [{}];", name, node)?;
        }
        for (from, to, edge) in &self.edges {
            writeln!(f, "{} -> {} [{}];", from, to, edge)?;
        }
        for g in &self.graphs {
            writeln!(f)?;
            writeln!(f, "{g}")?;
        }
        writeln!(f, "}}")
    }
}

#[derive(Clone, Default)]
pub struct DotAttributes(BTreeMap<String, String>);

impl DotAttributes {
    pub fn set(&mut self, name: impl Into<String>, val: impl Into<String>) -> &mut Self {
        self.0.insert(name.into(), val.into());
        self
    }
}

impl Display for DotAttributes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (k, v) in &self.0 {
            write!(f, "{}={}", k, v)?;
            if f.alternate() {
                writeln!(f)?;
            } else {
                f.write_char(' ')?;
            }
        }
        Ok(())
    }
}

pub struct DotVisitor<HO> {
    pub dot: DotGraph,
    pub id_builder: fn(&HO) -> String,
    pub branch_builder: fn(&KeyVec, Dir, &Branch<HO>) -> String,
    phantom_data: PhantomData<HO>,
}

impl<HO: HashOutput> DotVisitor<HO> {
    pub fn new(name: impl Into<String>) -> Self {
        DotVisitor {
            dot: DotGraph::new(name),
            id_builder: hash_id,
            branch_builder: format_branch_label,
            phantom_data: PhantomData,
        }
    }

    fn depth_graph(&mut self, prefix: &KeyVec) -> &mut DotGraph {
        // We create a subgraph for each prefix bit depth so that we can force
        // the layout to put nodes at the same bit depth at the same vertical
        // position in the output.
        let cluster_name = format!("depth_{}", prefix.len());
        let depth_graph = self.dot.graph_mut(&cluster_name);
        depth_graph.attributes.set("rank", "same");
        depth_graph
    }
}

impl<HO: HashOutput> Visitor<HO> for DotVisitor<HO> {
    fn visit_node(&mut self, prefix: &BitVec, hash: &HO, node: &Node<HO>) {
        let n = node_to_dot(prefix, hash, node);
        let id = (self.id_builder)(hash);
        self.depth_graph(prefix).add_node(id, n);
    }

    fn visit_missing_node(&mut self, prefix: &KeyVec, node_hash: &HO) {
        let mut node = DotAttributes::default();
        node.set("style", "dotted");
        node.set("ordering", "out");
        node.set("shape", "box");
        node.set("label", format!("\"{:?}\"", node_hash));
        let id = (self.id_builder)(node_hash);
        self.depth_graph(prefix).add_node(id, node);
    }

    fn visit_branch(&mut self, prefix: &BitVec, node_hash: &HO, dir: Dir, branch: &Branch<HO>) {
        let mut attr = DotAttributes::default();
        attr.set("nojustify", "true");
        attr.set("arrowsize", "0.7");

        attr.set("label", (self.branch_builder)(prefix, dir, branch));
        self.dot.add_edge(
            (self.id_builder)(node_hash),
            (self.id_builder)(&branch.hash),
            attr,
        );
    }
}

pub fn node_to_dot<HO: HashOutput>(prefix: &BitVec, hash: &HO, node: &Node<HO>) -> DotAttributes {
    let mut attr = DotAttributes::default();
    if prefix.is_empty() {
        attr.set("fillcolor", "darkseagreen");
    } else if matches!(node, Node::Leaf(_)) {
        attr.set("fillcolor", "lightblue1");
    } else {
        attr.set("fillcolor", "azure3");
    }
    attr.set("style", "filled");
    attr.set("ordering", "out");
    attr.set("shape", "box");
    fn format_leaf_value(v: &[u8]) -> String {
        if v.len() == 1 && v[0] <= 26 {
            ((b'A' + v[0] - 1) as char).into()
        } else {
            format!("{:?}", v)
        }
    }
    match node {
        Node::Interior(_) if prefix.is_empty() => {
            attr.set("label", format!("\"root\\n{:?}\"", hash))
        }
        Node::Interior(_) => attr.set("label", format!("\"{:?}\"", hash)),
        Node::Leaf(l) => attr.set(
            "label",
            format!("\"{:?}\\nvalue: {}\"", hash, format_leaf_value(&l.value)),
        ),
    };
    attr
}

pub fn hash_id<HO: HashOutput>(h: &HO) -> String {
    format!("h{h:?}")
}

fn format_branch_label<HO>(_prefix: &KeyVec, dir: Dir, branch: &Branch<HO>) -> String {
    let lb = if branch.prefix.len() > 8 { "\\n" } else { " " };
    format!(
        "\"{}:{}{}\\l\"",
        dir,
        lb,
        DisplayBits {
            byte_separator: "\\n",
            opener: "",
            closer: "",
            bits: &branch.prefix
        }
    )
}
