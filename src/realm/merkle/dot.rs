use std::{
    fs::File,
    io::{BufWriter, Write},
};

use super::{
    agent::Node, agent::TreeStoreReader, concat, Branch, Dir, HashOutput, KeySlice, KeyVec,
};

// Creates a dot file for a visualization of the tree starting
// at the supplied root hash.
pub fn tree_to_dot<HO: HashOutput>(
    root: HO,
    reader: &impl TreeStoreReader<HO>,
    output_file: &str,
) -> std::io::Result<()> {
    let f = File::create(output_file).unwrap();
    let mut w = BufWriter::new(f);
    writeln!(w, "digraph merkletree {{")?;
    add_node_to_dot(KeyVec::new(), root, reader, &mut w)?;
    writeln!(w, "}}")?;
    w.flush()
}
fn add_node_to_dot<HO: HashOutput>(
    prefix: KeyVec,
    h: HO,
    reader: &impl TreeStoreReader<HO>,
    w: &mut impl Write,
) -> std::io::Result<()> {
    match reader
        .fetch(prefix.clone(), h)
        .unwrap_or_else(|_| panic!("node with hash {h:?} should exist"))
    {
        Node::Interior(int) => {
            if let Some(ref b) = int.left {
                write_branch(&prefix, &int.hash, b, Dir::Left, reader, w)?;
            }
            if let Some(ref b) = int.right {
                write_branch(&prefix, &int.hash, b, Dir::Right, reader, w)?;
            }
            writeln!(
                w,
                "h{:?} [label=\"{:?}\" style=filled fillcolor=azure3 ordering=out shape=box];",
                int.hash, int.hash
            )
        }
        Node::Leaf(l) => {
            writeln!(w,"h{:?} [label=\"{:?}\\nv:{:?}\" style=filled fillcolor=lightblue1 ordering=out shape=box];", l.hash,l.hash,l.value)
        }
    }
}
fn write_branch<HO: HashOutput>(
    prefix: &KeySlice,
    parent: &HO,
    b: &Branch<HO>,
    dir: Dir,
    reader: &impl TreeStoreReader<HO>,
    w: &mut impl Write,
) -> std::io::Result<()> {
    let lb = if b.prefix.len() > 8 { "\\n" } else { " " };
    writeln!(
        w,
        "h{:?} -> h{:?} [label=\"{}:{}{}\\l\" nojustify=true arrowsize=0.7];",
        parent,
        b.hash,
        dir,
        lb,
        super::compact_keyslice_str(&b.prefix, "\\n")
    )?;
    add_node_to_dot(concat(prefix, &b.prefix), b.hash, reader, w)
}
