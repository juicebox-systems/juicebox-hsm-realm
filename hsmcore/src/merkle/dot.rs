use std::{
    fs::File,
    io::{BufWriter, Write},
};

use super::super::bitvec::DisplayBits;
use super::agent::StoreKey;
use super::{agent::tests::TreeStoreReader, agent::Node, Bits, Branch, Dir, HashOutput, KeyVec};
use async_recursion::async_recursion;
use juicebox_sdk_core::types::RealmId;

// Creates a dot file for a visualization of the tree starting
// at the supplied root hash.
pub async fn tree_to_dot<HO: HashOutput>(
    realm_id: &RealmId,
    reader: &impl TreeStoreReader<HO>,
    root: HO,
    output_file: &str,
) -> std::io::Result<()> {
    let f = File::create(output_file).unwrap();
    let mut w = BufWriter::new(f);
    writeln!(w, "digraph merkletree {{")?;
    add_node_to_dot(realm_id, KeyVec::new(), root, reader, &mut w).await?;
    writeln!(w, "}}")?;
    w.flush()
}

#[async_recursion]
async fn add_node_to_dot<W: Write + Send, HO: HashOutput>(
    realm_id: &RealmId,
    prefix: KeyVec,
    h: HO,
    reader: &impl TreeStoreReader<HO>,
    w: &mut W,
) -> std::io::Result<()> {
    match reader
        .read_node(realm_id, StoreKey::new(&prefix, &h))
        .await
        .unwrap_or_else(|_| panic!("node with hash {h:?} should exist"))
    {
        Node::Interior(int) => {
            if let Some(ref b) = int.left {
                write_branch(&h, b, Dir::Left, w)?;
                add_node_to_dot(realm_id, prefix.concat(&b.prefix), b.hash, reader, w).await?;
            }
            if let Some(ref b) = int.right {
                write_branch(&h, b, Dir::Right, w)?;
                add_node_to_dot(realm_id, prefix.concat(&b.prefix), b.hash, reader, w).await?;
            }
            writeln!(
                w,
                "h{:?} [label=\"{:?}\" style=filled fillcolor=azure3 ordering=out shape=box];",
                h, h
            )
        }
        Node::Leaf(l) => {
            writeln!(w,"h{:?} [label=\"{:?}\\nv:{:?}\" style=filled fillcolor=lightblue1 ordering=out shape=box];", h, h, l.value)
        }
    }
}
fn write_branch<HO: HashOutput>(
    parent: &HO,
    b: &Branch<HO>,
    dir: Dir,
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
        DisplayBits("\\n", &b.prefix),
    )
}
