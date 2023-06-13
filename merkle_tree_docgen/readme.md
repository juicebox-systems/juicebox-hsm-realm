# Merkle Tree Whitepaper Generation

This crate generates the diagrams used in the merkle tree whitepaper.

The code generates `{filename}.dot` files which are then processed with `dot` to
generate the PNGs.

`dot` should be installed and on the path. (`apt install graphviz` on Linux)

From the root of the overall repo, run `cargo run -p merkle_tree_docgen` to regenerate
the .dot and .png files.
