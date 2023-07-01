# Merkle Tree Whitepaper Generation

This crate generates the diagrams used in the merkle tree whitepaper.

The code generates `{filename}.dot` files which are then processed with `dot` to
generate the PNGs.

`dot` should be installed and on the path. (`apt install graphviz` on Linux)

It will also run `typst` to generate a new version of the merkle.pdf output.

typst is run from a docker container by default. This can be overridden with the
`--typst` command line flag.

See https://github.com/typst/typst for more information on typst.

From the root of the overall repo, run `cargo run -p merkle_tree_docgen` to regenerate
the .dot, .png and .pdf files.
