# to install tools
# https://sr.ht/~jplatte/cargo-depgraph/
# cargo install cargo-depgraph

# https://github.com/pksunkara/cargo-workspaces
# cargo install cargo-workspaces

# api install graphviz

# cd to repo root
cd -P -- "$(dirname -- "$0")/.."

cargo depgraph --dedup-transitive-deps --include `(cargo ws list  && cargo ws --manifest-path sdk/Cargo.toml list) | tr '\n' ','` | dot -Tpng -o crate_graph.png
