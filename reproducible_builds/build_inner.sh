# cd to repo root directory
cd -P -- "$(dirname -- "$0")/.."

CARGO_TARGET_DIR=/target; export CARGO_TARGET_DIR
NIGHTLY=nightly-2023-06-01; export NIGHTLY

entrust_hsm/compile_linux.sh && cargo build --release -p entrust_init -p entrust_agent -p load_balancer -p cluster_manager -p cluster_cli

find $CARGO_TARGET_DIR/release/ -maxdepth 1 -executable -type f -exec sha256sum {} \;
find $CARGO_TARGET_DIR/powerpc-unknown-linux-gnu/release -name "*.elf" -maxdepth 1 -type f -exec sha256sum {} \;
