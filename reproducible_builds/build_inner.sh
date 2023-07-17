#!/bin/sh

set -eux

# cd to repo root directory
cd -P -- "$(dirname -- "$0")/.."

CARGO_TARGET_DIR=$(pwd)/target/reproducible; export CARGO_TARGET_DIR
NIGHTLY=nightly-2023-06-01; export NIGHTLY
TMPDIR=${TMPDIR:-/tmp}

sha256sum Codesafe_Lin64-12.80.4.zip
mkdir -p $TMPDIR/encipher/codesafe
unzip -d $TMPDIR/encipher Codesafe_Lin64-12.80.4.zip
(
    cd $TMPDIR/encipher/codesafe
    7z x ../Codesafe_Lin64-12.80.4.iso
    tar -C / -xf linux/amd64/csd.tar.gz
)

entrust_hsm/compile_linux.sh
cargo build --release \
    -p cluster_cli \
    -p cluster_manager \
    -p entrust_agent \
    -p entrust_init \
    -p load_balancer

(
  find $CARGO_TARGET_DIR/powerpc-unknown-linux-gnu/release -maxdepth 1 -name '*.elf' -type f -print0
  find $CARGO_TARGET_DIR/release -maxdepth 1 -executable -type f -print0
) | sort -z | xargs -0 sha256sum
