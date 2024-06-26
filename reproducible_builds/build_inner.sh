#!/bin/sh

set -eux

# cd to repo root directory
cd -P -- "$(dirname -- "$0")/.."

CARGO_TARGET_DIR=/target; export CARGO_TARGET_DIR
TMPDIR=${TMPDIR:-/tmp}
OUT_DIR=$(pwd)/target/reproducible

sha256sum Codesafe_Lin64-13.4.3.iso.zip
mkdir -p $TMPDIR/ncipher/codesafe
unzip -d $TMPDIR/ncipher Codesafe_Lin64-13.4.3.iso.zip
(
    cd $TMPDIR/ncipher/codesafe
    7z x ../Codesafe_Lin64-13.4.3.iso
    tar -C / -xf linux/amd64/csd.tar.gz
)

entrust_hsm/compile_linux.sh
cargo build --release \
    -p cluster_cli \
    -p cluster_manager \
    -p entrust_agent \
    -p entrust_init \
    -p entrust_ops \
    -p load_balancer

outputs='
    powerpc-unknown-linux-gnu/release/entrust_hsm.elf
    release/cluster
    release/cluster_manager
    release/entrust_agent
    release/entrust_init
    release/entrust_ops
    release/load_balancer
'

cd $CARGO_TARGET_DIR
sha256sum $outputs

# The overall TAR file should also be deterministic (for convenience). See
# https://reproducible-builds.org/docs/archives/ for relevant flags.
tar --mtime='2023-01-01 00:00Z' \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
     -cf $OUT_DIR/dist.tgz $outputs
cd $OUT_DIR
sha256sum dist.tgz
chown -R "$HOST_USER:$HOST_GROUP" dist.tgz
