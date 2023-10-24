#!/bin/sh

# Run this from a dev machine to:
# 1. Build all the binaries, including the Entrust stuff;
# 2. Copy them to a remote host, along with some helper files; and
# 3. Sign the binaries and userdata on that host for the HSM.

set -eux

# cd to project directory
cd -P -- "$(dirname -- "$0")"
cd ..

REMOTE_HOST="$1"

cargo build --release \
    --package entrust_agent \
    --package entrust_init \
    --workspace
./entrust_hsm/compile_linux.sh --features insecure

rsync --archive --compress --mkpath --progress --relative \
    secrets-demo.json \
    scripts/ \
    target/powerpc-unknown-linux-gnu/release/entrust_hsm.elf \
    target/release/cluster \
    target/release/cluster_bench \
    target/release/cluster_manager \
    target/release/demo_runner \
    target/release/entrust_agent \
    target/release/entrust_init \
    target/release/hsm_bench \
    target/release/load_balancer \
    target/release/software_agent \
    "$REMOTE_HOST":juicebox-hsm-realm/

ssh "$REMOTE_HOST" juicebox-hsm-realm/scripts/entrust-sign.sh

rsync --archive --compress --progress \
    "$REMOTE_HOST":juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/*.sar \
    target/powerpc-unknown-linux-gnu/release/
