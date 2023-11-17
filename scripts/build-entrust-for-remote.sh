#!/bin/sh

# Run this from a dev machine to:
# 1. Build all the binaries, including the Entrust stuff,
# 2. Copy them to a remote host,
# 3. Sign the binaries and userdata on that host for the HSM, and
# 4. Copy the signed archives back.
#
# The first argument should be the remote hostname.

set -eu

# cd to project directory
cd -P -- "$(dirname -- "$0")/.."

if [ $# -ne 1 ]; then
    echo "Usage: $0 <HOSTNAME>"
    exit 1
fi
REMOTE_HOST="$1"

set -x

cargo build --release \
    --package entrust_agent \
    --package entrust_init \
    --package entrust_ops \
    --workspace

if [ -d target/powerpc-unknown-linux-gnu/release ]; then
    find target/powerpc-unknown-linux-gnu/release \
        \( -name '*.sar' -o -name 'entrust_signed_by_*' \) \
        -delete
fi

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
    target/release/entrust_ops \
    target/release/hsm_bench \
    target/release/load_balancer \
    target/release/software_agent \
    "$REMOTE_HOST":juicebox-hsm-realm/

ssh "$REMOTE_HOST" \
    'cd juicebox-hsm-realm && \
    hostname --all-fqdns > target/powerpc-unknown-linux-gnu/release/signed_by_fqdns && \
    target/release/entrust_ops sign software && \
    target/release/entrust_ops sign userdata'

rsync --archive --compress --progress \
    "$REMOTE_HOST":'juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/entrust_hsm.sar' \
    "$REMOTE_HOST":'juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/userdata.sar' \
    "$REMOTE_HOST":'juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/signed_by_fqdns' \
    target/powerpc-unknown-linux-gnu/release/

# `hostname --all-fqdns` prints either just a newline or one or more
# space-delimited FQDNs and not-fully-qualified names, ending in an extra space
# before the newline. The ordering is not guaranteed. We prefer:
# 1. a "*.juicebox.xyz" address, over
# 2. another FQDN (such as Tailscale addresses), over
# 3. the name passed to this script.
fqdns=$(xargs -n 1 < target/powerpc-unknown-linux-gnu/release/signed_by_fqdns | LC_ALL=C sort)
remote_name=$(
    { echo "$fqdns" | grep --max-count 1 '\.juicebox\.xyz$' ; } || \
    { echo "$fqdns" | grep --max-count 1 '\.' ; } || \
    echo "$REMOTE_HOST"
)
true > "target/powerpc-unknown-linux-gnu/release/entrust_signed_by_$remote_name"
