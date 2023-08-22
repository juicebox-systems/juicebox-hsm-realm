#!/bin/sh

set -eu

if [ $# -ge 1 ]
then
    toolchain="+$1"; shift
else
    toolchain=''
    # Enable nightly features on stable cargo/rustc.
    export RUSTC_BOOTSTRAP=1
fi

cargo $toolchain build \
    -p hsm_core \
    --target powerpc-unknown-linux-gnu \
    -Z build-std=core,alloc \
    "$@"
