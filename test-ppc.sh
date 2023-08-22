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

# The e500mc is not the actual Entrust HSM CPU, but it's similar enough.
# (Qemu doesn't appear to know about the e5500.)
export CARGO_TARGET_POWERPC_UNKNOWN_LINUX_GNU_RUNNER='qemu-ppc -cpu e500mc'
export QEMU_LD_PREFIX='/usr/powerpc-linux-gnu/'
cargo $toolchain test \
    -p hsm_core \
    --target powerpc-unknown-linux-gnu \
    -Z build-std \
    "$@"
