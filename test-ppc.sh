#!/bin/sh
if [ $# -ge 1 ]
then
    toolchain=$1; shift
else
    toolchain="nightly"
fi
# the e500mc is not the actual Entrust HSM CPU, but is similar enough (Qemu doesn't appear to know about the e5500)
CARGO_TARGET_POWERPC_UNKNOWN_LINUX_GNU_RUNNER='qemu-ppc -cpu e500mc' QEMU_LD_PREFIX="/usr/powerpc-linux-gnu/" cargo +${toolchain} test -p hsm_core --target powerpc-unknown-linux-gnu -Z build-std  "$@"
