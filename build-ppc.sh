#!/bin/sh
if [ $# -ge 1 ]
then
    toolchain=$1; shift
else
    toolchain="nightly"
fi
cargo +${toolchain} build -p hsmcore --target powerpc-unknown-linux-gnu -Z build-std=core,alloc "$@"
