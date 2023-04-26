#!/bin/sh
cargo +nightly build -p hsmcore --target powerpc-unknown-linux-gnu -Z build-std=core,alloc "$@"
