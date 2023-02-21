CARGO_TARGET_POWERPC_UNKNOWN_LINUX_GNU_RUNNER='qemu-ppc -cpu e500mc' QEMU_LD_PREFIX="/usr/powerpc-linux-gnu/" cargo +nightly test --target powerpc-unknown-linux-gnu -Z build-std 
