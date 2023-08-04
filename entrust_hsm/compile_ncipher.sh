#!/bin/bash -eux
set -o pipefail

# cd to repo root directory
cd -P -- "$(dirname -- "$0")/.."

TARGET=e5500-entrust-ncipherxc-gnu

# Compile Rust code
cargo +nightly build --target entrust_hsm/$TARGET.json --release -Z build-std=core,alloc -p entrust_hsm $@

# cd to project dir
cd entrust_hsm

# Compile C code
/opt/nfast/gcc/bin/powerpc-codesafe-linux-gnu-gcc \
    -O2 -Wall -Wpointer-arith \
    -Wwrite-strings -Wstrict-prototypes \
    -Wmissing-prototypes -mpowerpc -mcpu=e5500 \
    -mno-toc -mbig-endian -mhard-float \
    -mno-multiple -mno-string -meabi \
    -mprototype -mstrict-align -memb \
    -fno-builtin -Werror -DNF_CROSSCC_PPC_GCC=1 \
    -I /opt/nfast/c/csd/include-see/module/ \
    -I /opt/nfast/c/csd/include-see/module/glibsee \
    -pthread -c src/main.c \
    -o ../target/$TARGET/release/hsm_main.o

NFAST_DIR=/opt/nfast/c/csd/lib-ppc-linux-gcc

# Link
/opt/nfast/gcc/bin/powerpc-codesafe-linux-gnu-gcc \
    -O2 -Wall -Wpointer-arith \
    -Wwrite-strings -Wstrict-prototypes \
    -Wmissing-prototypes -mpowerpc -mcpu=e5500 \
    -mno-toc -mbig-endian -mhard-float \
    -mno-multiple -mno-string -meabi \
    -mprototype -mstrict-align -memb \
    -fno-builtin -Werror -DNF_CROSSCC_PPC_GCC=1 \
    -pthread \
    -o ../target/$TARGET/release/entrust-hsm.elf \
    ../target/$TARGET/release/hsm_main.o \
    ../target/$TARGET/release/libentrust_hsm.a \
    $NFAST_DIR/seelib.a \
    $NFAST_DIR/rtlib/librtusr.a \
    -ldl -lm -lpthread
