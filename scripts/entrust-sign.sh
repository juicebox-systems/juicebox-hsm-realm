#!/bin/sh

# Run this from a server with an Entrust HSM to sign the SEE machine and dummy
# userdata.

set -eux

# cd to project directory
cd -P -- "$(dirname -- "$0")"
cd ..

DIR=target/powerpc-unknown-linux-gnu/release
KEY=jbox-signer

/opt/nfast/bin/tct2 --sign-and-pack \
    --infile $DIR/entrust_hsm.elf \
    --outfile $DIR/entrust_hsm.sar \
    --key $KEY \
    --is-machine \
    --machine-type PowerPCELF

echo dummy > $DIR/userdata.dummy
/opt/nfast/bin/tct2 --sign-and-pack \
    --infile $DIR/userdata.dummy \
    --outfile $DIR/userdata.sar \
    --key $KEY \
    --machine-key-ident $KEY \
    --machine-type PowerPCELF
