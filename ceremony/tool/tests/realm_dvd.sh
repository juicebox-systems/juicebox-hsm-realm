#!/bin/sh

set -eux

# cd to tool directory
cd -P -- "$(dirname -- "$0")/.."

if cargo version; then
    cargo build
else
    echo "WARNING: cargo not installed, not building tool"
fi

rm -rf target/realm_dvd
mkdir -p target/realm_dvd

uid=$(id -u)
gid=$(id -g)

# privileged to be able to mount the ISO
docker run \
    --env HOST_USER="$uid:$gid" \
    --privileged \
    --rm \
    --volume "$PWD/target/debug/ceremony:/usr/local/bin/ceremony:ro" \
    --volume "$PWD/target/realm_dvd:/output/" \
    --volume "$PWD/tests/realm_dvd_inner.sh:/usr/local/bin/realm_dvd_inner.sh:ro" \
    debian:12 \
    realm_dvd_inner.sh

hexdump -C target/realm_dvd/realm.iso > tests/realm.iso.actual.txt
diff -u tests/realm.iso.txt tests/realm.iso.actual.txt
rm tests/realm.iso.actual.txt
