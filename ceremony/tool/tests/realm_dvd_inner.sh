#!/bin/sh

set -eux

apt update
apt install --no-install-recommends --yes xorriso

mkdir -p /opt/nfast/kmdata/local
echo mac > /opt/nfast/kmdata/local/key_simple_jbox-mac
echo noise > /opt/nfast/kmdata/local/key_simple_jbox-noise
echo record > /opt/nfast/kmdata/local/key_simple_jbox-record
echo world > /opt/nfast/kmdata/local/world

mkdir -p /root/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release
echo hsmsar > /root/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/entrust_hsm.sar
echo userdata > /root/juicebox-hsm-realm/target/powerpc-unknown-linux-gnu/release/userdata.sar

mkdir -p /root/juicebox-hsm-realm/target/release
echo init > /root/juicebox-hsm-realm/target/release/entrust_init

epoch=$(date -u -d 2023-01-01 +'%s')
SOURCE_DATE_EPOCH=$epoch ceremony realm-dvd create-iso

chown "$HOST_USER" /root/realm.iso
cp -av /root/realm.iso /output/

mkdir -p /run/dvd
mount -o ro /root/realm.iso /run/dvd # requires privileged docker, probably
ceremony realm-dvd verify
ceremony realm-dvd unmount
