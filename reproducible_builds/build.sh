#!/bin/sh

set -eux

# cd to repo root directory
cd -P -- "$(dirname -- "$0")/.."

git submodule update -- sdk
mkdir -p target/reproducible

docker run --rm  \
    --volume "$PWD:/juicebox:ro"  \
    --volume "$PWD/target/reproducible:/juicebox/target/reproducible:rw"  \
    --workdir /juicebox \
    --mount type=bind,source=$SSH_AUTH_SOCK,target=/ssh-agent \
    --env SSH_AUTH_SOCK=/ssh-agent \
    --env HOST_USER=$(id -u) \
    --env HOST_GROUP=$(id -g) \
    --interactive \
    --tty \
    juicebox-hsm-build \
    /juicebox/reproducible_builds/build_inner.sh
