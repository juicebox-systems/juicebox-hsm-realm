#!/bin/sh

set -eux

# cd to repo root directory
cd -P -- "$(dirname -- "$0")/.."

git submodule update --init -- sdk
mkdir -p target/reproducible

if [ "$(uname -s)" = Darwin ]; then
    # On OS X, `$SSH_AUTH_SOCK` defaults to a sandboxed `/var` location,
    # which Docker is unable to bind to the container.
    SSH_AUTH_SOCK=/run/host-services/ssh-auth.sock
fi

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
