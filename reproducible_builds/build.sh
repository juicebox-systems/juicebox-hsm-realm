# cd to repo root directory
cd -P -- "$(dirname -- "$0")/.."

docker run --rm  \
    --volume "$PWD:/juicebox:ro"  \
    --volume "/opt/nfast/c/csd:/opt/nfast/c/csd:ro" \
    --volume "/opt/nfast/gcc:/opt/nfast/gcc:ro" \
    --workdir /juicebox \
    --mount type=bind,source=$SSH_AUTH_SOCK,target=/ssh-agent \
    --env SSH_AUTH_SOCK=/ssh-agent \
    juicebox-hsm-build \
    bash -c "/juicebox/reproducible_builds/build_inner.sh"
