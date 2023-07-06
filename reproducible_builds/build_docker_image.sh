# cd to build directory
cd -P -- "$(dirname -- "$0")"

docker build -t juicebox-hsm-build .
