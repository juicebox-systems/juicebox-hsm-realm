#!/bin/bash
#
# does a build optionally including the entrust components. Uploads the
# results to a google cloud bucket from where it can be deployed.
#
# build-and-upload [-e]
#
# with no args, builds the standard components
# with -e will build the entrust components as well.
#
# ./build-and-upload.sh -e
#
set -eu

ENTRUST=0
MODE='release' # or 'debug'

while getopts :e FLAG
do
  case "${FLAG}" in
    e) ENTRUST=1 ;;
    *) exit 1 ;;
  esac
done

PROJECT='juicebox-infra'
BUCKET='9c39e3ca5fca69f058b9e673aef193b10d9e8c48' # sha1("ci-builds\n")

GIT=`git rev-parse HEAD`
GSPATH="$BUCKET/$GIT"

if ! command -v gcloud > /dev/null; then
  echo "ERROR: Cannot find 'gcloud'. See https://cloud.google.com/sdk/docs/install"
  exit 1
fi

echo "Building version $GIT in $MODE mode"
if [ "$ENTRUST" -eq "1" ]; then
  cargo build --all "--$MODE"
  entrust_hsm/compile_linux.sh --features insecure
else
  cargo build "--$MODE"
fi

echo 'Uploading artifacts to Google Cloud Storage'
gcloud storage cp \
  "target/$MODE/cluster" \
  "target/$MODE/cluster_bench" \
  "target/$MODE/cluster_manager" \
  "target/$MODE/load_balancer" \
  "target/$MODE/service_checker" \
  "target/$MODE/software_agent" \
  "target/$MODE/software_hsm" \
  "target/$MODE/chaos" \
  "gs://$GSPATH/"

if [ "$ENTRUST" -eq "1" ]; then
  gcloud storage cp \
    "target/$MODE/entrust_agent" \
    "target/$MODE/entrust_init" \
    "target/$MODE/entrust_ops" \
    "target/powerpc-unknown-linux-gnu/$MODE/entrust_hsm.elf" \
    "gs://$GSPATH/"
fi

echo 'Upload done:'
echo "https://console.cloud.google.com/storage/browser/$GSPATH?project=$PROJECT"
