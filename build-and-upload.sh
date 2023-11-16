#!/bin/bash
#
# does a build optionally including the entrust components. Uploads the
# results to a google cloud bucket from where it can be deployed.
#
# build-and-upload [-e <hsm-host>]
#
# with no args, builds the standard components
# with -e <hsm-host> will build & sign the entrust components as well.
#
# e.g. to use agent-2 in the colo to sign the code.
# ./build-and-upload.sh -e agent@100.79.214.29
#
set -eu

ENTRUST=0
MODE='release' # or 'debug'

while getopts e: FLAG
do
  case "${FLAG}" in
    e) REMOTE_HOST="${OPTARG}"; ENTRUST=1 ;;
    *) exit 1 ;;
  esac
done

PROJECT='juicebox-infra'
BUCKET='9c39e3ca5fca69f058b9e673aef193b10d9e8c48' # sha1("ci-builds\n")

GIT="git-$(git describe --always --dirty)"
TIMESTAMP="$(date -u '+%Y%m%d%H%M%SZ')"
GSPATH="$BUCKET/$TIMESTAMP/$GIT/$MODE"

if ! command -v gcloud > /dev/null; then
  echo "ERROR: Cannot find 'gcloud'. See https://cloud.google.com/sdk/docs/install"
  exit 1
fi

echo "Building version $GIT in $MODE mode"
if [ "$ENTRUST" -eq "1" ]; then
  scripts/build-entrust-for-remote.sh "$REMOTE_HOST"
else
  cargo build "--$MODE"
fi

echo 'Uploading artifacts to Google Cloud Storage'
gcloud storage cp \
  "target/$MODE/cluster" \
  "target/$MODE/cluster_bench" \
  "target/$MODE/cluster_manager" \
  "target/$MODE/load_balancer" \
  "target/$MODE/software_agent" \
  "gs://$GSPATH/"

if [ "$ENTRUST" -eq "1" ]; then
  gcloud storage cp \
    "target/$MODE/entrust_agent" \
    "target/$MODE/entrust_init" \
    "target/$MODE/entrust_ops" \
    "target/powerpc-unknown-linux-gnu/$MODE/entrust_hsm.sar" \
    "target/powerpc-unknown-linux-gnu/$MODE/userdata.sar" \
    "gs://$GSPATH/"
fi

echo 'Upload done:'
echo "https://console.cloud.google.com/storage/browser/$GSPATH?project=$PROJECT"
