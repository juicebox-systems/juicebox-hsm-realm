#!/bin/sh

set -eu

PROJECT='loam-dev-env'
BUCKET='a6cca386fe978990258c511c46fa8123a5f2e3b2' # sha1("daily-builds\n")
MODE='release' # always 'release'

GIT="git-$(git describe --always --dirty)"
TIMESTAMP="$(date -u '+%Y%m%d%H%M%SZ')"
GSPATH="$BUCKET/$TIMESTAMP/$GIT/$MODE"
REMOTE_HOST="$1"

if ! command -v gcloud > /dev/null; then
  echo "ERROR: Cannot find 'gcloud'. See https://cloud.google.com/sdk/docs/install"
  exit 1
fi

echo "Building version $GIT"
scripts/build-entrust-for-remote.sh $REMOTE_HOST

echo 'Uploading artifacts to Google Cloud Storage'
gcloud storage cp \
  "target/release/cluster" \
  "target/release/cluster_bench" \
  "target/release/cluster_manager" \
  "target/release/load_balancer" \
  "target/release/software_agent" \
  "target/release/entrust_agent" \
  "target/release/entrust_init" \
  "target/powerpc-unknown-linux-gnu/release/*.sar" \
  "gs://$GSPATH/"

echo 'Upload done:'
echo "https://console.cloud.google.com/storage/browser/$GSPATH?project=$PROJECT"
