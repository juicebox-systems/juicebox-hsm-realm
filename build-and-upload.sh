#!/bin/sh

set -eu

PROJECT='loam-dev-env'
BUCKET='a6cca386fe978990258c511c46fa8123a5f2e3b2' # sha1("daily-builds\n")
MODE='release' # 'debug' or 'release'

GIT="git-$(git describe --always --dirty)"
TIMESTAMP="$(date -u '+%Y%m%d%H%M%SZ')"
GSPATH="$BUCKET/$USER/$TIMESTAMP/$GIT/$MODE"

if ! command -v gcloud > /dev/null; then
  echo "ERROR: Cannot find 'gcloud'. See https://cloud.google.com/sdk/docs/install"
  exit 1
fi

echo "Building version $GIT in $MODE mode"
cargo build "--$MODE" \
  --package load_balancer \
  --package loam-mvp \
  --bin agent \
  --bin cluster_manager \
  --bin demo \
  --bin http_hsm \
  --bin load_balancer

echo 'Uploading artifacts to Google Cloud Storage'
gcloud storage cp \
  "target/$MODE/agent" \
  "target/$MODE/cluster_manager" \
  "target/$MODE/demo" \
  "target/$MODE/http_hsm" \
  "target/$MODE/load_balancer" \
  "gs://$GSPATH/"

echo 'Upload done:'
echo "https://console.cloud.google.com/storage/browser/$GSPATH?project=$PROJECT"
