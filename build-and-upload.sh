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
  --package cluster-cli \
  --package load_balancer \
  --package loam-mvp \
  --package software_agent \
  --bin cluster \
  --bin cluster_manager \
  --bin demo \
  --bin load_balancer \
  --bin software_agent

echo 'Uploading artifacts to Google Cloud Storage'
gcloud storage cp \
  "target/$MODE/cluster" \
  "target/$MODE/cluster_manager" \
  "target/$MODE/demo" \
  "target/$MODE/load_balancer" \
  "target/$MODE/software_agent" \
  "gs://$GSPATH/"

echo 'Upload done:'
echo "https://console.cloud.google.com/storage/browser/$GSPATH?project=$PROJECT"
