#!/bin/sh

set -eu

cluster() {
    echo
    echo cluster "$@"
    target/debug/cluster \
        --bigtable-project loam-dev-env \
        --bigtable-instance dev-bigtable \
        "$@"
}

cargo build -p cluster-cli

cluster auth-token test-7368 user1

cluster agents
out=$(cluster new-realm \
        'http://127.0.0.1:10001' \
        'http://127.0.0.1:10002' \
        'http://127.0.0.1:10003')
echo "$out"
REALM=$(echo "$out" | grep 'Created realm' | awk '{ print $3 }')
GROUP1=$(echo "$out" | grep 'Created realm' | awk '{ print $7 }')

cluster configuration https://example.org

out=$(cluster new-group \
        --realm "$REALM" \
        'http://127.0.0.1:10004' \
        'http://127.0.0.1:10005' \
        'http://127.0.0.1:10006')
echo "$out"
GROUP2=$(echo "$out" | grep 'Created group' | awk '{ print $3 }')

cluster transfer \
    --realm $REALM \
    --source $GROUP1 \
    --destination $GROUP2 \
    --start 0000000000000000000000000000000000000000000000000000000000000000 \
    --end 7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

cluster agents
cluster groups

cluster experimental assimilate

cluster agents
cluster groups
