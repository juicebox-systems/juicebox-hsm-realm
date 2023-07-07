use agent_api::merkle::TreeStoreReader;
use bitvec::Bits;
use hsmcore::hsm::types::{OwnedRange, RecordId};
use hsmcore::merkle::agent::{Node, StoreKey, TreeStoreError};
use hsmcore::merkle::proof::ReadProof;
use hsmcore::merkle::{Dir, HashOutput, KeyVec};
use juicebox_sdk_core::types::RealmId;
use observability::metrics;

/// Looks up a path to a record in a Merkle tree and returns its proof.
pub async fn read<R: TreeStoreReader<HO>, HO: HashOutput>(
    realm_id: &RealmId,
    store: &R,
    range: &OwnedRange,
    root_hash: &HO,
    k: &RecordId,
    metrics: &metrics::Client,
    tags: &[metrics::Tag],
) -> Result<ReadProof<HO>, TreeStoreError> {
    let mut nodes = store.path_lookup(realm_id, k, root_hash, tags).await?;
    let root = match nodes.remove(root_hash) {
        None => return Err(TreeStoreError::MissingNode),
        Some(Node::Leaf(_)) => panic!("found unexpected leaf node"),
        Some(Node::Interior(int)) => int,
    };
    let mut res = ReadProof::new(k.clone(), range.clone(), *root_hash, root);
    let full_key = k.to_bitvec();
    let mut key = full_key.as_ref();
    loop {
        let n = res.path.last().unwrap();
        let d = Dir::from(key[0]);
        match n.branch(d) {
            None => break,
            Some(b) => {
                if !key.starts_with(&b.prefix) {
                    break;
                }
                key = key.slice(b.prefix.len()..);
                match nodes.remove(&b.hash) {
                    None => return Err(TreeStoreError::MissingNode),
                    Some(Node::Interior(int)) => {
                        res.path.push(int);
                        continue;
                    }
                    Some(Node::Leaf(v)) => {
                        assert!(key.is_empty());
                        res.leaf = Some(v);
                        break;
                    }
                }
            }
        }
    }

    metrics.histogram("agent.merkle_read.proof_nodes", res.path.len(), tags);
    metrics.histogram("agent.merkle_read.extraneous_nodes", nodes.len(), tags);
    metrics.histogram(
        "agent.merkle_read.has_leaf",
        res.leaf.is_some() as i64,
        tags,
    );

    Ok(res)
}

// Reads down the tree from the root always following one side until a leaf is reached.
// Needed for merge.
pub async fn read_tree_side<R: TreeStoreReader<HO>, HO: HashOutput>(
    realm_id: &RealmId,
    store: &R,
    range: &OwnedRange,
    root_hash: &HO,
    side: Dir,
    tags: &[metrics::Tag],
) -> Result<ReadProof<HO>, TreeStoreError> {
    let mut path = Vec::new();
    let mut key = KeyVec::new();
    let mut current = *root_hash;
    loop {
        match store
            .read_node(realm_id, StoreKey::new(&key, &current), tags)
            .await?
        {
            Node::Interior(int) => match int.branch(side) {
                None => match int.branch(side.opposite()) {
                    None => {
                        path.push(int);
                        let k = if side == Dir::Right {
                            &range.end
                        } else {
                            &range.start
                        };
                        // TODO, should we remove key from ReadProof?
                        // this key is not a full key in this event.
                        // this can only happen for the root node.
                        return Ok(ReadProof {
                            key: k.clone(),
                            range: range.clone(),
                            root_hash: *root_hash,
                            leaf: None,
                            path,
                        });
                    }
                    Some(b) => {
                        current = b.hash;
                        key.extend(&b.prefix);
                        path.push(int);
                        continue;
                    }
                },
                Some(b) => {
                    current = b.hash;
                    key.extend(&b.prefix);
                    path.push(int);
                    continue;
                }
            },

            Node::Leaf(l) => {
                return Ok(ReadProof {
                    key: RecordId::from_bitvec(&key),
                    range: range.clone(),
                    root_hash: *root_hash,
                    leaf: Some(l),
                    path,
                });
            }
        }
    }
}
