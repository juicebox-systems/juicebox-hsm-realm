use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use super::super::hsm::types::RecordId;
use super::{Dir, HashOutput, InteriorNode, KeySlice, KeyVec, LeafNode, OwnedRange, ReadProof};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Node<HO> {
    Interior(InteriorNode<HO>),
    Leaf(LeafNode<HO>),
}
impl<HO: HashOutput> Node<HO> {
    pub fn hash(&self) -> HO {
        match self {
            Node::Interior(int) => int.hash,
            Node::Leaf(leaf) => leaf.hash,
        }
    }
}

#[derive(Debug)]
pub enum TreeStoreError {
    MissingNode,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[non_exhaustive]
pub struct StoreDelta<HO: HashOutput> {
    pub add: Vec<Node<HO>>,
    pub remove: HashSet<HO>,
}
impl<HO: HashOutput> StoreDelta<HO> {
    pub fn items(self) -> (Vec<Node<HO>>, HashSet<HO>) {
        (self.add, self.remove)
    }
}

pub struct DeltaBuilder<HO> {
    to_add: Vec<Node<HO>>,
    to_remove: HashSet<HO>,
}
impl<HO: HashOutput> DeltaBuilder<HO> {
    pub fn new() -> Self {
        DeltaBuilder {
            to_add: Vec::new(),
            to_remove: HashSet::new(),
        }
    }
    pub fn add(&mut self, n: Node<HO>) {
        self.to_add.push(n);
    }
    pub fn remove(&mut self, hash: HO) {
        self.to_remove.insert(hash);
    }
    pub fn build(mut self) -> StoreDelta<HO> {
        for n in &self.to_add {
            self.to_remove.remove(&n.hash());
        }
        StoreDelta {
            add: self.to_add,
            remove: self.to_remove,
        }
    }
}

pub trait TreeStoreReader<HO> {
    fn fetch(&self, k: &HO) -> Result<Node<HO>, TreeStoreError>;
}

pub fn read<R: TreeStoreReader<HO>, HO: HashOutput>(
    store: &R,
    range: &OwnedRange,
    root_hash: &HO,
    k: &RecordId,
) -> Result<ReadProof<HO>, TreeStoreError> {
    let root = match store.fetch(root_hash)? {
        Node::Interior(int) => int,
        Node::Leaf(_) => panic!("found unexpected leaf node"),
    };
    let mut res = ReadProof::new(k.clone(), range.clone(), root);
    let mut key = KeySlice::from_slice(&k.0);
    loop {
        let n = res.path.last().unwrap();
        let d = Dir::from(key[0]);
        match n.branch(d) {
            None => return Ok(res),
            Some(b) => {
                if !key.starts_with(&b.prefix) {
                    return Ok(res);
                }
                key = &key[b.prefix.len()..];
                match store.fetch(&b.hash)? {
                    Node::Interior(int) => {
                        res.path.push(int);
                        continue;
                    }
                    Node::Leaf(v) => {
                        assert!(key.is_empty());
                        res.leaf = Some(v);
                        return Ok(res);
                    }
                }
            }
        }
    }
}

// Reads down the tree from the root always following one side until a leaf is reached.
// Needed for merge.
pub fn read_tree_side<R: TreeStoreReader<HO>, HO: HashOutput>(
    store: &R,
    range: &OwnedRange,
    root_hash: &HO,
    side: Dir,
) -> Result<ReadProof<HO>, TreeStoreError> {
    let mut path = Vec::new();
    let mut key = KeyVec::with_capacity(RecordId::num_bits());
    let mut current = *root_hash;
    loop {
        match store.fetch(&current)? {
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
                    key: keyvec_to_rec_id(key),
                    range: range.clone(),
                    leaf: Some(l),
                    path,
                });
            }
        }
    }
}

fn keyvec_to_rec_id(k: KeyVec) -> RecordId {
    assert!(k.len() == RecordId::num_bits());
    let b = k.into_vec();
    let mut r = RecordId([0; 32]);
    r.0.copy_from_slice(&b);
    r
}
