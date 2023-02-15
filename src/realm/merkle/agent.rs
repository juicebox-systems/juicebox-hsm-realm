use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashSet;

use super::super::hsm::types::RecordId;
use super::{
    base128, Dir, HashOutput, InteriorNode, KeySlice, KeyVec, LeafNode, OwnedRange, ReadProof,
};

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
    pub add: Vec<(NodeKey<HO>, Node<HO>)>,
    pub remove: HashSet<NodeKey<HO>>,
}

pub struct DeltaBuilder<HO> {
    to_add: Vec<(NodeKey<HO>, Node<HO>)>,
    to_remove: HashSet<NodeKey<HO>>,
}
impl<HO: HashOutput> DeltaBuilder<HO> {
    pub fn new() -> Self {
        DeltaBuilder {
            to_add: Vec::new(),
            to_remove: HashSet::new(),
        }
    }
    pub fn add(&mut self, key: NodeKey<HO>, n: Node<HO>) {
        self.to_add.push((key, n));
    }
    pub fn remove(&mut self, key: NodeKey<HO>) {
        self.to_remove.insert(key);
    }
    pub fn build(mut self) -> StoreDelta<HO> {
        for n in &self.to_add {
            self.to_remove.remove(&n.0);
        }
        StoreDelta {
            add: self.to_add,
            remove: self.to_remove,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct NodeKey<HO> {
    // The full key prefix to the node
    pub prefix: KeyVec,
    pub hash: HO,
}
impl<HO: HashOutput> NodeKey<HO> {
    pub fn new(prefix: KeyVec, hash: HO) -> Self {
        Self { prefix, hash }
    }
    // Returns a lexicographically ordered encoding of this prefix & hash
    // that leads with prefix.
    pub fn store_key(&self) -> StoreKey {
        StoreKey::new(self.prefix.clone(), self.hash)
    }
}

// The key value for a row in the key value store. Nodes are stored in the Store
// using these keys. See NodeKey for a way to get one of these.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StoreKey(Vec<u8>);
impl StoreKey {
    pub fn new<HO: HashOutput>(prefix: KeyVec, hash: HO) -> StoreKey {
        // encoded key consists of
        //   the prefix base128 encoded
        //   a delimiter which has Msb set and the lower 4 bits indicate the
        //   number of bits used in the last byte of the prefix (this is part of
        //   the base128 encoding)
        //   the hash
        let prefix_len_bytes = base128::encoded_len(prefix.len());
        let mut out: Vec<u8> = Vec::with_capacity(prefix_len_bytes + hash.as_u8().len());
        encode_prefix_into(prefix, &mut out);
        out.extend(hash.as_u8());
        StoreKey(out)
    }
    pub fn starts_with(&self, s: &StoreKeyStart) -> bool {
        self.0.starts_with(&s.0)
    }
    pub fn cmp_start(&self, o: &StoreKeyStart) -> Ordering {
        self.0.cmp(&o.0)
    }
}
// The beginning part of a StoreKey
pub struct StoreKeyStart(Vec<u8>);

// Encode the prefix and delimiter into the supplied buffer.
fn encode_prefix_into(mut prefix: KeyVec, dest: &mut Vec<u8>) {
    prefix.set_uninitialized(false);
    let prefix_bits_len = prefix.len();
    let v = prefix.into_vec();
    base128::encode(&v, prefix_bits_len, dest);
}

// Generates the encoded version of each prefix for this recordId. starts at
// prefix[..0] and end with at prefix[..recordId::num_bits()]
pub fn all_store_key_starts(k: &RecordId) -> Vec<StoreKeyStart> {
    let mut out = Vec::with_capacity(RecordId::num_bits() + 1);
    for i in 0..=RecordId::num_bits() {
        let mut enc = Vec::new();
        base128::encode(&k.0, i, &mut enc);
        out.push(StoreKeyStart(enc));
    }
    out
}

pub trait TreeStoreReader<HO: HashOutput> {
    fn range(&self, key: &StoreKeyStart) -> Result<Vec<Node<HO>>, TreeStoreError>;

    fn fetch(&self, prefix: KeyVec, hash: HO) -> Result<Node<HO>, TreeStoreError>;
}

pub fn read<R: TreeStoreReader<HO>, HO: HashOutput>(
    store: &R,
    range: &OwnedRange,
    root_hash: &HO,
    k: &RecordId,
) -> Result<ReadProof<HO>, TreeStoreError> {
    let prefixes = all_store_key_starts(k);
    let find = |prefix_len: usize, hash: HO| {
        let k = &prefixes[prefix_len];
        store
            .range(k)?
            .into_iter()
            .find(|n| n.hash() == hash)
            .ok_or(TreeStoreError::MissingNode)
    };
    let root = match find(0, *root_hash)? {
        Node::Interior(int) => int,
        Node::Leaf(_) => panic!("found unexpected leaf node"),
    };
    let mut res = ReadProof::new(k.clone(), range.clone(), root);
    let mut prefix_len = 0;
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
                prefix_len += b.prefix.len();
                match find(prefix_len, b.hash)? {
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
        match store.fetch(key.clone(), current)? {
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

#[cfg(test)]
mod tests {
    use super::super::super::hsm::types::RecordId;
    use super::super::tests::TestHash;
    use super::super::{KeySlice, KeyVec};
    use super::{all_store_key_starts, encode_prefix_into, NodeKey};
    use bitvec::bitvec;
    use bitvec::prelude::Msb0;

    #[test]
    fn store_key_encoding() {
        let k = NodeKey::new(KeyVec::new(), TestHash([1u8; 8]));
        assert_eq!([128u8, 1, 1, 1, 1, 1, 1, 1, 1].to_vec(), k.store_key().0);

        let k = NodeKey::new(bitvec![u8,Msb0; 0], TestHash([1u8; 8]));
        assert_eq!([0u8, 129, 1, 1, 1, 1, 1, 1, 1, 1].to_vec(), k.store_key().0);
        let k = NodeKey::new(bitvec![u8,Msb0; 1], TestHash([4u8; 8]));
        assert_eq!(
            [64u8, 129, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            k.store_key().0
        );

        let k = NodeKey::new(bitvec![u8,Msb0; 0,1], TestHash([4u8; 8]));
        assert_eq!(
            [32u8, 130, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            k.store_key().0
        );

        let k = NodeKey::new(bitvec![u8,Msb0; 1,1,1,1,1,1,1], TestHash([4u8; 8]));
        assert_eq!(
            [127u8, 135, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            k.store_key().0
        );
        let k = NodeKey::new(bitvec![u8,Msb0; 1,1,1,1,1,1,1,1], TestHash([4u8; 8]));
        assert_eq!(
            [127u8, 64, 129, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            k.store_key().0
        );
        let k = NodeKey::new(bitvec![u8,Msb0; 1,1,1,1,1,1,1,1,1], TestHash([4u8; 8]));
        assert_eq!(
            [127u8, 96, 130, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            k.store_key().0
        );
    }

    #[test]
    fn bulk_prefix_encoding() {
        // cross check the bulk & single encoders
        let test = |r| {
            let prefixes = all_store_key_starts(&r);
            assert_eq!(257, prefixes.len());
            let k = KeySlice::from_slice(&r.0);
            let mut buff = Vec::with_capacity(64);
            for (i, prefix) in prefixes.iter().enumerate() {
                buff.clear();
                encode_prefix_into(k[..i].to_bitvec(), &mut buff);
                assert_eq!(buff, prefix.0, "with prefix len {i}");
            }
        };
        test(RecordId([0x00; 32]));
        test(RecordId([0x01; 32]));
        test(RecordId([0x5a; 32]));
        test(RecordId([0xa5; 32]));
        test(RecordId([0x7F; 32]));
        test(RecordId([0x80; 32]));
        test(RecordId([0xFE; 32]));
        test(RecordId([0xFF; 32]));
    }
}
