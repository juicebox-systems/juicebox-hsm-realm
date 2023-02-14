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
    pub fn encoded_key(&self) -> Vec<u8> {
        encode_prefix_and_hash(self.prefix.clone(), self.hash)
    }
}

fn encode_prefix_and_hash<HO: HashOutput>(prefix: KeyVec, hash: HO) -> Vec<u8> {
    // encoded key consists of
    //   the prefix length in bits encoded into 2 bytes.
    //   the prefix encoded into bytes
    //   the hash
    let prefix_len_bytes = len_of_encoded_prefix(&prefix);
    let len = prefix_len_bytes + hash.as_u8().len();
    let mut out: Vec<u8> = Vec::with_capacity(len);
    encode_prefix_into(prefix, &mut out);
    out.extend(hash.as_u8());
    out
}

// Returns the number of bytes that the encoded version of this prefix will require.
fn len_of_encoded_prefix(prefix: &KeySlice) -> usize {
    let len = (prefix.len() / 8) + 2;
    if prefix.len() % 8 != 0 {
        len + 1
    } else {
        len
    }
}
// Encode the prefix into the supplied buffer.
fn encode_prefix_into(mut prefix: KeyVec, dest: &mut Vec<u8>) {
    let num_prefix_bits = prefix.len() as u16;
    dest.extend(&num_prefix_bits.to_be_bytes());
    prefix.set_uninitialized(false);
    let v = prefix.into_vec();
    dest.extend(&v);
}

// Generates the encoded version of each prefix for this recordId. starts at
// prefix[..0] and end with at prefix[..recordId::num_bits()]
pub fn encode_prefixes(k: &RecordId) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(RecordId::num_bits() + 1);
    let key = KeySlice::from_slice(&k.0);
    let clear_masks: [u8; 7] = [
        0b10000000, 0b11000000, 0b11100000, 0b11110000, 0b11111000, 0b11111100, 0b11111110,
    ];
    for i in 0..=RecordId::num_bits() {
        let len_bytes = len_of_encoded_prefix(&key[..i]);
        let mut enc = Vec::with_capacity(len_bytes);
        // prefix len
        let num_prefix_bits = i as u16;
        enc.extend(num_prefix_bits.to_be_bytes());
        // whole bytes are easy
        let num_wb = i / 8;
        enc.extend(&k.0[..num_wb]);
        // deal with clearing trailing bits of the last byte that are not part of the prefix
        let bits_last_byte = i % 8;
        if bits_last_byte > 0 {
            enc.push(k.0[num_wb] & clear_masks[bits_last_byte - 1]);
        }
        out.push(enc);
    }
    out
}

pub trait TreeStoreReader<HO: HashOutput> {
    fn fetch(&self, key: &[u8]) -> Result<Vec<Node<HO>>, TreeStoreError>;

    fn find(&self, prefix: &KeySlice, hash: HO) -> Result<Node<HO>, TreeStoreError> {
        let k = encode_prefix_and_hash(prefix.to_bitvec(), hash);
        self.fetch(&k)?
            .into_iter()
            .find(|n| n.hash() == hash)
            .ok_or(TreeStoreError::MissingNode)
    }
}

pub fn read<R: TreeStoreReader<HO>, HO: HashOutput>(
    store: &R,
    range: &OwnedRange,
    root_hash: &HO,
    k: &RecordId,
) -> Result<ReadProof<HO>, TreeStoreError> {
    let prefixes = encode_prefixes(k);
    let find = |prefix_len: usize, hash: HO| {
        let k = &prefixes[prefix_len];
        store
            .fetch(k)?
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
        match store.find(&key, current)? {
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
    use super::{encode_prefix_into, encode_prefixes, NodeKey};
    use bitvec::bitvec;
    use bitvec::prelude::Msb0;

    #[test]
    fn store_key_encoding() {
        let k = NodeKey::new(KeyVec::new(), TestHash([1u8; 8]));
        assert_eq!([0u8, 0, 1, 1, 1, 1, 1, 1, 1, 1].to_vec(), k.encoded_key());

        let k = NodeKey::new(bitvec![u8,Msb0; 0], TestHash([1u8; 8]));
        assert_eq!(
            [0u8, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1].to_vec(),
            k.encoded_key()
        );
        let k = NodeKey::new(bitvec![u8,Msb0; 1], TestHash([4u8; 8]));
        assert_eq!(
            [0u8, 1, 128, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            k.encoded_key()
        );

        let k = NodeKey::new(bitvec![u8,Msb0; 0,1], TestHash([4u8; 8]));
        assert_eq!(
            [0u8, 2, 64, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            k.encoded_key()
        );

        let k = NodeKey::new(bitvec![u8,Msb0; 1,1,1,1,1,1,1,1], TestHash([4u8; 8]));
        assert_eq!(
            [0u8, 8, 255, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            k.encoded_key()
        );
        let k = NodeKey::new(bitvec![u8,Msb0; 1,1,1,1,1,1,1,1,1], TestHash([4u8; 8]));
        assert_eq!(
            [0u8, 9, 255, 128, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            k.encoded_key()
        );
    }

    #[test]
    fn bulk_prefix_encoding() {
        // cross check the bulk & single encoders
        let test = |r| {
            let prefixes = encode_prefixes(&r);
            assert_eq!(257, prefixes.len());
            let k = KeySlice::from_slice(&r.0);
            let mut buff = Vec::with_capacity(64);
            for (i, prefix) in prefixes.iter().enumerate() {
                buff.clear();
                encode_prefix_into(k[..i].to_bitvec(), &mut buff);
                assert_eq!(&buff, prefix, "with prefix len {i}");
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
