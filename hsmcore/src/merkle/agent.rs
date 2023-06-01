extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::{HashMap, HashSet}; // TODO: randomize hasher
use serde::{Deserialize, Serialize};

use super::super::hsm::types::RecordId;
use super::Bits;
use super::{base128, HashOutput, InteriorNode, KeyVec, LeafNode};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Node<HO> {
    Interior(InteriorNode<HO>),
    Leaf(LeafNode),
}

#[derive(Debug)]
pub enum TreeStoreError {
    MissingNode,
    Network(String),
}

/// A collection of changes to be made to a Merkle tree.
///
/// Correct values of this struct have no overlap between nodes that are added
/// and nodes that are removed.
#[derive(Clone, Debug, Deserialize, Serialize)]
// TODO: `non_exhaustive` doesn't prevent others in the same crate from
// constructing these, which I think was the intent.
#[non_exhaustive]
pub struct StoreDelta<HO: HashOutput> {
    /// New nodes to be added.
    pub add: HashMap<NodeKey<HO>, Node<HO>>,
    /// Existing nodes to be removed.
    pub remove: HashSet<NodeKey<HO>>,
}

impl<HO: HashOutput> Default for StoreDelta<HO> {
    fn default() -> Self {
        Self {
            add: HashMap::new(),
            remove: HashSet::new(),
        }
    }
}

impl<HO: HashOutput> StoreDelta<HO> {
    /// Updates self with the changes described in other. Nodes that are added
    /// and then deleted by a subsequent squash are removed entirely. Squashing
    /// a number of StoreDelta's and then writing the result to storage is the
    /// same as applying the individual deltas to storage.
    pub fn squash(&mut self, other: StoreDelta<HO>) {
        self.add.extend(other.add);
        for k in other.remove {
            if self.add.remove(&k).is_none() {
                self.remove.insert(k);
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.remove.is_empty()
    }
}

#[derive(Default)]
pub struct DeltaBuilder<HO> {
    to_add: HashMap<NodeKey<HO>, Node<HO>>,
    to_remove: HashSet<NodeKey<HO>>,
}
impl<HO: HashOutput> DeltaBuilder<HO> {
    pub fn new() -> Self {
        DeltaBuilder {
            to_add: HashMap::new(),
            to_remove: HashSet::new(),
        }
    }
    pub fn add(&mut self, key: NodeKey<HO>, n: Node<HO>) {
        self.to_add.insert(key, n);
    }
    pub fn remove(&mut self, key: NodeKey<HO>) {
        self.to_remove.insert(key);
    }
    pub fn build(mut self) -> StoreDelta<HO> {
        for (k, _) in &self.to_add {
            self.to_remove.remove(k);
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
        StoreKey::new(&self.prefix, &self.hash)
    }
}

// The key value for a row in the key value store. Nodes are stored in the Store
// using these keys. See NodeKey for a way to get one of these.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StoreKey(Vec<u8>);

impl StoreKey {
    pub fn new<HO: HashOutput>(prefix: &KeyVec, hash: &HO) -> StoreKey {
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

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
    pub fn parse<HO: HashOutput>(bytes: &[u8]) -> Option<(EncodedRecordPrefix, HO)> {
        match bytes.iter().position(|b| b & 128 != 0) {
            None => None,
            Some(p) => {
                let ep = EncodedRecordPrefix(&bytes[..=p]);
                HO::from_slice(&bytes[p + 1..]).map(|h| (ep, h))
            }
        }
    }
}

impl From<Vec<u8>> for StoreKey {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

pub struct EncodedRecordPrefix<'a>(&'a [u8]);
// When/If we have a need to decode this back to the prefix, we can write the base128 decoder.

// The beginning part of a StoreKey
#[derive(Clone)]
pub struct StoreKeyStart(Vec<u8>);
impl StoreKeyStart {
    pub fn next(&self) -> Self {
        let mut c = self.0.clone();
        for i in (0..c.len()).rev() {
            if c[i] < 255 {
                c[i] += 1;
                return StoreKeyStart(c);
            } else {
                c[i] = 0;
            }
        }
        // The encoding of the recordId prefix means that its impossible to have
        // a StoreKeyStart value that leads with 0xFF, and so this is unreachable.
        // The base128 encoding of the prefix leaves the MSB clear. For the empty
        // prefix the encoding will have the single byte of the terminator, which'll
        // have the value 128.
        unreachable!()
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

// Encode the prefix and delimiter into the supplied buffer.
fn encode_prefix_into(prefix: &KeyVec, dest: &mut Vec<u8>) {
    base128::encode(prefix.as_bytes(), prefix.len(), dest);
}

// Generates the encoded version of each prefix for this recordId. starts at
// prefix[..0] and end with at prefix[..=RecordId::NUM_BITS]
pub fn all_store_key_starts(
    k: &RecordId,
) -> impl Iterator<Item = StoreKeyStart> + ExactSizeIterator + '_ {
    // `ExactSizeIterator` is not implemented for `RangeInclusive<usize>`, so
    // awkwardly cast back and forth.
    let range = 0..=u16::try_from(RecordId::NUM_BITS).unwrap();
    range.map(|i| {
        let mut enc = Vec::new();
        base128::encode(&k.0, usize::from(i), &mut enc);
        StoreKeyStart(enc)
    })
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;

    use super::super::super::{
        bitvec,
        hsm::types::{OwnedRange, RecordId},
    };
    use super::super::tests::{new_empty_tree, TestHash, TEST_REALM};
    use super::super::{agent::StoreDelta, Dir, HashOutput, KeyVec, ReadProof};
    use super::Bits;
    use super::{
        all_store_key_starts, encode_prefix_into, Node, NodeKey, StoreKey, TreeStoreError,
    };
    use async_trait::async_trait;
    use juicebox_sdk_core::types::RealmId;

    #[async_trait]
    pub trait TreeStoreReader<HO: HashOutput>: Sync {
        async fn path_lookup(
            &self,
            realm_id: &RealmId,
            record_id: &RecordId,
        ) -> Result<HashMap<HO, Node<HO>>, TreeStoreError>;

        async fn read_node(
            &self,
            realm_id: &RealmId,
            key: StoreKey,
        ) -> Result<Node<HO>, TreeStoreError>;
    }

    pub async fn read<R: TreeStoreReader<HO>, HO: HashOutput>(
        realm_id: &RealmId,
        store: &R,
        range: &OwnedRange,
        root_hash: &HO,
        k: &RecordId,
    ) -> Result<ReadProof<HO>, TreeStoreError> {
        let mut nodes = store.path_lookup(realm_id, k).await?;
        let root = match nodes.remove(root_hash) {
            None => return Err(TreeStoreError::MissingNode),
            Some(Node::Leaf(_)) => panic!("found unexpected leaf node"),
            Some(Node::Interior(int)) => int,
        };
        let mut res = ReadProof::new(k.clone(), range.clone(), *root_hash, root);
        let keyv = k.to_bitvec();
        let mut key = keyv.as_ref();
        loop {
            let n = res.path.last().unwrap();
            let d = Dir::from(key[0]);
            match n.branch(d) {
                None => return Ok(res),
                Some(b) => {
                    if !key.starts_with(&b.prefix) {
                        return Ok(res);
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
                            return Ok(res);
                        }
                    }
                }
            }
        }
    }

    // Reads down the tree from the root always following one side until a leaf is reached.
    // Needed for merge.
    pub async fn read_tree_side<R: TreeStoreReader<HO>, HO: HashOutput>(
        realm_id: &RealmId,
        store: &R,
        range: &OwnedRange,
        root_hash: &HO,
        side: Dir,
    ) -> Result<ReadProof<HO>, TreeStoreError> {
        let mut path = Vec::new();
        let mut key = KeyVec::new();
        let mut current = *root_hash;
        loop {
            match store
                .read_node(realm_id, StoreKey::new(&key, &current))
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

    #[test]
    fn store_key_encoding() {
        let k = NodeKey::new(KeyVec::new(), TestHash([1u8; 8]));
        assert_eq!([128u8, 1, 1, 1, 1, 1, 1, 1, 1].to_vec(), k.store_key().0);

        let k = NodeKey::new(bitvec![0], TestHash([1u8; 8]));
        assert_eq!([0u8, 129, 1, 1, 1, 1, 1, 1, 1, 1].to_vec(), k.store_key().0);
        let k = NodeKey::new(bitvec![1], TestHash([4u8; 8]));
        assert_eq!(
            [64u8, 129, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            k.store_key().0
        );

        let k = NodeKey::new(bitvec![0, 1], TestHash([4u8; 8]));
        assert_eq!(
            [32u8, 130, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            k.store_key().0
        );

        let k = NodeKey::new(bitvec![1, 1, 1, 1, 1, 1, 1], TestHash([4u8; 8]));
        assert_eq!(
            [127u8, 135, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            k.store_key().0
        );
        let k = NodeKey::new(bitvec![1, 1, 1, 1, 1, 1, 1, 1], TestHash([4u8; 8]));
        assert_eq!(
            [127u8, 64, 129, 4, 4, 4, 4, 4, 4, 4, 4].to_vec(),
            k.store_key().0
        );
        let k = NodeKey::new(bitvec![1, 1, 1, 1, 1, 1, 1, 1, 1], TestHash([4u8; 8]));
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
            let k = r.to_bitvec();
            let mut buff = Vec::with_capacity(64);
            for (i, prefix) in prefixes.enumerate() {
                buff.clear();
                encode_prefix_into(&k.slice(..i).to_bitvec(), &mut buff);
                assert_eq!(buff, prefix.0, "with prefix len {i}");
            }
        };
        test(RecordId([0x00; RecordId::NUM_BYTES]));
        test(RecordId([0x01; RecordId::NUM_BYTES]));
        test(RecordId([0x5a; RecordId::NUM_BYTES]));
        test(RecordId([0xa5; RecordId::NUM_BYTES]));
        test(RecordId([0x7F; RecordId::NUM_BYTES]));
        test(RecordId([0x80; RecordId::NUM_BYTES]));
        test(RecordId([0xFE; RecordId::NUM_BYTES]));
        test(RecordId([0xFF; RecordId::NUM_BYTES]));
    }

    #[test]
    fn test_store_key_parse() {
        let prefix = bitvec![1, 0, 1];
        let hash = TestHash([1, 2, 3, 4, 5, 6, 7, 8]);
        let sk = StoreKey::new(&prefix, &hash);
        assert_eq!(vec![0b01010000, 128 | 3, 1, 2, 3, 4, 5, 6, 7, 8], sk.0);
        match StoreKey::parse::<TestHash>(&sk.0) {
            None => panic!("should have decoded store key"),
            Some((p, h)) => {
                assert_eq!(h, hash);
                assert_eq!(&[0b01010000, 128 | 3], p.0);
            }
        }
    }

    #[test]
    fn test_store_key_parse_empty_prefix() {
        let prefix = bitvec![];
        let hash = TestHash([1, 2, 3, 4, 5, 6, 7, 8]);
        let sk = StoreKey::new(&prefix, &hash);
        assert_eq!(vec![128, 1, 2, 3, 4, 5, 6, 7, 8], sk.0);
        match StoreKey::parse::<TestHash>(&sk.0) {
            None => panic!("should have decoded store key"),
            Some((p, h)) => {
                assert_eq!(h, hash);
                assert_eq!(&[128], p.0);
            }
        }
    }

    #[test]
    fn test_store_key_parse_bad_input() {
        assert!(StoreKey::parse::<TestHash>(&[0, 0, 128, 1, 2, 3, 4]).is_none());
        assert!(StoreKey::parse::<TestHash>(&[]).is_none());
        assert!(StoreKey::parse::<TestHash>(&[1, 2]).is_none());
        assert!(StoreKey::parse::<TestHash>(&[1, 2, 128 | 1]).is_none());
    }

    #[tokio::test]
    async fn test_squash_deltas() {
        let range = OwnedRange::full();
        let (mut tree, init_root, mut store) = new_empty_tree(&range).await;
        let mut deltas = Vec::new();

        // insert some keys, collect the deltas
        let mut root = init_root;
        let mut d: StoreDelta<TestHash>;
        for key in (1..6).map(|i| RecordId([i; RecordId::NUM_BYTES])) {
            let rp = read(&TEST_REALM, &store, &range, &init_root, &key)
                .await
                .unwrap();
            let vp = tree.latest_proof(rp).unwrap();
            (root, d) = tree.insert(vp, key.0.to_vec()).unwrap();
            deltas.push(d);
        }
        // squashing the deltas and applying it, or applying them individually should result in the same thing
        let mut squashed_store = store.clone();
        let mut squashed = deltas[0].clone();
        for d in &deltas[1..] {
            squashed.squash(d.clone());
        }
        assert!(squashed.add.len() < deltas.iter().map(|d| d.add.len()).sum());
        assert!(squashed.remove.len() < deltas.iter().map(|d| d.remove.len()).sum());
        squashed_store.apply_store_delta(root, squashed);

        for d in deltas.into_iter() {
            store.apply_store_delta(root, d);
        }
        assert_eq!(store, squashed_store);
    }
}
