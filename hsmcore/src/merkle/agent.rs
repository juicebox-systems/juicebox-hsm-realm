extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use super::super::hsm::types::RecordId;
use super::Bits;
use super::{base128, HashOutput, InteriorNode, KeyVec, LeafNode};
use crate::hash::{HashExt, HashMap, HashSet, NotRandomized};

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
    ///
    /// This map doesn't need mitigation from HashDoS attacks because it's
    /// produced by the HSMs from Merkle tree modifications. The agents trust
    /// the HSMs. Plus, the node hashes do not depend on user input, since a
    /// random nonce is rolled up into them.
    ///
    /// It's best to avoid randomization here for performance. This and the
    /// `remove` set are created when processing every tree update.
    pub add: HashMap<NodeKey<HO>, Node<HO>, NotRandomized>,
    /// Existing nodes to be removed.
    pub remove: HashSet<NodeKey<HO>, NotRandomized>,
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
    to_add: HashMap<NodeKey<HO>, Node<HO>, NotRandomized>,
    to_remove: HashSet<NodeKey<HO>, NotRandomized>,
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
        let mut out: Vec<u8> = Vec::with_capacity(prefix_len_bytes + hash.as_slice().len());
        encode_prefix_into(prefix, &mut out);
        out.extend(hash.as_slice());
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

    use crate::merkle::testing::{new_empty_tree, read, TestHash};

    use super::super::super::bitvec;
    use super::super::super::hsm::types::{OwnedRange, RecordId};
    use super::super::tests::TEST_REALM;
    use super::super::{agent::StoreDelta, KeyVec};
    use super::Bits;
    use super::{all_store_key_starts, encode_prefix_into, NodeKey, StoreKey};

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
