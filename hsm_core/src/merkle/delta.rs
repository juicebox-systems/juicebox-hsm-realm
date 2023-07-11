extern crate alloc;

#[cfg(test)]
pub mod tests {

    use crate::merkle::testing::{new_empty_tree, TestHash};
    use bitvec::bitvec;
    use hsm_api::merkle::{DeltaBuilder, KeyVec, LeafNode, Node, NodeKey, StoreDelta};
    use hsm_api::{OwnedRange, RecordId};

    #[test]
    fn test_squash_deltas() {
        let range = OwnedRange::full();
        let (mut tree, init_root, mut store) = new_empty_tree(&range);
        let mut deltas = Vec::new();

        // insert some keys, collect the deltas
        let mut root = init_root;
        let mut d: StoreDelta<TestHash>;
        for key in (1..6).map(|i| RecordId([i; RecordId::NUM_BYTES])) {
            let rp = store.read(&range, &init_root, &key).unwrap();
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
        assert!(squashed.adds().len() < deltas.iter().map(|d| d.adds().len()).sum());
        assert!(squashed.removes().len() < deltas.iter().map(|d| d.removes().len()).sum());
        squashed_store.apply_store_delta(root, squashed);

        for d in deltas.into_iter() {
            store.apply_store_delta(root, d);
        }
        assert_eq!(store, squashed_store);
    }

    #[test]
    fn squash_remove() {
        // when squashing deltas, the result for a remove could be that its a new node so it
        // can be just deleted from the delta, or its not anything currently in the delta and
        // should be preseved as a delete.
        let mut b = DeltaBuilder::new();
        let n = Node::Leaf(LeafNode {
            value: vec![1, 2, 3, 4],
        });
        let k = NodeKey::new(bitvec![1, 1, 1, 1], TestHash([42; 8]));
        b.add(k.clone(), n);
        let delta = b.build();
        assert!(!delta.is_empty());
        assert!(delta.removes().is_empty());

        let mut b = DeltaBuilder::new();
        b.remove(k);
        let delta2 = b.build();
        assert!(!delta2.is_empty());
        assert!(!delta2.removes().is_empty());
        assert!(delta2.adds().is_empty());
        let mut base = delta.clone();
        base.squash(delta2);
        // 2nd delta removes the node the first delta added.
        assert!(base.is_empty());

        let mut b = DeltaBuilder::new();
        let k2 = NodeKey::new(bitvec![1], TestHash([41; 8]));
        b.remove(k2.clone());
        let delta3 = b.build();
        let mut base = delta;
        base.squash(delta3);
        // 2nd delta removes a node not in the first delta, should be
        // kept as a remove
        assert!(!base.is_empty());
        assert_eq!(base.removes().iter().cloned().collect::<Vec<_>>(), vec![k2]);
    }

    #[test]
    fn empty() {
        assert!(StoreDelta::<TestHash>::default().is_empty());
        let mut b = DeltaBuilder::new();
        b.remove(NodeKey::new(KeyVec::new(), TestHash([42; 8])));
        assert!(!b.build().is_empty());
    }
}
