extern crate alloc;

#[cfg(test)]
pub mod tests {

    use crate::merkle::testing::{new_empty_tree, TestHash};
    use hsm_api::merkle::StoreDelta;
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
}
