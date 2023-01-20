use super::{Dir, HashOutput, InteriorNode, KeySlice, LeafNode, ReadProof};

#[derive(Clone)]
pub enum Node<HO> {
    Interior(InteriorNode<HO>),
    Leaf(LeafNode<HO>),
}

#[derive(Debug)]
pub enum TreeStoreError {
    NoSuchRecord,
}

pub trait TreeStoreReader<HO> {
    fn fetch(&self, k: &[u8]) -> Result<Node<HO>, TreeStoreError>;
}

pub fn read<R: TreeStoreReader<HO>, HO: HashOutput>(
    store: &R,
    root_hash: &HO,
    k: &[u8],
) -> Result<ReadProof<HO>, TreeStoreError> {
    let root = match store.fetch(root_hash.as_u8())? {
        Node::Interior(int) => int,
        Node::Leaf(_) => panic!("found unexpected leaf node"),
    };
    let mut res = ReadProof::new(k, root);
    let mut key = KeySlice::from_slice(k);
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
                match store.fetch(b.hash.as_u8())? {
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
