use super::{Dir, HashOutput, InteriorNode, KeySlice, LeafNode, ReadProof};

#[derive(Debug, Clone)]
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
    NoSuchRecord,
}

#[derive(Debug)]
pub struct StoreDelta<HO: HashOutput> {
    pub root: HO,
    pub add: Vec<Node<HO>>,
    pub remove: Vec<HO>,
}

pub trait TreeStoreReader<HO> {
    fn fetch(&self, k: &[u8]) -> Result<Node<HO>, TreeStoreError>;
}

pub fn read<R: TreeStoreReader<HO>, HO: HashOutput>(
    store: &R,
    root_hash: &HO,
    k: &[u8],
    prefix_size: usize,
) -> Result<ReadProof<HO>, TreeStoreError> {
    let root = match store.fetch(root_hash.as_u8())? {
        Node::Interior(int) => int,
        Node::Leaf(_) => panic!("found unexpected leaf node"),
    };
    let mut res = ReadProof::new(k, prefix_size, root);
    let mut key = KeySlice::from_slice(k);
    key = &key[prefix_size..];
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
