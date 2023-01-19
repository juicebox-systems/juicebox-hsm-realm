use std::collections::{HashMap, HashSet, VecDeque};

use super::{agent::Node, Delta, Dir, HashOutput, KeySlice, ReadProof};
use std::hash::Hash;

pub struct TreeOverlay<HO> {
    nodes: HashMap<HO, Node<HO>>,
    changes: VecDeque<DeltaCleanup<HO>>,
    roots: HashSet<HO>,
    latest_root: HO,
}
impl<HO: HashOutput + Hash> TreeOverlay<HO> {
    //
    pub fn new(latest_root: HO, max_deltas: u16) -> Self {
        let mut o = TreeOverlay {
            nodes: HashMap::new(),
            changes: VecDeque::with_capacity(max_deltas as usize),
            roots: HashSet::with_capacity(max_deltas as usize),
            latest_root,
        };
        o.roots.insert(latest_root);
        o
    }
    pub fn add_delta(&mut self, d: &Delta<HO>) {
        // We apply the delta to nodes, and keep track of what was added.
        // When a delta is expired its used to remove entries
        // from nodes.
        if self.changes.len() == self.changes.capacity() - 1 {
            self.expire_delta();
        }
        let mut c = DeltaCleanup {
            root: *d.root(),
            to_remove: Vec::with_capacity(d.add.len() + 1),
        };
        c.to_remove.push(d.leaf.hash);
        self.nodes.insert(d.leaf.hash, Node::Leaf(d.leaf.clone()));
        for n in &d.add {
            c.to_remove.push(n.hash);
            self.nodes.insert(n.hash, Node::Interior(n.clone()));
        }
        self.roots.insert(c.root);
        self.latest_root = c.root;
        self.changes.push_back(c);
    }

    pub fn expire_delta(&mut self) {
        let d = self
            .changes
            .pop_front()
            .expect("should only be called when deltas is full");
        for n in d.to_remove {
            self.nodes.remove(&n);
        }
        self.roots.remove(&d.root);
    }

    pub fn read(&self, p: &ReadProof<HO>) -> Option<ReadProof<HO>> {
        if !self.roots.contains(&p.path[0].hash) {
            return None;
        }
        let root = match self.get_node(&self.latest_root, p) {
            None => return None,
            Some(Node::Interior(int)) => int,
            Some(Node::Leaf(_)) => panic!("found unexpected leaf node"),
        };
        let mut res = ReadProof::new(&p.key, root);
        let mut key = KeySlice::from_slice(&p.key);
        loop {
            let n = res.path.back().unwrap();
            let d = Dir::from(key[0]);
            match n.branch(d) {
                None => return Some(res),
                Some(b) => {
                    if !key.starts_with(&b.prefix) {
                        return Some(res);
                    }
                    key = &key[b.prefix.len()..];
                    match self.get_node(&b.hash, p) {
                        None => return None,
                        Some(Node::Interior(int)) => {
                            res.path.push_back(int);
                            continue;
                        }
                        Some(Node::Leaf(v)) => {
                            assert!(key.is_empty());
                            res.leaf = Some(v);
                            return Some(res);
                        }
                    }
                }
            }
        }
    }

    // Looks for a node with the supplied hash. It checks the overlay
    // first, and if not there, will look in the supplied proof.
    fn get_node(&self, hash: &HO, p: &ReadProof<HO>) -> Option<Node<HO>> {
        match self.nodes.get(hash) {
            Some(n) => match n {
                Node::Interior(int) => Some(Node::Interior(int.clone())),
                Node::Leaf(l) => Some(Node::Leaf(l.clone())),
            },
            None => {
                // Nodes near the leaf are most likely to not be in the overlay and
                // need finding from the proof.
                // TODO: do we want to dump the proof into a hashmap first (that we
                // reuse for the tree read)
                if let Some(l) = &p.leaf {
                    if &l.hash == hash {
                        return Some(Node::Leaf(l.clone()));
                    }
                }
                // path is in leaf->root order.
                for int in &p.path {
                    if &int.hash == hash {
                        return Some(Node::Interior(int.clone()));
                    }
                }
                None
            }
        }
    }
}

// DeltaCleanup contains information we need about a specific Delta that was applied
// so that we clean up when its expired.
struct DeltaCleanup<HO> {
    root: HO,
    to_remove: Vec<HO>,
}
