use std::collections::{HashMap, HashSet, VecDeque};

use super::{agent::Node, Delta, HashOutput, SplitResult};

// TreeOverlay keeps track of recent changes and can be used to get an upto date
// view of the tree for a recent ReadProof.
pub struct TreeOverlay<HO> {
    pub latest_root: HO,
    pub roots: HashSet<HO>,
    pub nodes: HashMap<HO, Node<HO>>,
    changes: VecDeque<DeltaCleanup<HO>>,
}
impl<HO: HashOutput> TreeOverlay<HO> {
    // Create a new TreeOverlay given the Tree's latest root hash. For
    // most effient memory usage max_deltas should be a power of 2 -1. e.g. 15.
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
        self.add_cleanup(c);
    }

    fn add_cleanup(&mut self, dc: DeltaCleanup<HO>) {
        if self.changes.len() == self.changes.capacity() - 1 {
            self.expire_oldest_delta();
        }
        self.changes.push_back(dc);
    }

    pub fn expire_oldest_delta(&mut self) {
        if let Some(d) = self.changes.pop_front() {
            for n in d.to_remove {
                self.nodes.remove(&n);
            }
            self.roots.remove(&d.root);
        };
    }

    // Captures that the tree was split and half of it given away.
    // We reset all our state to start at this new root so that
    // we can ensure that subsequent operations are based on the split
    // view of the tree.
    pub fn tree_has_split(&mut self, s: &SplitResult<HO>) {
        self.roots.clear();
        self.nodes.clear();
        self.changes.clear();
        self.roots.insert(s.keeping.root_hash);
        self.latest_root = s.keeping.root_hash;
        if let Some(k) = &s.keeping.add {
            self.add_cleanup(DeltaCleanup {
                root: s.keeping.root_hash,
                to_remove: vec![k.hash],
            });
            self.nodes.insert(k.hash, Node::Interior(k.clone()));
        }
    }
}

struct DeltaCleanup<HO> {
    root: HO,
    to_remove: Vec<HO>,
}
