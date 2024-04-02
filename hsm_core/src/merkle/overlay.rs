extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::hash::{HashExt, HashMap, HashSet};
use hsm_api::merkle::{HashOutput, Node, NodeKey, StoreDelta};

// TreeOverlay keeps track of recent changes and can be used to get an up to date
// view of the tree for a recent ReadProof.
pub struct TreeOverlay<HO> {
    pub latest_root: HO,
    pub roots: HashSet<HO>,
    pub nodes: HashMap<HO, Node<HO>>,
    changes: VecDeque<DeltaCleanup<HO>>,
}
impl<HO: HashOutput> TreeOverlay<HO> {
    // Create a new TreeOverlay given the Tree's latest root hash.
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

    pub fn add_delta(&mut self, root: HO, d: &StoreDelta<HO>) {
        // We apply the delta to nodes, and keep track of what was added.
        // When a delta is expired its used to remove entries
        // from nodes.
        let mut c = DeltaCleanup {
            root,
            to_remove: Vec::with_capacity(d.adds().len()),
        };
        for (k, n) in d.adds() {
            c.to_remove.push(k.clone());
            self.nodes.insert(k.hash, n.clone());
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
                self.nodes.remove(&n.hash);
            }
            self.roots.remove(&d.root);
        };
    }
}

struct DeltaCleanup<HO> {
    root: HO,
    to_remove: Vec<NodeKey<HO>>,
}
