extern crate alloc;

use alloc::collections::BTreeMap;
use core::hash::Hash;
use hashbrown::HashMap; // TODO: randomize hasher

/// A logical timestamp generated from a counter.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Timestamp(u64);

/// A simple LRU cache.
///
/// It's `O(log(N))` but not particularly efficient.
pub struct Cache<K, V> {
    map: HashMap<K, (Timestamp, V)>,
    lru: BTreeMap<Timestamp, K>,
    now: Timestamp,
    limit: usize,
}

impl<K, V> Cache<K, V>
where
    K: Clone + Eq + Hash,
{
    pub fn new(limit: usize) -> Self {
        assert!(limit > 0);
        Self {
            map: HashMap::new(),
            lru: BTreeMap::new(),
            now: Timestamp(0),
            limit,
        }
    }

    fn check_invariants(&self) {
        assert_eq!(self.map.len(), self.lru.len());
        for (k, (mtime, _)) in &self.map {
            assert!(self.lru.get(mtime) == Some(k));
        }
        assert!(self.map.len() <= self.limit);
    }

    pub fn insert(&mut self, k: K, v: V) {
        // This might add a new entry or it might overwrite an existing entry.
        // If the cache is already at its size limit, which path affects
        // whether another entry should be evicted. It's simplest to cheat and
        // go over `self.limit` temporarily, then evict afterwards if needed.
        self.now = Timestamp(self.now.0.checked_add(1).unwrap());
        match self.map.insert(k.clone(), (self.now, v)) {
            Some((prev_mtime, _)) => {
                // replaced an entry
                self.lru.remove(&prev_mtime);
            }
            None => {
                // added an entry
                if self.map.len() > self.limit {
                    if let Some((_, oldest)) = self.lru.pop_first() {
                        self.map.remove(&oldest);
                    }
                }
            }
        }
        self.lru.insert(self.now, k);
        if cfg!(debug_assert) {
            self.check_invariants();
        }
    }

    pub fn remove(&mut self, k: &K) -> Option<V> {
        if let Some((mtime, v)) = self.map.remove(k) {
            self.lru.remove(&mtime);
            if cfg!(debug_assert) {
                self.check_invariants();
            }
            Some(v)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Cache;

    #[test]
    fn test_basic() {
        let mut cache: Cache<char, f64> = Cache::new(3);
        cache.insert('4', 4.0);
        cache.insert('1', 1.0);
        cache.insert('3', 3.0);
        cache.insert('3', 3.5);
        cache.insert('2', 2.0);
        cache.insert('2', 2.5);
        assert_eq!(cache.remove(&'4'), None);
        assert_eq!(cache.remove(&'1'), Some(1.0));
        assert_eq!(cache.remove(&'3'), Some(3.5));
        assert_eq!(cache.remove(&'2'), Some(2.5));
        assert_eq!(cache.remove(&'2'), None);
        assert_eq!(cache.map.len(), 0);
    }

    #[test]
    fn test_tiny() {
        let mut cache: Cache<char, f64> = Cache::new(1);
        cache.insert('1', 1.0);
        cache.insert('3', 3.0);
        assert_eq!(cache.remove(&'1'), None);
        assert_eq!(cache.remove(&'3'), Some(3.0));
        assert_eq!(cache.remove(&'3'), None);
        assert_eq!(cache.map.len(), 0);
    }
}
