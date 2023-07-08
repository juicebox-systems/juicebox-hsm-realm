#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::collections::BTreeMap;
use core::fmt::Debug;
use core::hash::{BuildHasher, Hash};
use hashbrown::HashMap;

/// Reports the current time so that the cache can determine relative age.
///
/// HSMs use [`LogicalClock`] below, which is just a counter. Agents use a
/// clock based on `std::time::Instant` so that they can report stats based on
/// elapsed time.
pub trait Clock {
    type Time: Clone + Copy + Debug + Eq + Ord + PartialEq + PartialOrd;
    fn time(&mut self) -> Self::Time;
}

/// Counter-based implementation of [`Clock`].
///
/// This allows for cheaply comparing relative ages of items.
#[derive(Debug, Default)]
pub struct LogicalClock {
    now: u64,
}

impl Clock for LogicalClock {
    type Time = u64;

    fn time(&mut self) -> Self::Time {
        self.now += 1;
        self.now
    }
}

/// Statistics returned by [`Cache::stats`].
#[derive(Debug, Eq, PartialEq)]
pub struct Stats<Time = <LogicalClock as Clock>::Time>
where
    Time: Clone + Copy + Debug + Eq + Ord + PartialEq + PartialOrd,
{
    /// The number of items in the cache.
    pub entries: usize,
    /// The maximum number of items allowed in the cache.
    pub limit: usize,
    /// When the least recently accessed entry, if any, was inserted or
    /// accessed.
    pub lru_time: Option<Time>,
}

/// A simple LRU cache.
///
/// It's `O(log(N))` but not particularly efficient.
pub struct Cache<K, V, C: Clock, H> {
    map: HashMap<K, (C::Time, V), H>,
    lru: BTreeMap<C::Time, K>,
    clock: C,
    limit: usize,
}

impl<K, V, C, H> Cache<K, V, C, H>
where
    K: Clone + Eq + Hash,
    C: Clock,
    H: BuildHasher + Default,
{
    pub fn new(limit: usize) -> Self
    where
        C: Default,
    {
        assert!(limit > 0);
        Self {
            map: HashMap::with_hasher(H::default()),
            lru: BTreeMap::new(),
            clock: C::default(),
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
        let now = self.clock.time();
        match self.map.insert(k.clone(), (now, v)) {
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
        self.lru.insert(now, k);
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

    pub fn get(&mut self, k: &K) -> Option<&V> {
        // Remove and reinsert so that the timestamp gets updated.
        match self.remove(k) {
            Some(v) => {
                self.insert(k.clone(), v);
                let (_, v) = self.map.get(k).unwrap();
                Some(v)
            }
            None => None,
        }
    }

    pub fn stats(&self) -> Stats<C::Time> {
        Stats {
            entries: self.map.len(),
            limit: self.limit,
            lru_time: self.lru.first_key_value().map(|(mtime, _)| *mtime),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::RandomState;

    type FloatCache = Cache<char, f64, LogicalClock, RandomState>;

    #[test]
    fn test_basic() {
        let mut cache = FloatCache::new(3);
        cache.insert('4', 4.0); // t=1
        cache.insert('1', 1.0); // t=2
        cache.insert('3', 3.0); // t=3
        cache.insert('3', 3.5); // t=4
        cache.insert('2', 2.0); // t=5
        cache.insert('2', 2.5); // t=6

        assert_eq!(
            cache.stats(),
            Stats {
                entries: 3,
                limit: 3,
                lru_time: Some(2),
            }
        );

        assert_eq!(cache.remove(&'4'), None);
        assert_eq!(cache.remove(&'1'), Some(1.0));
        assert_eq!(cache.remove(&'3'), Some(3.5));

        assert_eq!(
            cache.stats(),
            Stats {
                entries: 1,
                limit: 3,
                lru_time: Some(6),
            }
        );

        assert_eq!(cache.remove(&'2'), Some(2.5));
        assert_eq!(cache.remove(&'2'), None);
        assert_eq!(cache.map.len(), 0);

        assert_eq!(
            cache.stats(),
            Stats {
                entries: 0,
                limit: 3,
                lru_time: None,
            }
        );
    }

    #[test]
    fn test_tiny() {
        let mut cache = FloatCache::new(1);
        cache.insert('1', 1.0);
        cache.insert('3', 3.0);
        assert_eq!(cache.remove(&'1'), None);
        assert_eq!(cache.remove(&'3'), Some(3.0));
        assert_eq!(cache.remove(&'3'), None);
        assert_eq!(cache.map.len(), 0);
    }

    #[test]
    fn test_get() {
        let mut cache = FloatCache::new(2);
        cache.insert('1', 1.0);
        cache.insert('3', 3.0);
        assert_eq!(cache.get(&'1'), Some(&1.0));
        cache.insert('2', 2.0);
        assert_eq!(cache.get(&'3'), None);
        assert_eq!(cache.get(&'1'), Some(&1.0));
    }
}
