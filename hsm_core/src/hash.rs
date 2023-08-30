//! Helpers for more secure hash table usage.
//!
//! The HSM code is `no_std` to run in embedded environments. As such, it
//! cannot use `std::collections::HashMap`. The std hash table is implemented
//! using the hashbrown crate, and this uses hashbrown directly.
//!
//! The std hash table are randomized to prevent HashDoS attacks. Hashbrown
//! offers some options around randomization, and this module provides some
//! convenience around using hashbrown safely.
//!
//! [`RandomState`] is randomized, typically from a random number generator
//! that has been globally registered. This is the safe "default" way to use a
//! hash table. If the RNG hasn't been registered, using this will panic.
//!
//! [`NotRandomized`] does not mitigate HashDoS attacks, but it requires the
//! user to be explicit in a way that is visible and grep-able in the code.
//!
//! ## Hash Function
//!
//! The hash function used is Blake2 (specifically [`Blake2sMac256`] for
//! randomized hash tables and [`Blake2s256`] for non-randomized hash tables).
//! The std hash tables currently use SipHash-1-3, but the SIP implementation
//! is not officially maintained as a separate library. We chose Blake2 because
//! this project already uses and trusts that dependency. It's a conservative
//! choice which may impact performance.

extern crate alloc;

use blake2::{Blake2s256, Blake2sMac256};
use core::hash::BuildHasher;
use digest::{Digest, FixedOutput, KeyInit};
use spin::Mutex;

use super::hal::CryptoRng;

pub type HashMap<K, V, S = RandomState> = hashbrown::HashMap<K, V, S>;

pub type HashSet<K, S = RandomState> = hashbrown::HashSet<K, S>;

/// An "extension" trait for conveniently creating [`HashMap`] and [`HashSet`]
/// instances with a default hasher.
pub trait HashExt {
    fn new() -> Self;
    fn with_capacity(capacity: usize) -> Self;
}

impl<K, V, S: Default> HashExt for HashMap<K, V, S> {
    fn new() -> Self {
        Self::with_hasher(S::default())
    }

    fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_and_hasher(capacity, S::default())
    }
}

impl<K, S: Default> HashExt for HashSet<K, S> {
    fn new() -> Self {
        Self::with_hasher(S::default())
    }

    fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_and_hasher(capacity, S::default())
    }
}

/// An explicit marker for hash tables that do not mitigate HashDoS attacks.
///
/// The intent is to require the user to be explicit in a way that is visible
/// and grep-able in the code. You should include a comment when you're using
/// this explaining both why it's necessary and why it's safe.
///
/// # Example
///
/// ```
/// use hsm_core::hash::{HashExt, HashMap, NotRandomized};
/// // This map doesn't need mitigation from HashDoS attacks because ___.
/// // It's best to avoid randomization here because ___.
/// let map: HashMap<String, String, NotRandomized> = HashMap::new();
/// ```
#[derive(Clone, Debug, Default)]
pub struct NotRandomized;

impl BuildHasher for NotRandomized {
    type Hasher = Hasher<Blake2s256>;

    fn build_hasher(&self) -> Self::Hasher {
        Hasher(<Blake2s256 as Digest>::new())
    }
}

/// Randomized state for a hash table that mitigates HashDoS attacks.
///
/// This is the safe "default" way to use a hash table.
///
/// This is typically created implicitly [`Default::default()`]. Its values
/// come from a random number generator that has been globally registered; see
/// [`set_global_rng()`]. If the RNG hasn't been registered, using [`Default`]
/// will panic.
///
/// # Example
///
/// ```
/// use hsm_core::hash::{HashExt, HashMap, set_global_rng};
/// set_global_rng(Box::new(rand_core::OsRng));
/// // The third generic parameter defaults to RandomState.
/// let map: HashMap<String, String> = HashMap::new();
/// ```
#[derive(Clone, Debug)]
pub struct RandomState(Blake2sMac256);

impl RandomState {
    pub fn new(mut rng: impl CryptoRng) -> Self {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        Self(<Blake2sMac256 as KeyInit>::new(&key.into()))
    }
}

impl BuildHasher for RandomState {
    type Hasher = Hasher<Blake2sMac256>;

    fn build_hasher(&self) -> Self::Hasher {
        Hasher(self.0.clone())
    }
}

/// A [`core::hash::Hasher`] implemented with the digest (rust-crypto) traits.
///
/// This allows cryptographic hash functions to be used for hash maps.
pub struct Hasher<D: Clone + FixedOutput>(D);

impl<D: Clone + FixedOutput> core::hash::Hasher for Hasher<D> {
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes)
    }

    fn finish(&self) -> u64 {
        let output = self.0.clone().finalize_fixed();
        u64::from_be_bytes(<[u8; 8]>::try_from(&output[..8]).unwrap())
    }
}

impl Default for RandomState {
    fn default() -> Self {
        let mut locked = GLOBAL_RNG.lock();
        match locked.as_deref_mut() {
            Some(rng) => Self::new(rng),
            None => {
                #[cfg(not(test))]
                panic!("need global RNG for hash state");
                #[cfg(test)]
                Self::new(rand_core::OsRng)
            }
        }
    }
}

static GLOBAL_RNG: Mutex<Option<Box<dyn CryptoRng>>> = Mutex::new(None);

/// Registers a process-global random number generator used with
/// [`RandomState`] for randomized hashing of hash tables. This takes ownership
/// of the provided RNG.
///
/// The global RNG will be registered by the time this function returns. It's
/// safe to call this more than once. However, if this is called more than once
/// or concurrently, which RNG is registered is unspecified.
pub fn set_global_rng(rng: Box<dyn CryptoRng>) {
    *GLOBAL_RNG.lock() = Some(rng);
}

#[cfg(test)]
mod tests {
    use super::{HashExt, HashMap, HashSet, NotRandomized, RandomState};
    use core::hash::{BuildHasher, Hasher};

    #[test]
    fn test_hash_map_randomized() {
        // We don't need to register the global RNG here because tests default
        // to using OsRng.
        let mut map = HashMap::<u8, &'static str>::new();
        map.insert(1, "one");
        map.insert(2, "two");
        assert_eq!(Some(&"one"), map.get(&1));
        assert_eq!(Some(&"two"), map.get(&2));
        assert_eq!(None, map.get(&3));
    }

    #[test]
    fn test_hash_map_not_randomized() {
        let mut map = HashMap::<u8, &'static str, NotRandomized>::new();
        map.insert(1, "one");
        map.insert(2, "two");
        assert_eq!(Some(&"one"), map.get(&1));
        assert_eq!(Some(&"two"), map.get(&2));
        assert_eq!(None, map.get(&3));
    }

    #[test]
    fn test_hash_set_randomized() {
        // We don't need to register the global RNG here because tests default
        // to using OsRng.
        let mut set = HashSet::<u8>::new();
        set.insert(1);
        set.insert(2);
        assert!(set.contains(&1));
        assert!(set.contains(&2));
        assert!(!set.contains(&3));
    }

    #[test]
    fn test_hash_set_not_randomized() {
        let mut set = HashSet::<u8>::new();
        set.insert(1);
        set.insert(2);
        assert!(set.contains(&1));
        assert!(set.contains(&2));
        assert!(!set.contains(&3));
    }

    #[test]
    fn test_random_state() {
        // We don't need to register the global RNG here because tests default
        // to using OsRng.
        let build_hasher1 = RandomState::default();
        let mut hasher1 = build_hasher1.build_hasher();
        hasher1.write_u8(42);
        hasher1.write_u8(11);

        let mut hasher2 = build_hasher1.build_hasher();
        hasher2.write_u8(42);
        hasher2.write_u8(11);
        assert_eq!(hasher1.finish(), hasher2.finish());

        let build_hasher2 = RandomState::default();
        let mut hasher3 = build_hasher2.build_hasher();
        hasher3.write_u8(42);
        hasher3.write_u8(11);
        assert_ne!(hasher1.finish(), hasher3.finish());
    }

    #[test]
    fn test_not_randomized() {
        let mut hasher1 = NotRandomized.build_hasher();
        assert_eq!(7575470396830417044, hasher1.finish());
        hasher1.write_u8(42);
        assert_eq!(5509661675087876720, hasher1.finish());
        hasher1.write_u8(11);
        assert_eq!(16522658520095206419, hasher1.finish());

        let mut hasher2 = NotRandomized.build_hasher();
        hasher2.write_u8(42);
        hasher2.write_u8(11);
        assert_eq!(16522658520095206419, hasher2.finish());
    }
}
