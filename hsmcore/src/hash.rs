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

extern crate alloc;

use alloc::sync::Arc;
use core::hash::BuildHasher;
use core::ops::DerefMut;
use spin::once::Once;
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
/// use hsmcore::hash::{HashExt, HashMap, NotRandomized};
/// // This map doesn't need mitigation from HashDoS attacks because ___.
/// // It's best to avoid randomization here because ___.
/// let map: HashMap<String, String, NotRandomized> = HashMap::new();
/// ```
#[derive(Clone, Debug, Default)]
pub struct NotRandomized;

impl BuildHasher for NotRandomized {
    type Hasher = ahash::AHasher;

    fn build_hasher(&self) -> Self::Hasher {
        let state = ahash::RandomState::with_seeds(1, 2, 3, 4);
        state.build_hasher()
    }
}

/// Randomized state for a hash table that mitigates HashDoS attacks.
///
/// This is the safe "default" way to use a hash table.
///
/// This is typically created implicitly [`Default::default()`]. Its values
/// come from a random number generator that has been globally registered; see
/// [`set_global_rng_shared()`] and [`set_global_rng_owned()`]. If the RNG
/// hasn't been registered, using [`Default`] will panic.
///
/// # Example
///
/// ```
/// use hsmcore::hash::{HashExt, HashMap, set_global_rng_owned};
/// set_global_rng_owned(rand_core::OsRng);
/// // The third generic parameter defaults to RandomState.
/// let map: HashMap<String, String> = HashMap::new();
/// ```
#[derive(Clone, Debug)]
pub struct RandomState(ahash::RandomState);

impl RandomState {
    pub fn new(mut rng: impl CryptoRng) -> Self {
        Self(ahash::RandomState::with_seeds(
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
            rng.next_u64(),
        ))
    }
}

impl BuildHasher for RandomState {
    type Hasher = ahash::AHasher;

    fn build_hasher(&self) -> Self::Hasher {
        self.0.build_hasher()
    }
}

impl Default for RandomState {
    fn default() -> Self {
        match GLOBAL_RNG.get() {
            Some(mutex) => {
                let mut locked = mutex.lock();
                Self::new(locked.deref_mut())
            }
            None => {
                #[cfg(not(test))]
                panic!("need global RNG for hash state");
                #[cfg(test)]
                Self::new(rand_core::OsRng)
            }
        }
    }
}

static GLOBAL_RNG: Once<Arc<Mutex<dyn CryptoRng>>> = Once::new();

/// Registers the process-global random number generator used with
/// [`RandomState`] for randomized hashing of hash tables. This version takes a
/// reference to an RNG that can be shared for other purposes.
///
/// The global RNG will be registered by the time this function returns. It's
/// safe to call this more than once. However, if this is called more than once
/// or concurrently, which RNG is registered is unspecified.
pub fn set_global_rng_shared(rng: Arc<Mutex<dyn CryptoRng>>) {
    GLOBAL_RNG.call_once(|| rng);
}

/// See [`set_global_rng_shared`] except this version takes ownership of the
/// provided RNG.
pub fn set_global_rng_owned(rng: impl CryptoRng + 'static) {
    GLOBAL_RNG.call_once(|| Arc::new(Mutex::new(rng)));
}
