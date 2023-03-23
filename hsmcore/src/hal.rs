use core::ops::Sub;
use serde::{Deserialize, Serialize};

pub trait CryptoRng: rand_core::RngCore + rand_core::CryptoRng + Send {}
impl<R> CryptoRng for R where R: rand_core::RngCore + rand_core::CryptoRng + Send {}

// Nanoseconds upto ~4.29 seconds.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialOrd, PartialEq, Serialize)]
pub struct Nanos(pub u32);

impl Nanos {
    pub const ZERO: Nanos = Nanos(0);
    pub const ONE_SECOND: Nanos = Nanos(1_000_000_000);
    pub const MAX: Nanos = Nanos(u32::MAX);
}

// A Monotonic clock that can calculate durations in nanoseconds.
pub trait Clock {
    // You can subtract an Instant from another one to get the duration. Durations longer than
    // can fit in a Nanos should return Nanos::MAX
    type Instant: Sub<Output = Nanos>;

    fn now(&self) -> Option<Self::Instant>;

    fn elapsed(&self, start: Self::Instant) -> Option<Nanos>;
}

// Platform provides an abstraction for the integration to different HSM models.
pub trait Platform: Clock + CryptoRng {}

impl<R> Platform for R where R: Clock + CryptoRng {}
