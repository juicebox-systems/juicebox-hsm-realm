use core::time::Duration;

pub trait CryptoRng: rand_core::RngCore + rand_core::CryptoRng + Send {}
impl<R> CryptoRng for R where R: rand_core::RngCore + rand_core::CryptoRng + Send {}

// A Monotonic clock that can calculate durations.
pub trait Clock {
    type Instant;

    fn now(&self) -> Option<Self::Instant>;
    fn elapsed(&self, start: Self::Instant) -> Option<Duration>;
}
