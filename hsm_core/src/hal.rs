extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::ops::Sub;
use serde::{Deserialize, Serialize};

use hsm_api::rpc::Nanos;

pub trait CryptoRng: rand_core::RngCore + rand_core::CryptoRng + Send {}
impl<R> CryptoRng for R where R: rand_core::RngCore + rand_core::CryptoRng + Send {}

// A Monotonic clock that can calculate durations in nanoseconds.
pub trait Clock {
    // You can subtract an Instant from another one to get the duration. Durations longer than
    // can fit in a Nanos should return Nanos::MAX
    type Instant: Sub<Output = Nanos>;

    fn now(&self) -> Option<Self::Instant>;

    fn elapsed(&self, start: Self::Instant) -> Option<Nanos>;
}

pub const MAX_NVRAM_SIZE: usize = 4000;

#[derive(Debug, Deserialize, Serialize)]
pub struct IOError(pub String);

// Persistent storage of up to 'MAX_NVRAM_SIZE' bytes of data.
pub trait NVRam {
    // Returns the last written data, or an empty Vec if nothing has been written yet.
    fn read(&self) -> Result<Vec<u8>, IOError>;

    // Write 'data' to NVRam. If this is writing to flash this may be depressingly slow.
    // e.g. on the Entrust SoloXC this takes about 1ms. Returns an error if data is larger
    // than MAX_NVRAM_SIZE bytes.
    fn write(&self, data: Vec<u8>) -> Result<(), IOError>;
}

// Platform provides an abstraction for the integration to different HSM models.
pub trait Platform: Clock + CryptoRng + NVRam + Clone {}

impl<R> Platform for R where R: Clock + CryptoRng + NVRam + Clone {}
