#![cfg_attr(not(test), no_std)]

pub mod bitvec;
pub mod hsm;
pub mod marshalling;
pub mod merkle;
pub mod types;

pub trait CryptoRng: rand_core::RngCore + rand_core::CryptoRng + Send {}
impl<R> CryptoRng for R where R: rand_core::RngCore + rand_core::CryptoRng + Send {}
