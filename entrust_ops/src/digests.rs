//! Utilities for dealing with cryptographic digests.

use sha2::{Digest, Sha256};
use std::fmt;

use super::Context;
use crate::Error;

/// The output of SHA-256 (from the SHA2 family of cryptographic hash functions).
#[derive(Clone, PartialEq)]
pub struct Sha256Sum([u8; 32]);

impl Sha256Sum {
    pub const DUMMY: Self = Self([
        0xab, 0xad, 0xde, 0xca, 0xfc, 0x0f, 0xfe, 0xe1, //
        0xab, 0xad, 0xde, 0xca, 0xfc, 0x0f, 0xfe, 0xe2, //
        0xab, 0xad, 0xde, 0xca, 0xfc, 0x0f, 0xfe, 0xe3, //
        0xab, 0xad, 0xde, 0xca, 0xfc, 0x0f, 0xfe, 0xe4,
    ]);

    pub fn compute(data: &[u8]) -> Self {
        Self(Sha256::digest(data).into())
    }

    #[allow(unused)]
    pub fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for Sha256Sum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::encode(self.0).fmt(f)
    }
}

impl fmt::Debug for Sha256Sum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::encode(self.0).fmt(f)
    }
}

/// Methods to calculate and check file digests.
///
/// These respect dry runs.
impl Context {
    /// Returns the given path if its contents match the expected hash, or
    /// returns an error otherwise.
    ///
    /// Prints the hash and the BIP-39 mnemonic.
    ///
    /// For dry runs, prints the expected hash and claims success.
    pub(crate) fn check_file_digest<'a>(
        &self,
        file: &'a str,
        expected: &Sha256Sum,
    ) -> Result<&'a str, Error> {
        println!();
        let digest: Sha256Sum = if self.common_args.dry_run {
            println!("Not computing file digest for {file:?} because --dry-run");
            expected.clone()
        } else {
            self.file_digest(file)?
        };

        println!("File {file:?}");
        println!("SHA-256: {digest}");
        if &digest != expected && !self.common_args.dry_run {
            return Err(Error::new(format!(
                "expected SHA-256 {expected} for {file:?}"
            )));
        }
        println!("Matches expected digest");
        println!();
        Ok(file)
    }

    /// Returns the SHA-256 hash of the file at the given path, or returns an
    /// I/O error.
    ///
    /// For dry runs, returns [`Sha256Sum::DUMMY`].
    pub(crate) fn file_digest(&self, file: &str) -> Result<Sha256Sum, Error> {
        if self.common_args.dry_run {
            println!("Not computing file digest for {file:?} because --dry-run");
            Ok(Sha256Sum::DUMMY)
        } else {
            let contents = self.read(file)?;
            Ok(Sha256Sum::compute(&contents))
        }
    }

    /// Prints the path, SHA-256 hash, and BIP-39 mnemonic of the file, or
    /// returns an I/O error.
    ///
    /// For dry runs, prints [`Sha256Sum::DUMMY`].
    pub(crate) fn print_file_digest(&self, file: &str) -> Result<(), Error> {
        let digest = self.file_digest(file)?;
        println!("File {file:?}");
        println!("SHA-256: {digest}");
        println!();
        Ok(())
    }
}
