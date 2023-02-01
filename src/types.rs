//! Data types shared between the client and server.

use actix::prelude::*;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use std::fmt::{self, Debug, Display};

pub type OprfCipherSuite = voprf::Ristretto255;
pub type OprfBlindedInput = voprf::BlindedElement<OprfCipherSuite>;
pub type OprfBlindedResult = voprf::EvaluationElement<OprfCipherSuite>;

/// Represents the authority to act as a particular user.
#[derive(Clone, Deserialize, Serialize)]
pub struct AuthToken {
    pub user: String,
    pub signature: String,
}

impl Debug for AuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(auth token for {:?})", self.user)
    }
}

/// A share of the user's secret.
///
/// The client needs a threshold number of such shares to recover the user's
/// secret.
#[derive(Clone, Serialize, Deserialize)]
pub struct UserSecretShare(pub Vec<u8>);

impl From<Vec<u8>> for UserSecretShare {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Debug for UserSecretShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

/// Defines restrictions on how a secret may be accessed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    /// The number of guesses allowed before the secret can no longer be
    /// accessed.
    ///
    /// This should be set to a small number greater than 0. Lower numbers have
    /// a smaller risk that an adversary could guess the PIN to unlock the
    /// secret, but they have a larger risk that the user will get accidentally
    /// locked out due to typos and transient errors.
    pub num_guesses: u16,
}

/// A share of the password-generating key that has been XORed with
/// `OPRF(PIN)`.
///
/// The client sends this to a realm during registration and gets it back from
/// the realm during recovery.
///
/// The client needs the correct PIN and a threshold number of such shares and
/// OPRF results to recover the password-generating key.
#[derive(Clone, Serialize, Deserialize)]
pub struct MaskedPgkShare(pub Vec<u8>);

impl Debug for MaskedPgkShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

/// A pseudo-random value that the client assigns to a realm when registering a
/// share of the user's secret and must provide to the realm during recovery to
/// get back the share.
#[derive(Clone, Serialize, Deserialize)]
pub struct UnlockPassword(pub Vec<u8>);

impl Debug for UnlockPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

impl ConstantTimeEq for UnlockPassword {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Identifies a version of a PIN-protected secret record.
///
/// Every time the user registers a new PIN-protected secret, that will have a
/// larger generation number than any before it.
///
/// # Note
///
/// Generation numbers are an implementation detail. They are exposed publicly
/// for the purpose of error messages only.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct GenerationNumber(pub u64);

impl Display for GenerationNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

/// Request message for the first phase of registration.
#[derive(Clone, Debug, Deserialize, Message, Serialize)]
#[rtype(result = "Register1Response")]
pub struct Register1Request {
    pub auth_token: AuthToken,
    pub generation: GenerationNumber,
    pub blinded_pin: OprfBlindedInput,
}

/// Response message for the first phase of registration.
#[derive(Debug, Deserialize, MessageResponse, Serialize)]
pub enum Register1Response {
    Ok { blinded_oprf_pin: OprfBlindedResult },
    InvalidAuth,
    BadGeneration { first_available: GenerationNumber },
}

/// Request message for the second phase of registration.
#[derive(Clone, Debug, Deserialize, Message, Serialize)]
#[rtype(result = "Register2Response")]
pub struct Register2Request {
    pub auth_token: AuthToken,
    pub generation: GenerationNumber,
    pub masked_pgk_share: MaskedPgkShare,
    pub password: UnlockPassword,
    pub secret_share: UserSecretShare,
    pub policy: Policy,
}

/// Response message for the second phase of registration.
#[derive(Debug, Deserialize, MessageResponse, Serialize)]
pub enum Register2Response {
    Ok { found_earlier_generations: bool },
    InvalidAuth,
    NotRegistering,
    AlreadyRegistered,
}

/// Request message for the first phase of recovery.
#[derive(Clone, Debug, Deserialize, Message, Serialize)]
#[rtype(result = "Recover1Response")]
pub struct Recover1Request {
    pub auth_token: AuthToken,
    /// Which generation to recover. If the generation number is not provided, the
    /// server will start recovery with the latest generation.
    pub generation: Option<GenerationNumber>,
    pub blinded_pin: OprfBlindedInput,
}

/// Response message for the first phase of recovery.
#[derive(Debug, Deserialize, MessageResponse, Serialize)]
pub enum Recover1Response {
    Ok {
        generation: GenerationNumber,
        blinded_oprf_pin: OprfBlindedResult,
        masked_pgk_share: MaskedPgkShare,
        /// The largest-numbered generation record on the server that's older
        /// than `generation`, if any. This allows the client to discover older
        /// generations to clean up or try recovering.
        previous_generation: Option<GenerationNumber>,
    },
    InvalidAuth,
    NotRegistered {
        generation: Option<GenerationNumber>,
        previous_generation: Option<GenerationNumber>,
    },
    PartiallyRegistered {
        generation: GenerationNumber,
        previous_generation: Option<GenerationNumber>,
    },
    NoGuesses {
        generation: GenerationNumber,
        previous_generation: Option<GenerationNumber>,
    },
}

/// Request message for the second phase of recovery.
#[derive(Clone, Debug, Deserialize, Message, Serialize)]
#[rtype(result = "Recover2Response")]
pub struct Recover2Request {
    pub auth_token: AuthToken,
    pub generation: GenerationNumber,
    pub password: UnlockPassword,
}

/// Response message for the second phase of recovery.
#[derive(Debug, Deserialize, MessageResponse, Serialize)]
pub enum Recover2Response {
    Ok(UserSecretShare),
    InvalidAuth,
    NotRegistered,
    BadUnlockPassword,
}

/// Request message to delete registered secrets.
#[derive(Clone, Debug, Deserialize, Message, Serialize)]
#[rtype(result = "DeleteResponse")]
pub struct DeleteRequest {
    pub auth_token: AuthToken,
    /// If `Some`, the server deletes generations from 0 up to and excluding
    /// this number. If `None`, the server deletes all generations.
    pub up_to: Option<GenerationNumber>,
}

/// Response message to delete registered secrets.
#[derive(Debug, Deserialize, MessageResponse, Serialize)]
pub enum DeleteResponse {
    Ok,
    InvalidAuth,
}
