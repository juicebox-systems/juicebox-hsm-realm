use actix::prelude::*;
use subtle::ConstantTimeEq;

use std::fmt::{self, Debug};

pub type OprfCipherSuite = voprf::Ristretto255;
pub type OprfBlindedInput = voprf::BlindedElement<OprfCipherSuite>;
pub type OprfBlindedResult = voprf::EvaluationElement<OprfCipherSuite>;

#[derive(Clone)]
pub struct AuthToken {
    pub user: String,
    pub signature: String,
}

impl Debug for AuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(auth token for {:?})", self.user)
    }
}

#[derive(Clone)]
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

#[derive(Clone, Debug)]
pub struct Policy {
    pub num_guesses: u16,
}

impl Default for Policy {
    fn default() -> Self {
        Self { num_guesses: 3 }
    }
}

#[derive(Clone)]
pub struct MaskedPgkShare(pub Vec<u8>);

impl Debug for MaskedPgkShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

#[derive(Clone)]
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

#[derive(Debug, Message)]
#[rtype(result = "Register1Response")]
pub struct Register1Request {
    pub auth_token: AuthToken,
    pub blinded_pin: OprfBlindedInput,
}

#[derive(Debug, MessageResponse)]
pub enum Register1Response {
    Ok { blinded_oprf_pin: OprfBlindedResult },
    InvalidAuth,
    AlreadyRegistered,
}

#[derive(Debug, Message)]
#[rtype(result = "Register2Response")]
pub struct Register2Request {
    pub auth_token: AuthToken,
    pub masked_pgk_share: MaskedPgkShare,
    pub password: UnlockPassword,
    pub secret_share: UserSecretShare,
    pub policy: Policy,
}

#[derive(Debug, MessageResponse)]
pub enum Register2Response {
    Ok,
    InvalidAuth,
    NotRegistering,
    AlreadyRegistered,
}

#[derive(Debug, Message)]
#[rtype(result = "Recover1Response")]
pub struct Recover1Request {
    pub auth_token: AuthToken,
    pub blinded_pin: OprfBlindedInput,
}

#[derive(Debug, MessageResponse)]
pub enum Recover1Response {
    Ok {
        blinded_oprf_pin: OprfBlindedResult,
        masked_pgk_share: MaskedPgkShare,
    },
    InvalidAuth,
    NotRegistered,
    NoGuesses,
}

#[derive(Debug, Message)]
#[rtype(result = "Recover2Response")]
pub struct Recover2Request {
    pub auth_token: AuthToken,
    pub password: UnlockPassword,
}

#[derive(Debug, MessageResponse)]
pub enum Recover2Response {
    Ok(UserSecretShare),
    InvalidAuth,
    NotRegistered,
    BadUnlockPassword,
}

#[derive(Debug, Message)]
#[rtype(result = "DeleteResponse")]
pub struct DeleteRequest {
    pub auth_token: AuthToken,
}

#[derive(Debug, MessageResponse)]
pub enum DeleteResponse {
    Ok,
    InvalidAuth,
}
