use actix::prelude::*;

use std::fmt::{self, Debug};

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

#[derive(Clone, PartialEq, Eq)]
pub struct Pin(pub String);

impl Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

#[derive(Clone)]
pub struct UserSecret(pub String);

impl Debug for UserSecret {
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

#[derive(Debug, Message)]
#[rtype(result = "RegisterResponse")]
pub struct RegisterRequest {
    pub auth_token: AuthToken,
    pub pin: Pin,
    pub secret: UserSecret,
    pub policy: Policy,
}

#[derive(Debug, MessageResponse)]
pub enum RegisterResponse {
    Ok,
    InvalidAuth,
    AlreadyRegistered,
}

#[derive(Debug, Message)]
#[rtype(result = "RecoverResponse")]
pub struct RecoverRequest {
    pub auth_token: AuthToken,
    pub pin: Pin,
}

#[derive(Debug, MessageResponse)]
pub enum RecoverResponse {
    Ok(UserSecret),
    InvalidAuth,
    NotRegistered,
    NoGuesses,
    BadPin,
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
