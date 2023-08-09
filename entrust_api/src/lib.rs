//! Entrust specific types dealing with initialization and startup of the hsmcore implementation.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use juicebox_marshalling::bytes;
use serde::{Deserialize, Serialize};

/// A Ticket for gaining accessing to a key, as generated by Cmd_GetTicket.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ticket(#[serde(with = "bytes")] pub Vec<u8>);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NvRamState {
    LastWritten,
    Reinitialize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StartRequest {
    pub tree_overlay_size: u16,
    pub max_sessions: u16,
    pub comm_private_key: Ticket,
    pub comm_public_key: Ticket,
    pub mac_key: Ticket,
    pub record_key: Ticket,
    pub nvram: NvRamState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum StartResponse {
    Ok,
    WorldSigner(WorldSignerError),
    InvalidTicket(KeyRole, u32), //M_Status
    InvalidKeyLength {
        role: KeyRole,
        expecting: usize,
        actual: usize,
    },
    PersistenceError(String),
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum KeyRole {
    CommunicationPrivateKey,
    CommunicationPublicKey,
    MacKey,
    RecordKey,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum WorldSignerError {
    FailedToLoad {
        status: u32, // aka M_Status
    },
    /// The SEE Machine failed to find a world signer. Ensure that both the
    /// SEEMachine binary and the userdata file are signed with a `seeinteg`
    /// key.
    NoWorldSigner,
    /// The SEE Machine found 2 or more world signers, there should only be 1.
    /// Ensure that both the SEEMachine binary and the userdata file are signed
    /// with the same `seeinteg` key.
    TooManyWorldSigners,
}

impl From<WorldSignerError> for StartResponse {
    fn from(value: WorldSignerError) -> Self {
        StartResponse::WorldSigner(value)
    }
}
