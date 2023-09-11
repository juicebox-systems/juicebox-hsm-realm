//! Entrust specific types dealing with initialization and startup of the hsmcore implementation.

#![no_std]

extern crate alloc;

use alloc::format;
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

// SEEJob response buffers contain a trailing byte indicating the type of the
// payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SEEJobResponseType {
    // The response is the serialized result of executing the job.
    JobResult,
    // The response is the serialized result of executing the job. + 4 additional
    // bytes containing a big endian encoded u32 indicating the number of
    // nanoseconds that were spent waiting for the next job.
    JobResultWithIdleTime,
    // The response is a panic message in UTF8.
    PanicMessage,
    // THe response is a marshalling error message in UTF8.
    MarshallingError,
}

impl SEEJobResponseType {
    pub fn as_byte(&self) -> u8 {
        match self {
            SEEJobResponseType::JobResult => 1,
            SEEJobResponseType::JobResultWithIdleTime => 2,
            SEEJobResponseType::PanicMessage => 3,
            SEEJobResponseType::MarshallingError => 4,
        }
    }
    pub fn from_byte(b: u8) -> Result<Self, String> {
        match b {
            1 => Ok(SEEJobResponseType::JobResult),
            2 => Ok(Self::JobResultWithIdleTime),
            3 => Ok(SEEJobResponseType::PanicMessage),
            4 => Ok(SEEJobResponseType::MarshallingError),
            _ => Err(format!("Invalid SEEJobResponseType value of {b}")),
        }
    }
}
