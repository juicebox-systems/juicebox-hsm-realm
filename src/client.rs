use actix::prelude::*;

use super::types::{
    AuthToken, DeleteRequest, DeleteResponse, Pin, Policy, RecoverRequest, RecoverResponse,
    RegisterRequest, RegisterResponse, UserSecret,
};
use super::Server;

#[derive(Debug, Clone)]
pub struct Realm {
    pub address: Addr<Server>,
    pub public_key: String,
}

#[derive(Debug)]
pub struct Client {
    configuration: Realm,
    auth_token: AuthToken,
}

#[derive(Debug)]
pub enum RegisterError {
    NetworkError(actix::MailboxError),
    InvalidAuth,
    AlreadyRegistered,
}

#[derive(Debug)]
pub enum RecoverError {
    NetworkError(actix::MailboxError),
    InvalidAuth,
    NotRegistered,
    NoGuesses,
    BadPin,
}

#[derive(Debug)]
pub enum DeleteError {
    NetworkError(actix::MailboxError),
    InvalidAuth,
}

impl Client {
    pub fn new(mut configuration: Vec<Realm>, auth_token: AuthToken) -> Self {
        Self {
            // this client only uses the first realm for now
            configuration: configuration
                .pop()
                .expect("Client needs at least one realm"),
            auth_token,
        }
    }

    pub async fn register(
        &self,
        pin: &Pin,
        secret: &UserSecret,
        policy: Policy,
    ) -> Result<(), RegisterError> {
        match self
            .configuration
            .address
            .send(RegisterRequest {
                auth_token: self.auth_token.clone(),
                pin: pin.clone(),
                secret: secret.clone(),
                policy,
            })
            .await
        {
            Err(err) => Err(RegisterError::NetworkError(err)),
            Ok(response) => match response {
                RegisterResponse::Ok => Ok(()),
                RegisterResponse::InvalidAuth => Err(RegisterError::InvalidAuth),
                RegisterResponse::AlreadyRegistered => Err(RegisterError::AlreadyRegistered),
            },
        }
    }

    pub async fn recover(&self, pin: &Pin) -> Result<UserSecret, RecoverError> {
        match self
            .configuration
            .address
            .send(RecoverRequest {
                auth_token: self.auth_token.clone(),
                pin: pin.clone(),
            })
            .await
        {
            Err(err) => Err(RecoverError::NetworkError(err)),
            Ok(response) => match response {
                RecoverResponse::Ok(secret) => Ok(secret),
                RecoverResponse::InvalidAuth => Err(RecoverError::InvalidAuth),
                RecoverResponse::NotRegistered => Err(RecoverError::NotRegistered),
                RecoverResponse::NoGuesses => Err(RecoverError::NoGuesses),
                RecoverResponse::BadPin => Err(RecoverError::BadPin),
            },
        }
    }

    pub async fn delete_all(&self) -> Result<(), DeleteError> {
        match self
            .configuration
            .address
            .send(DeleteRequest {
                auth_token: self.auth_token.clone(),
            })
            .await
        {
            Err(err) => Err(DeleteError::NetworkError(err)),
            Ok(response) => match response {
                DeleteResponse::Ok => Ok(()),
                DeleteResponse::InvalidAuth => Err(DeleteError::InvalidAuth),
            },
        }
    }
}
