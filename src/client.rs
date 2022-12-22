use actix::prelude::*;
use digest::Digest;
use futures::future::{join_all, try_join_all};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::fmt::{self, Debug};

mod trivial_sharing;
use trivial_sharing::RecombineError;

use super::types::{
    AuthToken, DeleteRequest, DeleteResponse, MaskedPgkShare, OprfCipherSuite, Policy,
    Recover1Request, Recover1Response, Recover2Request, Recover2Response, Register1Request,
    Register1Response, Register2Request, Register2Response, UnlockPassword, UserSecretShare,
};
use super::Server;

type OprfClient = voprf::OprfClient<OprfCipherSuite>;

fn oprf_output_size() -> usize {
    <OprfCipherSuite as voprf::CipherSuite>::Hash::output_size()
}

#[derive(Debug, Clone)]
pub struct Realm {
    pub address: Addr<Server>,
    pub public_key: Vec<u8>,
}

#[derive(Clone)]
pub struct Pin(pub Vec<u8>);

impl Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

#[derive(Clone)]
pub struct UserSecret(pub Vec<u8>);

impl Debug for UserSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

#[derive(Debug)]
pub struct Client {
    configuration: Vec<Realm>,
    auth_token: AuthToken,
}

#[derive(Debug)]
pub enum RegisterError {
    NetworkError(actix::MailboxError),
    InvalidAuth,
    AlreadyRegistered,
    Retry,
    ProtocolError,
}

#[derive(Debug)]
pub enum RecoverError {
    NetworkError(actix::MailboxError),
    InvalidAuth,
    NotRegistered,
    NoGuesses,
    FailedUnlock,
    ProtocolError,
}

#[derive(Debug)]
pub enum DeleteError {
    NetworkError(actix::MailboxError),
    InvalidAuth,
}

struct PasswordGeneratingKey(Vec<u8>);

impl PasswordGeneratingKey {
    fn new_random() -> Self {
        // The PGK should be the same size as the OPRF output,
        // so that the PGK shares can be masked with the OPRF output.
        let mut pgk = vec![0u8; oprf_output_size()];
        OsRng.fill_bytes(&mut pgk);
        Self(pgk)
    }

    fn password(&self, realm_id: &[u8]) -> UnlockPassword {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("failed to initialize HMAC");
        mac.update(realm_id);
        UnlockPassword(mac.finalize().into_bytes().to_vec())
    }
}

#[derive(Clone)]
struct PgkShare(pub Vec<u8>);

impl From<Vec<u8>> for PgkShare {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

// Named arguments to [`Client::register_on_realm`].
struct RegisterOnRealmArgs {
    pin: Pin,
    pgk_share: PgkShare,
    password: UnlockPassword,
    secret_share: UserSecretShare,
    policy: Policy,
}

impl Client {
    pub fn new(configuration: Vec<Realm>, auth_token: AuthToken) -> Self {
        assert!(!configuration.is_empty(), "Client needs at least one realm");
        Self {
            configuration,
            auth_token,
        }
    }

    pub async fn register(
        &self,
        pin: &Pin,
        secret: &UserSecret,
        policy: Policy,
    ) -> Result<(), RegisterError> {
        let pgk = PasswordGeneratingKey::new_random();
        let pgk_shares: Vec<PgkShare> =
            trivial_sharing::split(&pgk.0, self.configuration.len(), &mut OsRng);
        let secret_shares: Vec<UserSecretShare> =
            trivial_sharing::split(&secret.0, self.configuration.len(), &mut OsRng);

        let requests = self
            .configuration
            .iter()
            .zip(pgk_shares)
            .zip(secret_shares)
            .map(|((realm, pgk_share), secret_share)| {
                self.register_on_realm(
                    realm,
                    RegisterOnRealmArgs {
                        pin: pin.clone(),
                        pgk_share,
                        password: pgk.password(&realm.public_key),
                        secret_share,
                        policy: policy.clone(),
                    },
                )
            });

        try_join_all(requests).await?;
        Ok(())
    }

    async fn register_on_realm(
        &self,
        realm: &Realm,
        args: RegisterOnRealmArgs,
    ) -> Result<(), RegisterError> {
        let blinded_pin = OprfClient::blind(&args.pin.0, &mut OsRng).expect("voprf blinding error");

        let register1_result = realm
            .address
            .send(Register1Request {
                auth_token: self.auth_token.clone(),
                blinded_pin: blinded_pin.message,
            })
            .await;

        let oprf_pin = match register1_result {
            Err(err) => return Err(RegisterError::NetworkError(err)),
            Ok(response) => match response {
                Register1Response::Ok { blinded_oprf_pin } => {
                    let oprf_pin = blinded_pin
                        .state
                        .finalize(&args.pin.0, &blinded_oprf_pin)
                        .map_err(|e| {
                            println!("failed to unblind oprf result: {e:?}");
                            RegisterError::ProtocolError
                        })?;
                    if oprf_pin.len() != oprf_output_size() {
                        return Err(RegisterError::ProtocolError);
                    }
                    oprf_pin
                }
                Register1Response::InvalidAuth => return Err(RegisterError::InvalidAuth),
                Register1Response::AlreadyRegistered => {
                    return Err(RegisterError::AlreadyRegistered)
                }
            },
        };

        let masked_pgk_share = {
            assert_eq!(oprf_pin.len(), args.pgk_share.0.len());
            let mut masked_pgk_share = vec![0u8; args.pgk_share.0.len()];
            for i in 0..masked_pgk_share.len() {
                masked_pgk_share[i] = oprf_pin[i] ^ args.pgk_share.0[i];
            }
            MaskedPgkShare(masked_pgk_share)
        };

        let register2_result = realm
            .address
            .send(Register2Request {
                auth_token: self.auth_token.clone(),
                masked_pgk_share,
                password: args.password,
                secret_share: args.secret_share,
                policy: args.policy.clone(),
            })
            .await;

        match register2_result {
            Err(err) => Err(RegisterError::NetworkError(err)),
            Ok(response) => match response {
                Register2Response::Ok => Ok(()),
                Register2Response::InvalidAuth => Err(RegisterError::InvalidAuth),
                Register2Response::NotRegistering => Err(RegisterError::Retry),
                Register2Response::AlreadyRegistered => Err(RegisterError::AlreadyRegistered),
            },
        }
    }

    pub async fn recover(&self, pin: &Pin) -> Result<UserSecret, RecoverError> {
        let recover1_requests = self
            .configuration
            .iter()
            .map(|realm| self.recover1_on_realm(realm, pin));

        let pgk_shares = try_join_all(recover1_requests).await?;

        let pgk = match trivial_sharing::recombine(pgk_shares.iter().map(|s| &s.0)) {
            Ok(pgk) => PasswordGeneratingKey(pgk),
            Err(RecombineError::NoShares) => panic!("had some shares"),
            Err(RecombineError::ShareLengthsDiffer) => return Err(RecoverError::ProtocolError),
        };

        let recover2_requests = self
            .configuration
            .iter()
            .map(|realm| self.recover2_on_realm(realm, pgk.password(&realm.public_key)));

        let secret_shares = try_join_all(recover2_requests).await?;

        match trivial_sharing::recombine(secret_shares.iter().map(|s| &s.0)) {
            Ok(secret) => Ok(UserSecret(secret)),
            Err(RecombineError::NoShares) => panic!("had some shares"),
            Err(RecombineError::ShareLengthsDiffer) => Err(RecoverError::ProtocolError),
        }
    }

    async fn recover1_on_realm(&self, realm: &Realm, pin: &Pin) -> Result<PgkShare, RecoverError> {
        let blinded_pin = OprfClient::blind(&pin.0, &mut OsRng).expect("voprf blinding error");

        let recover1_result = realm
            .address
            .send(Recover1Request {
                auth_token: self.auth_token.clone(),
                blinded_pin: blinded_pin.message,
            })
            .await;

        let (blinded_oprf_pin, masked_pgk_share) = match recover1_result {
            Err(err) => return Err(RecoverError::NetworkError(err)),
            Ok(response) => match response {
                Recover1Response::Ok {
                    blinded_oprf_pin,
                    masked_pgk_share,
                } => (blinded_oprf_pin, masked_pgk_share),
                Recover1Response::InvalidAuth => return Err(RecoverError::InvalidAuth),
                Recover1Response::NotRegistered => return Err(RecoverError::NotRegistered),
                Recover1Response::NoGuesses => return Err(RecoverError::NoGuesses),
            },
        };

        let oprf_pin = blinded_pin
            .state
            .finalize(&pin.0, &blinded_oprf_pin)
            .map_err(|e| {
                println!("failed to unblind oprf result: {e:?}");
                RecoverError::ProtocolError
            })?;
        if oprf_pin.len() != oprf_output_size() {
            return Err(RecoverError::ProtocolError);
        }

        assert_eq!(oprf_pin.len(), masked_pgk_share.0.len());
        let mut pgk_share = vec![0u8; masked_pgk_share.0.len()];
        for i in 0..masked_pgk_share.0.len() {
            pgk_share[i] = oprf_pin[i] ^ masked_pgk_share.0[i];
        }
        Ok(PgkShare(pgk_share.to_vec()))
    }

    async fn recover2_on_realm(
        &self,
        realm: &Realm,
        password: UnlockPassword,
    ) -> Result<UserSecretShare, RecoverError> {
        let recover2_result = realm
            .address
            .send(Recover2Request {
                auth_token: self.auth_token.clone(),
                password,
            })
            .await;

        match recover2_result {
            Err(err) => Err(RecoverError::NetworkError(err)),
            Ok(response) => match response {
                Recover2Response::Ok(secret_share) => Ok(secret_share),
                Recover2Response::InvalidAuth => Err(RecoverError::InvalidAuth),
                Recover2Response::NotRegistered => Err(RecoverError::NotRegistered),
                Recover2Response::BadUnlockPassword => Err(RecoverError::FailedUnlock),
            },
        }
    }

    pub async fn delete_all(&self) -> Result<(), DeleteError> {
        let requests = self
            .configuration
            .iter()
            .map(|realm| self.delete_on_realm(realm));

        // Use `join_all` instead of `try_join_all` so that a failed delete
        // request does not short-ciruit other requests (which may still succeed).
        join_all(requests).await.into_iter().collect()
    }

    async fn delete_on_realm(&self, realm: &Realm) -> Result<(), DeleteError> {
        let delete_result = realm
            .address
            .send(DeleteRequest {
                auth_token: self.auth_token.clone(),
            })
            .await;

        match delete_result {
            Err(err) => Err(DeleteError::NetworkError(err)),
            Ok(response) => match response {
                DeleteResponse::Ok => Ok(()),
                DeleteResponse::InvalidAuth => Err(DeleteError::InvalidAuth),
            },
        }
    }
}
