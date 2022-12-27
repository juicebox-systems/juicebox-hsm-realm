//! Register and recover PIN-protected secrets on behalf of a particular user.
//! See [`Client`].

use actix::prelude::*;
use digest::Digest;
use futures::future::{join_all, try_join_all};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::collections::BTreeSet;
use std::fmt::{self, Debug};
use std::iter::zip;

mod trivial_sharing;
use trivial_sharing::RecombineError;

use super::types::{
    AuthToken, DeleteRequest, DeleteResponse, GenerationNumber, MaskedPgkShare, OprfBlindedResult,
    OprfCipherSuite, Policy, Recover1Request, Recover1Response, Recover2Request, Recover2Response,
    Register1Request, Register1Response, Register2Request, Register2Response, UnlockPassword,
    UserSecretShare,
};
use super::Server;

type OprfClient = voprf::OprfClient<OprfCipherSuite>;
type OprfResult = digest::Output<<OprfCipherSuite as voprf::CipherSuite>::Hash>;

fn oprf_output_size() -> usize {
    <OprfCipherSuite as voprf::CipherSuite>::Hash::output_size()
}

/// A remote service that the client interacts with directly.
#[derive(Debug, Clone)]
pub struct Realm {
    /// The network address to connect to the service.
    pub address: Addr<Server>,
    /// A long-lived public key for which the service has the matching private
    /// key.
    pub public_key: Vec<u8>,
}

/// A user-chosen password that may be low in entropy.
#[derive(Clone)]
pub struct Pin(pub Vec<u8>);

impl Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

/// A user-chosen secret.
///
/// # Warning
///
/// If the secrets vary in length (such as passwords), the caller should add
/// padding to obscure the secrets' length. Values of this type are assumed
/// to already include such padding.
#[derive(Clone)]
pub struct UserSecret(pub Vec<u8>);

impl Debug for UserSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

// TODO: many errors should specify the realm involved.

/// Error return type for [`Client::register`].
#[derive(Debug)]
pub enum RegisterError {
    /// A transient error in sending or receiving requests to a realm.
    NetworkError(actix::MailboxError),

    /// A realm rejected the `Client`'s auth token.
    InvalidAuth,

    /// An error representing an assumption was not met in executing the
    /// registration protocol.
    ///
    /// This can arise if any servers are misbehaving or running an unexpected
    /// version of the protocol, or if the user is concurrently executing
    /// requests.
    ProtocolError,
}

/// Error return type for [`Client::recover`].
#[derive(Debug)]
pub enum RecoverError {
    /// A transient error in sending or receiving requests to a realm.
    NetworkError(actix::MailboxError),

    /// A realm rejected the `Client`'s auth token.
    InvalidAuth,

    /// A list of attempts explaining why the recovery failed.
    ///
    /// Each entry in the vector corresponds to an attempt at recovery with
    /// a particular realm at a particular generation number.
    Unsuccessful(Vec<(GenerationNumber, UnsuccessfulRecoverReason)>),
}

/// An explanation for a [`RecoverError::Unsuccessful`] entry.
#[derive(Debug)]
pub enum UnsuccessfulRecoverReason {
    /// The secret was not registered or not fully registered.
    NotRegistered,

    /// The secret was locked due to too many failed recovery attempts.
    NoGuesses,

    /// The secret could not be unlocked, most likely due to an incorrect PIN.
    FailedUnlock,

    /// An error representing an assumption was not met in executing the
    /// registration protocol.
    ///
    /// This can arise if any servers are misbehaving or running an unexpected
    /// version of the protocol, or if the user is concurrently executing
    /// requests or has previously executed requests with a misbehaving client.
    ProtocolError,
}

/// Error return type for [`Client::delete_all`].
#[derive(Debug)]
pub enum DeleteError {
    /// A transient error in sending or receiving requests to a realm.
    NetworkError(actix::MailboxError),

    /// A realm rejected the `Client`'s auth token.
    InvalidAuth,
}

/// A random key that is used to derive secret-unlocking passwords
/// ([`UnlockPassword`]) for each realm.
struct PasswordGeneratingKey(Vec<u8>);

impl PasswordGeneratingKey {
    /// Generates a new key with random data.
    fn new_random() -> Self {
        // The PGK should be the same size as the OPRF output,
        // so that the PGK shares can be masked with the OPRF output.
        let mut pgk = vec![0u8; oprf_output_size()];
        OsRng.fill_bytes(&mut pgk);
        Self(pgk)
    }

    /// Computes a derived secret-unlocking password for the realm.
    fn password(&self, realm_id: &[u8]) -> UnlockPassword {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("failed to initialize HMAC");
        mac.update(realm_id);
        UnlockPassword(mac.finalize().into_bytes().to_vec())
    }
}

/// A share of the [`PasswordGeneratingKey`].
///
/// The version of this that is XORed with `OPRF(PIN)` is
/// [`MaskedPgkShare`](super::types::MaskedPgkShare).
#[derive(Clone)]
struct PgkShare(pub Vec<u8>);

impl From<Vec<u8>> for PgkShare {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

/// Successful return type of [`Client::register_generation`].
struct RegisterGenSuccess {
    /// If true, at least one generation record with a lower generation number
    /// was found on the server. The client should attempt to delete those
    /// records.
    found_earlier_generations: bool,
}

/// Error return type of [`Client::register_generation`].
enum RegisterGenError {
    Error(RegisterError),
    Retry(GenerationNumber),
}

/// Named arguments to [`Client::register2`].
struct Register2Args {
    generation: GenerationNumber,
    oprf_pin: OprfResult,
    pgk_share: PgkShare,
    password: UnlockPassword,
    secret_share: UserSecretShare,
    policy: Policy,
}

/// Successful return type of [`Client::recover_generation`].
struct RecoverGenSuccess {
    generation: GenerationNumber,
    secret: UserSecret,
    found_earlier_generations: bool,
}

/// Error return type of [`Client::recover_generation`].
struct RecoverGenError {
    error: RecoverError,
    retry: Option<GenerationNumber>,
}

/// Successful return type of [`Client::recover1`].
struct Recover1Success {
    generation: GenerationNumber,
    pgk_share: PgkShare,
    previous_generation: Option<GenerationNumber>,
}

/// Used to register and recover PIN-protected secrets on behalf of a
/// particular user.
#[derive(Debug)]
pub struct Client {
    configuration: Vec<Realm>,
    auth_token: AuthToken,
}

impl Client {
    /// Constructs a new `Client`.
    ///
    /// The configuration provided must include at least one realm.
    ///
    /// The `auth_token` represents the authority to act as a particular user
    /// and should be valid for the lifetime of the `Client`.
    pub fn new(configuration: Vec<Realm>, auth_token: AuthToken) -> Self {
        assert!(!configuration.is_empty(), "Client needs at least one realm");
        Self {
            configuration,
            auth_token,
        }
    }

    /// Stores a new PIN-protected secret.
    ///
    /// If it's successful, this also deletes any prior secrets for this user.
    ///
    /// # Warning
    ///
    /// If the secrets vary in length (such as passwords), the caller should
    /// add padding to obscure the secrets' length.
    pub async fn register(
        &self,
        pin: &Pin,
        secret: &UserSecret,
        policy: Policy,
    ) -> Result<(), RegisterError> {
        // This first tries to register generation 0. If that generation has
        // already been used, it then tries to register the first generation
        // that was available on all servers.
        match self
            .register_generation(GenerationNumber(0), pin, secret, policy.clone())
            .await
        {
            Ok(_) => Ok(()),

            Err(RegisterGenError::Error(e)) => Err(e),

            Err(RegisterGenError::Retry(generation)) => {
                match self
                    .register_generation(generation, pin, secret, policy)
                    .await
                {
                    Ok(RegisterGenSuccess {
                        found_earlier_generations,
                    }) => {
                        if found_earlier_generations {
                            if let Err(delete_err) = self.delete_up_to(Some(generation)).await {
                                println!("warning: register failed to clean up earlier registrations: {delete_err:?}");
                            }
                        }
                        Ok(())
                    }

                    Err(RegisterGenError::Error(e)) => Err(e),

                    Err(RegisterGenError::Retry(_)) => Err(RegisterError::ProtocolError),
                }
            }
        }
    }

    /// Registers a PIN-protected secret at a given generation number.
    async fn register_generation(
        &self,
        generation: GenerationNumber,
        pin: &Pin,
        secret: &UserSecret,
        policy: Policy,
    ) -> Result<RegisterGenSuccess, RegisterGenError> {
        let register1_requests = self
            .configuration
            .iter()
            .map(|realm| self.register1(realm, generation, pin));

        // Wait for and process the results to `register1` from all the servers
        // here. It's technically possible to have all the servers do both
        // phases of registration without any synchronization. However, in the
        // event that the desired `generation` is unavailable on some server,
        // powering through to phase 2 would waste server time and leave behind
        // cruft. It's better to synchronize here and abort early instead.
        let oprfs_pin = {
            let mut oprfs_pin: Vec<OprfResult> = Vec::with_capacity(self.configuration.len());
            // The next generation number that is available on every server (so
            // far).
            let mut retry_generation = None;
            for result in join_all(register1_requests).await {
                match result {
                    Ok(oprf_pin) => {
                        oprfs_pin.push(oprf_pin);
                    }
                    Err(e @ RegisterGenError::Error(_)) => return Err(e),
                    Err(RegisterGenError::Retry(generation)) => match retry_generation {
                        None => retry_generation = Some(generation),
                        Some(g) => {
                            if g < generation {
                                retry_generation = Some(generation);
                            }
                        }
                    },
                }
            }
            if let Some(g) = retry_generation {
                return Err(RegisterGenError::Retry(g));
            }
            assert_eq!(oprfs_pin.len(), self.configuration.len());
            oprfs_pin
        };

        let pgk = PasswordGeneratingKey::new_random();
        let pgk_shares: Vec<PgkShare> =
            trivial_sharing::split(&pgk.0, self.configuration.len(), &mut OsRng);
        let secret_shares: Vec<UserSecretShare> =
            trivial_sharing::split(&secret.0, self.configuration.len(), &mut OsRng);

        let register2_requests = self.configuration.iter().enumerate().map(|(i, realm)| {
            self.register2(
                realm,
                Register2Args {
                    generation,
                    oprf_pin: oprfs_pin[i],
                    pgk_share: pgk_shares[i].clone(),
                    password: pgk.password(&realm.public_key),
                    secret_share: secret_shares[i].clone(),
                    policy: policy.clone(),
                },
            )
        });

        match try_join_all(register2_requests).await {
            Ok(success) => Ok(RegisterGenSuccess {
                found_earlier_generations: success.iter().any(|s| s.found_earlier_generations),
            }),
            Err(e) => Err(RegisterGenError::Error(e)),
        }
    }

    /// Executes phase 1 of registration on a particular realm at a particular
    /// generation.
    async fn register1(
        &self,
        realm: &Realm,
        generation: GenerationNumber,
        pin: &Pin,
    ) -> Result<OprfResult, RegisterGenError> {
        let blinded_pin = OprfClient::blind(&pin.0, &mut OsRng).expect("voprf blinding error");

        let register1_request = realm.address.send(Register1Request {
            auth_token: self.auth_token.clone(),
            generation,
            blinded_pin: blinded_pin.message,
        });

        match register1_request.await {
            Err(err) => Err(RegisterGenError::Error(RegisterError::NetworkError(err))),

            Ok(response) => match response {
                Register1Response::Ok { blinded_oprf_pin } => {
                    let oprf_pin = blinded_pin
                        .state
                        .finalize(&pin.0, &blinded_oprf_pin)
                        .map_err(|e| {
                            println!("failed to unblind oprf result: {e:?}");
                            RegisterGenError::Error(RegisterError::ProtocolError)
                        })?;
                    if oprf_pin.len() != oprf_output_size() {
                        return Err(RegisterGenError::Error(RegisterError::ProtocolError));
                    }
                    Ok(oprf_pin)
                }

                Register1Response::InvalidAuth => {
                    Err(RegisterGenError::Error(RegisterError::InvalidAuth))
                }

                Register1Response::BadGeneration { first_available } => {
                    Err(RegisterGenError::Retry(first_available))
                }
            },
        }
    }

    /// Executes phase 2 of registration on a particular realm at a particular
    /// generation.
    async fn register2(
        &self,
        realm: &Realm,
        Register2Args {
            generation,
            oprf_pin,
            pgk_share,
            password,
            secret_share,
            policy,
        }: Register2Args,
    ) -> Result<RegisterGenSuccess, RegisterError> {
        assert_eq!(oprf_pin.len(), pgk_share.0.len());
        let masked_pgk_share =
            MaskedPgkShare(zip(oprf_pin, pgk_share.0).map(|(a, b)| a ^ b).collect());

        let register2_request = realm.address.send(Register2Request {
            auth_token: self.auth_token.clone(),
            generation,
            masked_pgk_share,
            password,
            secret_share,
            policy,
        });

        match register2_request.await {
            Err(err) => Err(RegisterError::NetworkError(err)),
            Ok(response) => match response {
                Register2Response::Ok {
                    found_earlier_generations,
                } => Ok(RegisterGenSuccess {
                    found_earlier_generations,
                }),
                Register2Response::InvalidAuth => Err(RegisterError::InvalidAuth),
                Register2Response::NotRegistering | Register2Response::AlreadyRegistered => {
                    Err(RegisterError::ProtocolError)
                }
            },
        }
    }

    /// Retrieves a PIN-protected secret.
    ///
    /// If it's successful, this also deletes any earlier secrets for this
    /// user.
    pub async fn recover(&self, pin: &Pin) -> Result<UserSecret, RecoverError> {
        // First, try the latest generation on each server (represented as
        // `generation = None`). In the common case, all the servers will
        // agree on the last registered generation. If they don't, step back by
        // one generation at a time, limited to actual generations seen,
        // heading towards generation 0.

        let mut generation: Option<GenerationNumber> = None;
        let mut unsuccessful: Vec<(GenerationNumber, UnsuccessfulRecoverReason)> = Vec::new();

        loop {
            return match self.recover_generation(generation, pin).await {
                Ok(RecoverGenSuccess {
                    generation,
                    secret,
                    found_earlier_generations,
                }) => {
                    if found_earlier_generations {
                        if let Err(delete_err) = self.delete_up_to(Some(generation)).await {
                            println!("warning: recover failed to clean up earlier registrations: {delete_err:?}");
                        }
                    }
                    Ok(secret)
                }

                Err(
                    e @ RecoverGenError {
                        error: RecoverError::NetworkError(_) | RecoverError::InvalidAuth,
                        retry: _,
                    },
                ) => Err(e.error),

                Err(RecoverGenError {
                    error: RecoverError::Unsuccessful(detail),
                    retry,
                }) => {
                    unsuccessful.extend(detail);
                    if retry.is_some() {
                        assert!(retry < generation);
                        generation = retry;
                        continue;
                    }
                    Err(RecoverError::Unsuccessful(unsuccessful))
                }
            };
        }
    }

    /// Retrieves a PIN-protected secret at a given generation number.
    ///
    /// If the generation number is given as `None`, tries the latest
    /// generation present on each realm.
    async fn recover_generation(
        &self,
        request_generation: Option<GenerationNumber>,
        pin: &Pin,
    ) -> Result<RecoverGenSuccess, RecoverGenError> {
        let recover1_requests = self
            .configuration
            .iter()
            .map(|realm| self.recover1(realm, request_generation, pin));

        let mut generations_found = BTreeSet::new();
        let mut pgk_shares: Vec<(GenerationNumber, PgkShare)> = Vec::new();
        let mut unsuccessful: Vec<(GenerationNumber, UnsuccessfulRecoverReason)> = Vec::new();
        for result in join_all(recover1_requests).await {
            match result {
                Ok(Recover1Success {
                    generation,
                    pgk_share,
                    previous_generation,
                }) => {
                    generations_found.insert(generation);
                    if let Some(p) = previous_generation {
                        generations_found.insert(p);
                    }
                    pgk_shares.push((generation, pgk_share));
                }

                Err(
                    e @ RecoverGenError {
                        error: RecoverError::NetworkError(_) | RecoverError::InvalidAuth,
                        retry: _,
                    },
                ) => {
                    return Err(e);
                }

                Err(RecoverGenError {
                    error: RecoverError::Unsuccessful(detail),
                    retry,
                }) => {
                    for (generation, _reason) in &detail {
                        generations_found.insert(*generation);
                    }
                    unsuccessful.extend(detail);
                    if let Some(generation) = retry {
                        generations_found.insert(generation);
                    }
                }
            }
        }

        let mut iter = generations_found.into_iter().rev();
        let current_generation = iter.next().unwrap();
        let previous_generation = iter.next();

        if !unsuccessful.is_empty() {
            return Err(RecoverGenError {
                error: RecoverError::Unsuccessful(unsuccessful),
                retry: previous_generation,
            });
        }

        // At this point, we know the phase 1 requests were successful on each
        // realm for some generation, but their generations may not have
        // agreed.

        let pgk_shares: Vec<Vec<u8>> = pgk_shares
            .into_iter()
            .filter_map(|(generation, share)| {
                if generation == current_generation {
                    Some(share.0)
                } else {
                    None
                }
            })
            .collect();

        if pgk_shares.len() != self.configuration.len() {
            return Err(RecoverGenError {
                error: RecoverError::Unsuccessful(vec![(
                    current_generation,
                    UnsuccessfulRecoverReason::NotRegistered,
                )]),
                retry: previous_generation,
            });
        }

        let pgk = match trivial_sharing::recombine(pgk_shares) {
            Ok(pgk) => PasswordGeneratingKey(pgk),

            Err(RecombineError::NoShares) => unreachable!(),

            Err(RecombineError::ShareLengthsDiffer) => {
                return Err(RecoverGenError {
                    error: RecoverError::Unsuccessful(vec![(
                        current_generation,
                        UnsuccessfulRecoverReason::ProtocolError,
                    )]),
                    retry: previous_generation,
                });
            }
        };

        let recover2_requests = self
            .configuration
            .iter()
            .map(|realm| self.recover2(realm, current_generation, pgk.password(&realm.public_key)));

        let secret_shares =
            try_join_all(recover2_requests)
                .await
                .map_err(|error| RecoverGenError {
                    error,
                    retry: previous_generation,
                })?;

        match trivial_sharing::recombine(secret_shares.iter().map(|s| &s.0)) {
            Ok(secret) => Ok(RecoverGenSuccess {
                generation: current_generation,
                secret: UserSecret(secret),
                found_earlier_generations: previous_generation.is_some(),
            }),

            Err(RecombineError::NoShares | RecombineError::ShareLengthsDiffer) => {
                Err(RecoverGenError {
                    error: RecoverError::Unsuccessful(vec![(
                        current_generation,
                        UnsuccessfulRecoverReason::ProtocolError,
                    )]),
                    retry: previous_generation,
                })
            }
        }
    }

    /// Executes phase 1 of recovery on a particular realm at a particular
    /// generation.
    ///
    /// If the generation number is given as `None`, tries the latest
    /// generation present on the realm.
    async fn recover1(
        &self,
        realm: &Realm,
        generation: Option<GenerationNumber>,
        pin: &Pin,
    ) -> Result<Recover1Success, RecoverGenError> {
        let blinded_pin = OprfClient::blind(&pin.0, &mut OsRng).expect("voprf blinding error");

        let recover1_request = realm.address.send(Recover1Request {
            auth_token: self.auth_token.clone(),
            generation,
            blinded_pin: blinded_pin.message,
        });

        // This is a verbose way to copy some fields out to this outer scope.
        // It helps avoid having to process these fields at a high level of
        // indentation.
        struct OkResponse {
            generation: GenerationNumber,
            blinded_oprf_pin: OprfBlindedResult,
            masked_pgk_share: MaskedPgkShare,
            previous_generation: Option<GenerationNumber>,
        }
        let OkResponse {
            generation,
            blinded_oprf_pin,
            masked_pgk_share,
            previous_generation,
        } = match recover1_request.await {
            Err(err) => {
                return Err(RecoverGenError {
                    error: RecoverError::NetworkError(err),
                    retry: None,
                })
            }

            Ok(response) => match response {
                Recover1Response::Ok {
                    generation,
                    blinded_oprf_pin,
                    masked_pgk_share,
                    previous_generation,
                } => OkResponse {
                    generation,
                    blinded_oprf_pin,
                    masked_pgk_share,
                    previous_generation,
                },

                Recover1Response::InvalidAuth => {
                    return Err(RecoverGenError {
                        error: RecoverError::InvalidAuth,
                        retry: None,
                    })
                }

                Recover1Response::NotRegistered {
                    generation,
                    previous_generation,
                } => {
                    return Err(RecoverGenError {
                        error: RecoverError::Unsuccessful(vec![(
                            generation.unwrap_or(GenerationNumber(0)),
                            UnsuccessfulRecoverReason::NotRegistered,
                        )]),
                        retry: previous_generation,
                    });
                }

                Recover1Response::PartiallyRegistered {
                    generation,
                    previous_generation,
                    ..
                } => {
                    return Err(RecoverGenError {
                        error: RecoverError::Unsuccessful(vec![(
                            generation,
                            UnsuccessfulRecoverReason::NotRegistered,
                        )]),
                        retry: previous_generation,
                    });
                }

                Recover1Response::NoGuesses {
                    generation,
                    previous_generation,
                } => {
                    return Err(RecoverGenError {
                        error: RecoverError::Unsuccessful(vec![(
                            generation,
                            UnsuccessfulRecoverReason::NoGuesses,
                        )]),
                        retry: previous_generation,
                    });
                }
            },
        };

        let oprf_pin = blinded_pin
            .state
            .finalize(&pin.0, &blinded_oprf_pin)
            .map_err(|e| {
                println!("failed to unblind oprf result: {e:?}");
                RecoverGenError {
                    error: RecoverError::Unsuccessful(vec![(
                        generation,
                        UnsuccessfulRecoverReason::ProtocolError,
                    )]),
                    retry: previous_generation,
                }
            })?;

        if oprf_pin.len() != oprf_output_size() || masked_pgk_share.0.len() != oprf_output_size() {
            return Err(RecoverGenError {
                error: RecoverError::Unsuccessful(vec![(
                    generation,
                    UnsuccessfulRecoverReason::ProtocolError,
                )]),
                retry: previous_generation,
            });
        }

        let pgk_share = PgkShare(
            zip(oprf_pin, masked_pgk_share.0)
                .map(|(a, b)| a ^ b)
                .collect(),
        );

        Ok(Recover1Success {
            generation,
            pgk_share,
            previous_generation,
        })
    }

    /// Executes phase 2 of recovery on a particular realm at a particular
    /// generation.
    async fn recover2(
        &self,
        realm: &Realm,
        generation: GenerationNumber,
        password: UnlockPassword,
    ) -> Result<UserSecretShare, RecoverError> {
        let recover2_request = realm.address.send(Recover2Request {
            auth_token: self.auth_token.clone(),
            generation,
            password,
        });

        match recover2_request.await {
            Err(err) => Err(RecoverError::NetworkError(err)),
            Ok(response) => match response {
                Recover2Response::Ok(secret_share) => Ok(secret_share),
                Recover2Response::InvalidAuth => Err(RecoverError::InvalidAuth),
                Recover2Response::NotRegistered => Err(RecoverError::Unsuccessful(vec![(
                    generation,
                    UnsuccessfulRecoverReason::NotRegistered,
                )])),
                Recover2Response::BadUnlockPassword => Err(RecoverError::Unsuccessful(vec![(
                    generation,
                    UnsuccessfulRecoverReason::FailedUnlock,
                )])),
            },
        }
    }

    /// Deletes all secrets for this user.
    ///
    /// Note: This does not delete the user's audit log.
    pub async fn delete_all(&self) -> Result<(), DeleteError> {
        self.delete_up_to(None).await
    }

    /// Deletes all secrets for this user up to and excluding the given
    /// generation number.
    ///
    /// If the generation number is given as `None`, deletes all the user's
    /// generations.
    async fn delete_up_to(&self, up_to: Option<GenerationNumber>) -> Result<(), DeleteError> {
        let requests = self
            .configuration
            .iter()
            .map(|realm| self.delete_on_realm(realm, up_to));

        // Use `join_all` instead of `try_join_all` so that a failed delete
        // request does not short-ciruit other requests (which may still
        // succeed).
        join_all(requests).await.into_iter().collect()
    }

    /// Executes [`delete_up_to`](Self::delete_up_to) on a particular realm.
    async fn delete_on_realm(
        &self,
        realm: &Realm,
        up_to: Option<GenerationNumber>,
    ) -> Result<(), DeleteError> {
        let delete_result = realm
            .address
            .send(DeleteRequest {
                auth_token: self.auth_token.clone(),
                up_to,
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
