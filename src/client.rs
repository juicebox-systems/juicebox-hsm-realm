//! Register and recover PIN-protected secrets on behalf of a particular user.
//! See [`Client`].

use digest::Digest;
use futures::future::{join_all, try_join_all};
use hmac::{Hmac, Mac};
use hsmcore::marshalling;
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::Url;
use sha2::Sha256;
use sharks::Sharks;
use std::collections::BTreeSet;
use std::fmt::{self, Debug};
use std::iter::zip;
use std::ops::Deref;
use tracing::instrument;

use super::http_client;
use super::http_client::ClientError;
use super::realm::load_balancer::types::{ClientRequest, ClientResponse, LoadBalancerService};
use hsmcore::hsm::types::{RealmId, SecretsRequest, SecretsResponse};
use hsmcore::types::{
    AuthToken, DeleteRequest, DeleteResponse, GenerationNumber, MaskedTgkShare, OprfBlindedResult,
    OprfCipherSuite, Policy, Recover1Request, Recover1Response, Recover2Request, Recover2Response,
    Register1Request, Register1Response, Register2Request, Register2Response, UnlockTag,
    UserSecretShare,
};

type OprfClient = voprf::OprfClient<OprfCipherSuite>;
struct OprfResult(digest::Output<<OprfCipherSuite as voprf::CipherSuite>::Hash>);

impl Debug for OprfResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

fn oprf_output_size() -> usize {
    <OprfCipherSuite as voprf::CipherSuite>::Hash::output_size()
}

/// A remote service that the client interacts with directly.
#[derive(Clone)]
pub struct Realm {
    /// The network address to connect to the service.
    pub address: Url,
    /// A long-lived public key for which the service has the matching private
    /// key.
    pub public_key: Vec<u8>,
    /// Temp hack
    pub id: RealmId,
}

impl Debug for Realm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Realm")
            .field("id", &self.id)
            .field("address", &self.address.as_str())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct Configuration {
    /// The remote services that the client interacts with.
    ///
    /// There must be between `register_threshold` and 255 realms, inclusive.
    pub realms: Vec<Realm>,

    /// A registration will be considered successful if it's successful on at
    /// least this many realms.
    ///
    /// Must be between `recover_threshold` and `realms.len()`, inclusive.
    pub register_threshold: u8,

    /// A recovery (or an adversary) will need the cooperation of this many
    /// realms to retrieve the secret.
    ///
    /// Must be between `1` and `realms.len()`, inclusive.
    pub recover_threshold: u8,
}

#[derive(Debug)]
struct CheckedConfiguration(Configuration);

impl CheckedConfiguration {
    fn from(c: Configuration) -> Self {
        assert!(
            !c.realms.is_empty(),
            "Client needs at least one realm in Configuration"
        );

        // The secret sharing implementation (`sharks`) doesn't support more
        // than 255 shares.
        assert!(
            u8::try_from(c.realms.len()).is_ok(),
            "too many realms in Client configuration"
        );

        assert!(
            1 <= c.recover_threshold,
            "Configuration recover_threshold must be at least 1"
        );
        assert!(
            usize::from(c.recover_threshold) <= c.realms.len(),
            "Configuration recover_threshold cannot exceed number of realms"
        );

        assert!(
            c.recover_threshold <= c.register_threshold,
            "Configuration register_threshold must be at least recover_threshold"
        );
        assert!(
            usize::from(c.register_threshold) <= c.realms.len(),
            "Configuration register_threshold cannot exceed number of realms"
        );

        Self(c)
    }
}

impl Deref for CheckedConfiguration {
    type Target = Configuration;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
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
    NetworkError(reqwest::Error),

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
    NetworkError(reqwest::Error),

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
    NetworkError(reqwest::Error),

    /// A realm rejected the `Client`'s auth token.
    InvalidAuth,
}

/// A random key that is used to derive secret-unlocking tags
/// ([`UnlockTag`]) for each realm.
struct TagGeneratingKey(Vec<u8>);

impl TagGeneratingKey {
    /// Generates a new key with random data.
    fn new_random() -> Self {
        // The TGK should be one byte smaller than the OPRF output,
        // so that the TGK shares can be masked with the OPRF output.
        // The `sharks` library adds an extra byte for the x-coordinate.
        let mut tgk = vec![0u8; oprf_output_size() - 1];
        OsRng.fill_bytes(&mut tgk);
        Self(tgk)
    }

    /// Computes a derived secret-unlocking tag for the realm.
    fn tag(&self, realm_id: &[u8]) -> UnlockTag {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("failed to initialize HMAC");
        mac.update(realm_id);
        UnlockTag(mac.finalize().into_bytes().to_vec())
    }
}

/// Error return type for [`TgkShare::try_from_masked`].
#[derive(Debug)]
struct LengthMismatchError;

/// A share of the [`TagGeneratingKey`].
///
/// The version of this that is XORed with `OPRF(PIN)` is
/// [`MaskedTgkShare`](super::types::MaskedTgkShare).
#[derive(Clone)]
struct TgkShare(sharks::Share);

impl Debug for TgkShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

impl TgkShare {
    fn try_from_masked(
        masked_share: &MaskedTgkShare,
        oprf_pin: &[u8],
    ) -> Result<Self, LengthMismatchError> {
        if masked_share.0.len() == oprf_pin.len() {
            let share: Vec<u8> = zip(oprf_pin, &masked_share.0).map(|(a, b)| a ^ b).collect();
            match sharks::Share::try_from(share.as_slice()) {
                Ok(share) => Ok(Self(share)),
                Err(_) => Err(LengthMismatchError),
            }
        } else {
            Err(LengthMismatchError)
        }
    }

    fn mask(&self, oprf_pin: &OprfResult) -> MaskedTgkShare {
        let share = Vec::from(&self.0);
        assert_eq!(oprf_pin.0.len(), share.len());
        MaskedTgkShare(zip(oprf_pin.0, share).map(|(a, b)| a ^ b).collect())
    }
}

/// Successful return type of [`Client::register_generation`].
#[derive(Debug)]
struct RegisterGenSuccess {
    /// If true, at least one generation record with a lower generation number
    /// was found on the server. The client should attempt to delete those
    /// records.
    found_earlier_generations: bool,
}

/// Error return type of [`Client::register_generation`].
#[derive(Debug)]
enum RegisterGenError {
    Error(RegisterError),
    Retry(GenerationNumber),
}

/// Named arguments to [`Client::register2`].
struct Register2Args {
    generation: GenerationNumber,
    oprf_pin: OprfResult,
    tgk_share: TgkShare,
    tag: UnlockTag,
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
#[derive(Debug)]
struct RecoverGenError {
    error: RecoverError,
    retry: Option<GenerationNumber>,
}

/// Successful return type of [`Client::recover1`].
#[derive(Debug)]
struct Recover1Success {
    generation: GenerationNumber,
    tgk_share: TgkShare,
    previous_generation: Option<GenerationNumber>,
}

/// Used to register and recover PIN-protected secrets on behalf of a
/// particular user.
#[derive(Debug)]
pub struct Client {
    configuration: CheckedConfiguration,
    auth_token: AuthToken,
    http: http_client::Client<LoadBalancerService>,
}

enum RequestError {
    HttpError(reqwest::Error),
    HttpStatus(reqwest::StatusCode),
    DeserializationError(marshalling::DeserializationError),
    SerializationError(marshalling::SerializationError),
    Unavailable,
    InvalidAuth,
}

impl Client {
    /// Constructs a new `Client`.
    ///
    /// The configuration provided must include at least one realm.
    ///
    /// The `auth_token` represents the authority to act as a particular user
    /// and should be valid for the lifetime of the `Client`.
    pub fn new(configuration: Configuration, auth_token: AuthToken) -> Self {
        Self {
            configuration: CheckedConfiguration::from(configuration),
            auth_token,
            http: http_client::Client::new(),
        }
    }

    async fn make_request(
        &self,
        realm: &Realm,
        request: SecretsRequest,
    ) -> Result<SecretsResponse, RequestError> {
        match self
            .http
            .send(
                &realm.address,
                ClientRequest {
                    realm: realm.id,
                    auth_token: self.auth_token.clone(),
                    request,
                },
            )
            .await
        {
            Ok(ClientResponse::Ok(response)) => Ok(response),
            Ok(ClientResponse::Unavailable) => Err(RequestError::Unavailable),
            Ok(ClientResponse::InvalidAuth) => Err(RequestError::InvalidAuth),
            Err(ClientError::Network(e)) => Err(RequestError::HttpError(e)),
            Err(ClientError::HttpStatus(sc)) => Err(RequestError::HttpStatus(sc)),
            Err(ClientError::Serialization(e)) => Err(RequestError::SerializationError(e)),
            Err(ClientError::Deserialization(e)) => Err(RequestError::DeserializationError(e)),
            Err(ClientError::HsmRpcError) => Err(RequestError::Unavailable),
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
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
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
                                println!("client: warning: register failed to clean up earlier registrations: {delete_err:?}");
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
            .realms
            .iter()
            .map(|realm| self.register1(realm, generation, pin));

        // Wait for and process the results to `register1` from all the servers
        // here. It's technically possible to have all the servers do both
        // phases of registration without any synchronization. However, in the
        // event that the desired `generation` is unavailable on some server,
        // powering through to phase 2 would waste server time and leave behind
        // cruft. It's better to synchronize here and abort early instead.
        let oprfs_pin: Vec<Option<OprfResult>> = {
            let mut oprfs_pin = Vec::with_capacity(self.configuration.realms.len());
            // The next generation number that is available on every server (so
            // far).
            let mut retry_generation = None;
            let mut network_errors = 0;
            for result in join_all(register1_requests).await {
                match result {
                    Ok(oprf_pin) => {
                        oprfs_pin.push(Some(oprf_pin));
                    }
                    Err(RegisterGenError::Error(e @ RegisterError::NetworkError(_))) => {
                        println!("client: warning: transient error during register1: {e:?}");
                        network_errors += 1;
                        if self.configuration.realms.len() - network_errors
                            < usize::from(self.configuration.register_threshold)
                        {
                            return Err(RegisterGenError::Error(e));
                        }
                        oprfs_pin.push(None);
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
            assert_eq!(oprfs_pin.len(), self.configuration.realms.len());
            oprfs_pin
        };

        let tgk = TagGeneratingKey::new_random();

        let tgk_shares: Vec<TgkShare> = {
            Sharks(self.configuration.recover_threshold)
                .dealer_rng(&tgk.0, &mut OsRng)
                .take(self.configuration.realms.len())
                .map(TgkShare)
                .collect()
        };

        let secret_shares: Vec<UserSecretShare> = {
            Sharks(self.configuration.recover_threshold)
                .dealer_rng(&secret.0, &mut OsRng)
                .take(self.configuration.realms.len())
                .map(|share| UserSecretShare(Vec::<u8>::from(&share)))
                .collect()
        };

        let register2_requests = zip4(
            &self.configuration.realms,
            oprfs_pin,
            tgk_shares,
            secret_shares,
        )
        .filter_map(|(realm, oprf_pin, tgk_share, secret_share)| {
            oprf_pin.map(|oprf_pin| {
                self.register2(
                    realm,
                    Register2Args {
                        generation,
                        oprf_pin,
                        tgk_share,
                        tag: tgk.tag(&realm.public_key),
                        secret_share,
                        policy: policy.clone(),
                    },
                )
            })
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
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    async fn register1(
        &self,
        realm: &Realm,
        generation: GenerationNumber,
        pin: &Pin,
    ) -> Result<OprfResult, RegisterGenError> {
        let blinded_pin = OprfClient::blind(&pin.0, &mut OsRng).expect("voprf blinding error");

        let register1_request = self.make_request(
            realm,
            SecretsRequest::Register1(Register1Request {
                generation,
                blinded_pin: blinded_pin.message,
            }),
        );
        match register1_request.await {
            Err(RequestError::HttpError(err)) => {
                Err(RegisterGenError::Error(RegisterError::NetworkError(err)))
            }
            Err(RequestError::DeserializationError(_))
            | Err(RequestError::SerializationError(_)) => {
                Err(RegisterGenError::Error(RegisterError::ProtocolError))
            }
            Err(RequestError::HttpStatus(_status)) => todo!(),
            Err(RequestError::Unavailable) => todo!(),
            Err(RequestError::InvalidAuth) => {
                Err(RegisterGenError::Error(RegisterError::InvalidAuth))
            }

            Ok(SecretsResponse::Register1(rr)) => match rr {
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
                    Ok(OprfResult(oprf_pin))
                }

                Register1Response::BadGeneration { first_available } => {
                    Err(RegisterGenError::Retry(first_available))
                }
            },

            Ok(_) => todo!(),
        }
    }

    /// Executes phase 2 of registration on a particular realm at a particular
    /// generation.
    #[instrument(level = "trace", skip(self), ret, err(level = "trace", Debug))]
    async fn register2(
        &self,
        realm: &Realm,
        Register2Args {
            generation,
            oprf_pin,
            tgk_share,
            tag,
            secret_share,
            policy,
        }: Register2Args,
    ) -> Result<RegisterGenSuccess, RegisterError> {
        let masked_tgk_share = tgk_share.mask(&oprf_pin);

        let register2_request = self.make_request(
            realm,
            SecretsRequest::Register2(Register2Request {
                generation,
                masked_tgk_share,
                tag,
                secret_share,
                policy,
            }),
        );

        match register2_request.await {
            Err(RequestError::HttpError(err)) => Err(RegisterError::NetworkError(err)),
            Err(RequestError::DeserializationError(_))
            | Err(RequestError::SerializationError(_)) => Err(RegisterError::ProtocolError),
            Err(RequestError::HttpStatus(_status)) => todo!(),
            Err(RequestError::Unavailable) => todo!(),
            Err(RequestError::InvalidAuth) => Err(RegisterError::InvalidAuth),

            Ok(SecretsResponse::Register2(rr)) => match rr {
                Register2Response::Ok {
                    found_earlier_generations,
                } => Ok(RegisterGenSuccess {
                    found_earlier_generations,
                }),
                Register2Response::NotRegistering | Register2Response::AlreadyRegistered => {
                    Err(RegisterError::ProtocolError)
                }
            },
            Ok(_) => Err(RegisterError::ProtocolError),
        }
    }

    /// Retrieves a PIN-protected secret.
    ///
    /// If it's successful, this also deletes any earlier secrets for this
    /// user.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
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
                            println!("client: warning: recover failed to clean up earlier registrations: {delete_err:?}");
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
            .realms
            .iter()
            .map(|realm| self.recover1(realm, request_generation, pin));

        let mut generations_found = BTreeSet::new();
        let mut tgk_shares: Vec<(GenerationNumber, TgkShare)> = Vec::new();
        let mut unsuccessful: Vec<(GenerationNumber, UnsuccessfulRecoverReason)> = Vec::new();
        for result in join_all(recover1_requests).await {
            match result {
                Ok(Recover1Success {
                    generation,
                    tgk_share,
                    previous_generation,
                }) => {
                    generations_found.insert(generation);
                    if let Some(p) = previous_generation {
                        generations_found.insert(p);
                    }
                    tgk_shares.push((generation, tgk_share));
                }

                Err(RecoverGenError {
                    error: error @ RecoverError::NetworkError(_),
                    retry: _,
                }) => {
                    println!("client: warning: transient error during recover1: {error:?}");
                }

                Err(
                    e @ RecoverGenError {
                        error: RecoverError::InvalidAuth,
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

        let tgk_shares: Vec<sharks::Share> = tgk_shares
            .into_iter()
            .filter_map(|(generation, share)| {
                if generation == current_generation {
                    Some(share.0)
                } else {
                    None
                }
            })
            .collect();

        if tgk_shares.len() < usize::from(self.configuration.recover_threshold) {
            return Err(RecoverGenError {
                error: RecoverError::Unsuccessful(vec![(
                    current_generation,
                    UnsuccessfulRecoverReason::NotRegistered,
                )]),
                retry: previous_generation,
            });
        }

        let tgk = match Sharks(self.configuration.recover_threshold).recover(&tgk_shares) {
            Ok(tgk) => TagGeneratingKey(tgk),

            Err(_) => {
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
            .realms
            .iter()
            .map(|realm| self.recover2(realm, current_generation, tgk.tag(&realm.public_key)));

        let recover2_results = join_all(recover2_requests).await;

        let mut secret_shares = Vec::<sharks::Share>::new();
        for result in recover2_results {
            match result {
                Ok(secret_share) => match sharks::Share::try_from(secret_share.0.as_slice()) {
                    Ok(secret_share) => {
                        secret_shares.push(secret_share);
                    }

                    Err(_) => {
                        return Err(RecoverGenError {
                            error: RecoverError::Unsuccessful(vec![(
                                current_generation,
                                UnsuccessfulRecoverReason::ProtocolError,
                            )]),
                            retry: previous_generation,
                        })
                    }
                },

                Err(error @ RecoverError::NetworkError(_)) => {
                    println!("client: warning: transient error during recover2: {error:?}");
                }

                Err(error) => {
                    return Err(RecoverGenError {
                        error,
                        retry: previous_generation,
                    })
                }
            }
        }

        match Sharks(self.configuration.recover_threshold).recover(&secret_shares) {
            Ok(secret) => Ok(RecoverGenSuccess {
                generation: current_generation,
                secret: UserSecret(secret),
                found_earlier_generations: previous_generation.is_some(),
            }),

            Err(_) => Err(RecoverGenError {
                error: RecoverError::Unsuccessful(vec![(
                    current_generation,
                    UnsuccessfulRecoverReason::ProtocolError,
                )]),
                retry: previous_generation,
            }),
        }
    }

    /// Executes phase 1 of recovery on a particular realm at a particular
    /// generation.
    ///
    /// If the generation number is given as `None`, tries the latest
    /// generation present on the realm.
    #[instrument(level = "trace", skip(self), ret, err(level = "trace", Debug))]
    async fn recover1(
        &self,
        realm: &Realm,
        generation: Option<GenerationNumber>,
        pin: &Pin,
    ) -> Result<Recover1Success, RecoverGenError> {
        let blinded_pin = OprfClient::blind(&pin.0, &mut OsRng).expect("voprf blinding error");

        let recover1_request = self.make_request(
            realm,
            SecretsRequest::Recover1(Recover1Request {
                generation,
                blinded_pin: blinded_pin.message,
            }),
        );

        // This is a verbose way to copy some fields out to this outer scope.
        // It helps avoid having to process these fields at a high level of
        // indentation.
        struct OkResponse {
            generation: GenerationNumber,
            blinded_oprf_pin: OprfBlindedResult,
            masked_tgk_share: MaskedTgkShare,
            previous_generation: Option<GenerationNumber>,
        }
        let OkResponse {
            generation,
            blinded_oprf_pin,
            masked_tgk_share,
            previous_generation,
        } = match recover1_request.await {
            Err(RequestError::HttpError(err)) => {
                return Err(RecoverGenError {
                    error: RecoverError::NetworkError(err),
                    retry: None,
                })
            }
            Err(RequestError::DeserializationError(_))
            | Err(RequestError::SerializationError(_)) => todo!(),
            Err(RequestError::HttpStatus(_status)) => todo!(),
            Err(RequestError::Unavailable) => todo!(),
            Err(RequestError::InvalidAuth) => {
                return Err(RecoverGenError {
                    error: RecoverError::InvalidAuth,
                    retry: None,
                })
            }

            Ok(SecretsResponse::Recover1(rr)) => match rr {
                Recover1Response::Ok {
                    generation,
                    blinded_oprf_pin,
                    masked_tgk_share,
                    previous_generation,
                } => OkResponse {
                    generation,
                    blinded_oprf_pin,
                    masked_tgk_share,
                    previous_generation,
                },

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

            Ok(_) => todo!(),
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

        let tgk_share = TgkShare::try_from_masked(&masked_tgk_share, &oprf_pin).map_err(|_| {
            RecoverGenError {
                error: RecoverError::Unsuccessful(vec![(
                    generation,
                    UnsuccessfulRecoverReason::ProtocolError,
                )]),
                retry: previous_generation,
            }
        })?;

        Ok(Recover1Success {
            generation,
            tgk_share,
            previous_generation,
        })
    }

    /// Executes phase 2 of recovery on a particular realm at a particular
    /// generation.
    #[instrument(level = "trace", skip(self))]
    async fn recover2(
        &self,
        realm: &Realm,
        generation: GenerationNumber,
        tag: UnlockTag,
    ) -> Result<UserSecretShare, RecoverError> {
        let recover2_request = self.make_request(
            realm,
            SecretsRequest::Recover2(Recover2Request { generation, tag }),
        );

        match recover2_request.await {
            Err(RequestError::HttpError(err)) => Err(RecoverError::NetworkError(err)),
            Err(RequestError::DeserializationError(_))
            | Err(RequestError::SerializationError(_)) => todo!(),
            Err(RequestError::HttpStatus(_status)) => todo!(),
            Err(RequestError::Unavailable) => todo!(),
            Err(RequestError::InvalidAuth) => Err(RecoverError::InvalidAuth),

            Ok(SecretsResponse::Recover2(rr)) => match rr {
                Recover2Response::Ok(secret_share) => Ok(secret_share),
                Recover2Response::NotRegistered => Err(RecoverError::Unsuccessful(vec![(
                    generation,
                    UnsuccessfulRecoverReason::NotRegistered,
                )])),
                Recover2Response::BadUnlockTag => Err(RecoverError::Unsuccessful(vec![(
                    generation,
                    UnsuccessfulRecoverReason::FailedUnlock,
                )])),
            },
            Ok(_) => todo!(),
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
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    async fn delete_up_to(&self, up_to: Option<GenerationNumber>) -> Result<(), DeleteError> {
        let requests = self
            .configuration
            .realms
            .iter()
            .map(|realm| self.delete_on_realm(realm, up_to));

        // Use `join_all` instead of `try_join_all` so that a failed delete
        // request does not short-circuit other requests (which may still
        // succeed).
        join_all(requests).await.into_iter().collect()
    }

    /// Executes [`delete_up_to`](Self::delete_up_to) on a particular realm.
    #[instrument(level = "trace", skip(self), err(level = "trace", Debug))]
    async fn delete_on_realm(
        &self,
        realm: &Realm,
        up_to: Option<GenerationNumber>,
    ) -> Result<(), DeleteError> {
        let delete_result = self
            .make_request(realm, SecretsRequest::Delete(DeleteRequest { up_to }))
            .await;

        match delete_result {
            Err(RequestError::HttpError(err)) => Err(DeleteError::NetworkError(err)),
            Err(RequestError::DeserializationError(_))
            | Err(RequestError::SerializationError(_)) => todo!(),
            Err(RequestError::HttpStatus(_status)) => todo!(),
            Err(RequestError::Unavailable) => todo!(),
            Err(RequestError::InvalidAuth) => Err(DeleteError::InvalidAuth),

            Ok(SecretsResponse::Delete(dr)) => match dr {
                DeleteResponse::Ok => Ok(()),
            },
            Ok(_) => todo!(),
        }
    }
}

fn zip4<A, B, C, D>(
    a: A,
    b: B,
    c: C,
    d: D,
) -> impl Iterator<Item = (A::Item, B::Item, C::Item, D::Item)>
where
    A: IntoIterator,
    B: IntoIterator,
    C: IntoIterator,
    D: IntoIterator,
{
    zip(zip(a, b), zip(c, d)).map(|((a, b), (c, d))| (a, b, c, d))
}
