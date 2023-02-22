use super::types::{SecretsRequest, SecretsResponse};
use super::RealmKey;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt::{self, Debug};
use subtle::ConstantTimeEq;
use tracing::info;
use tracing::trace;

use super::super::types::{
    AuthToken, DeleteRequest, DeleteResponse, GenerationNumber, MaskedPgkShare, OprfBlindedInput,
    OprfBlindedResult, OprfCipherSuite, Policy, Recover1Request, Recover1Response, Recover2Request,
    Recover2Response, Register1Request, Register1Response, Register2Request, Register2Response,
    UnlockPassword, UserSecretShare,
};

type OprfServer = voprf::OprfServer<OprfCipherSuite>;

/// Persistent state for a particular user.
#[derive(Debug, Serialize, Deserialize)]
struct UserRecord {
    /// The user has never used a generation number greater than or equal to
    /// this one.
    first_available_generation: GenerationNumber,
    /// The user's registering and registered generations.
    generations: BTreeMap<GenerationNumber, GenerationRecord>,
    // TODO: audit log
}

impl UserRecord {
    fn new() -> Self {
        Self {
            first_available_generation: GenerationNumber(0),
            generations: BTreeMap::new(),
        }
    }
}

/// Persistent state for a particular generation of a particular user.
#[derive(Debug, Serialize, Deserialize)]
enum GenerationRecord {
    /// The record has gone through the first phase but not the second phase of
    /// registration. This is a stub record.
    Registering,
    /// The record has completed both phases of registration.
    Registered(RegisteredUserRecord),
}

/// Persistent state for a fully registered generation.
#[derive(Debug, Serialize, Deserialize)]
struct RegisteredUserRecord {
    guess_count: u16,
    policy: Policy,
    masked_pgk_share: MaskedPgkShare,
    password: UnlockPassword,
    secret_share: UserSecretShare,
}

/// A private root key used to derive keys for each user-generation's OPRF.
pub struct RootOprfKey([u8; 32]);

impl RootOprfKey {
    pub fn from(realm_key: &RealmKey) -> Self {
        // generated from /dev/random
        let salt = [
            0x26u8, 0x97, 0x33, 0x24, 0x75, 0xe3, 0x41, 0xb7, 0xee, 0x5c, 0x1c, 0x3e, 0x4d, 0x20,
            0xd0, 0xad, 0x9e, 0xf2, 0x6a, 0x2e, 0x55, 0x3b, 0x7b, 0x19, 0x1c, 0x94, 0x0d, 0xb2,
            0x2f, 0xd7, 0x3c, 0x10,
        ];
        let info = "oprf".as_bytes();
        let hk = Hkdf::<Sha256>::new(Some(&salt), &realm_key.0);
        let mut out = [0u8; 32];
        hk.expand(info, &mut out).unwrap();
        Self(out)
    }

    /// Compute the derived key used for the OPRF for a particular user and
    /// generation.
    fn user_generation_key(
        &self,
        user: &str,
        generation: GenerationNumber,
    ) -> digest::Output<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("failed to initialize HMAC");
        mac.update(user.as_bytes());
        mac.update(&[0u8]);
        mac.update(&generation.0.to_be_bytes());
        mac.finalize().into_bytes()
    }
}

impl Debug for RootOprfKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

fn register1(
    ctx: &AppContext,
    request: Register1Request,
    mut user_record: UserRecord,
) -> (Register1Response, Option<UserRecord>) {
    let Ok(user) = check_auth(&request.auth_token) else {
        return (Register1Response::InvalidAuth, None)
    };
    trace!(
        hsm = ctx.hsm_name,
        "register1 request for {user:?} at generation {}",
        request.generation
    );

    if request.generation < user_record.first_available_generation {
        trace!(
            hsm = ctx.hsm_name,
            "can't re-register {user:?} at generation {} (first available generation is {})",
            request.generation,
            user_record.first_available_generation
        );
        return (
            Register1Response::BadGeneration {
                first_available: user_record.first_available_generation,
            },
            None,
        );
    }

    match request.generation.0.checked_add(1) {
        None => {
            return (
                Register1Response::BadGeneration {
                    first_available: user_record.first_available_generation,
                },
                None,
            )
        }
        Some(avail) => {
            user_record.first_available_generation = GenerationNumber(avail);
        }
    }

    user_record
        .generations
        .insert(request.generation, GenerationRecord::Registering);

    let blinded_oprf_pin = evaluate_oprf(
        ctx.root_oprf_key,
        &user,
        request.generation,
        &request.blinded_pin,
    );
    trace!(
        hsm = ctx.hsm_name,
        "register1 {user:?} at generation {} completed",
        request.generation
    );
    (
        Register1Response::Ok { blinded_oprf_pin },
        Some(user_record),
    )
}

fn register2(
    ctx: &AppContext,
    request: Register2Request,
    mut user_record: UserRecord,
) -> (Register2Response, Option<UserRecord>) {
    let Ok(user) = check_auth(&request.auth_token) else {
        return (Register2Response::InvalidAuth,None)
    };
    trace!(
        hsm = ctx.hsm_name,
        "register2 request for {user:?} at generation {}",
        request.generation
    );

    match user_record.generations.get_mut(&request.generation) {
        None => {
            trace!(
                hsm = ctx.hsm_name,
                "can't do register2 for {user:?} at {}: haven't done register1",
                request.generation
            );
            (Register2Response::NotRegistering, None)
        }
        Some(GenerationRecord::Registered(_)) => {
            trace!(
                hsm = ctx.hsm_name,
                "can't do register2 for {user:?} at {}: already registered",
                request.generation
            );
            (Register2Response::AlreadyRegistered, None)
        }
        Some(record @ GenerationRecord::Registering) => {
            *record = GenerationRecord::Registered(RegisteredUserRecord {
                guess_count: 0,
                policy: request.policy,
                masked_pgk_share: request.masked_pgk_share,
                password: request.password,
                secret_share: request.secret_share,
            });
            let first_generation = *user_record.generations.first_key_value().unwrap().0;
            (
                Register2Response::Ok {
                    found_earlier_generations: first_generation < request.generation,
                },
                Some(user_record),
            )
        }
    }
}

fn recover1(
    ctx: &AppContext,
    request: Recover1Request,
    mut user_record: UserRecord,
) -> (Recover1Response, Option<UserRecord>) {
    let Ok(user) = check_auth(&request.auth_token) else {
        return (Recover1Response::InvalidAuth, None)
    };
    match request.generation {
        Some(generation) => trace!(?user, ?generation, "recover1 request"),
        None => trace!(
            hsm = ctx.hsm_name,
            ?user,
            "recover1 request at latest generation"
        ),
    };

    let mut iter = match request.generation {
        Some(generation) => user_record.generations.range_mut(..=generation),
        None => user_record.generations.range_mut(..),
    }
    .rev()
    .fuse();
    let generation = iter.next().map(|(num, record)| (*num, record));
    let previous_generation = iter.next().map(|(num, _)| *num);

    let (generation, masked_pgk_share) = match generation {
        None => {
            trace!(hsm = ctx.hsm_name,?user, ?request.generation,"can't recover: not registered");
            return (
                Recover1Response::NotRegistered {
                    generation: request.generation,
                    previous_generation,
                },
                None,
            );
        }

        Some((generation, GenerationRecord::Registering)) => {
            trace!(
                hsm = ctx.hsm_name,
                ?user,
                ?generation,
                "can't recover: partially registered"
            );
            return (
                Recover1Response::PartiallyRegistered {
                    generation,
                    previous_generation,
                },
                None,
            );
        }

        Some((generation, GenerationRecord::Registered(record))) => {
            if record.guess_count >= record.policy.num_guesses {
                trace!(
                    hsm = ctx.hsm_name,
                    ?user,
                    ?generation,
                    "can't recover: out of guesses"
                );
                return (
                    Recover1Response::NoGuesses {
                        generation,
                        previous_generation,
                    },
                    None,
                );
            }
            record.guess_count += 1;
            (generation, record.masked_pgk_share.clone())
        }
    };

    let blinded_oprf_pin =
        evaluate_oprf(ctx.root_oprf_key, &user, generation, &request.blinded_pin);
    info!(?user, ?generation, "recover1 completed");
    (
        Recover1Response::Ok {
            generation,
            blinded_oprf_pin,
            masked_pgk_share,
            previous_generation,
        },
        Some(user_record),
    )
}

fn recover2(
    ctx: &AppContext,
    request: Recover2Request,
    mut user_record: UserRecord,
) -> (Recover2Response, Option<UserRecord>) {
    let Ok(user) = check_auth(&request.auth_token) else {
        return (Recover2Response::InvalidAuth,None)
    };

    match user_record.generations.get_mut(&request.generation) {
        None | Some(GenerationRecord::Registering) => {
            trace!(hsm = ctx.hsm_name,?user, ?request.generation, "can't recover: not registered");
            (Recover2Response::NotRegistered, None)
        }
        Some(GenerationRecord::Registered(record)) => {
            if !bool::from(request.password.ct_eq(&record.password)) {
                trace!(hsm = ctx.hsm_name,?user,?request.generation, "can't recover: bad unlock password");
                (Recover2Response::BadUnlockPassword, None)
            } else {
                record.guess_count = 0;
                trace!(hsm = ctx.hsm_name,?user, ?request.generation, "recovered secret share successfully");
                (
                    Recover2Response::Ok(record.secret_share.clone()),
                    Some(user_record),
                )
            }
        }
    }
}

fn delete_generations(
    ctx: &AppContext,
    request: DeleteRequest,
    mut user_record: UserRecord,
) -> (DeleteResponse, Option<UserRecord>) {
    let Ok(user) = check_auth(&request.auth_token) else {
        return (DeleteResponse::InvalidAuth,None)
    };

    match request.up_to {
        // Remove from 0 up to and excluding generation.
        Some(generation) => {
            trace!(
                hsm = ctx.hsm_name,
                ?user,
                ?generation,
                "delete request up to generation"
            );
            while let Some(entry) = user_record.generations.first_entry() {
                if *entry.key() >= generation {
                    break;
                }
                entry.remove();
            }
        }

        // Remove all generations.
        None => {
            trace!(hsm = ctx.hsm_name, ?user, "delete all generations");
            user_record.generations.clear();
        }
    }

    (DeleteResponse::Ok, Some(user_record))
}

/// Returns the username if the auth token is valid, or an error otherwise.
/// TODO: is this being done here, or perhaps at the agent?
fn check_auth(token: &AuthToken) -> Result<String, ()> {
    if token.signature == "it's-a-me!" {
        Ok(token.user.clone())
    } else {
        trace!("failed auth for {:?}", token.user);
        Err(())
    }
}

/// Computes an OPRF for a user-generation.
fn evaluate_oprf(
    root_oprf_key: &RootOprfKey,
    user: &str,
    generation: GenerationNumber,
    blinded_pin: &OprfBlindedInput,
) -> OprfBlindedResult {
    let oprf_key = root_oprf_key.user_generation_key(user, generation);
    let oprf = OprfServer::new_from_seed(&oprf_key, &[ /* TODO: what is this "info" for? */])
        .expect("error constructing OprfServer");
    oprf.blind_evaluate(blinded_pin)
}

pub enum RecordChange {
    Update(Vec<u8>),
}

pub struct AppContext<'a> {
    pub root_oprf_key: &'a RootOprfKey,
    pub hsm_name: &'a str,
}

pub fn process(
    ctx: &AppContext,
    request: SecretsRequest,
    record_val: Option<Vec<u8>>,
) -> (SecretsResponse, Option<RecordChange>) {
    // TODO: how de we want to handle serialization/deserialization errors
    // TODO: value should be encrypted/decrypted somewhere

    let user_record_in = match record_val {
        None => UserRecord::new(),
        Some(data) => rmp_serde::from_slice(&data).unwrap(),
    };
    let (result, user_record_out) = match request {
        SecretsRequest::Register1(req) => {
            let res = register1(ctx, req, user_record_in);
            (SecretsResponse::Register1(res.0), res.1)
        }
        SecretsRequest::Register2(req) => {
            let res = register2(ctx, req, user_record_in);
            (SecretsResponse::Register2(res.0), res.1)
        }
        SecretsRequest::Recover1(req) => {
            let res = recover1(ctx, req, user_record_in);
            (SecretsResponse::Recover1(res.0), res.1)
        }
        SecretsRequest::Recover2(req) => {
            let res = recover2(ctx, req, user_record_in);
            (SecretsResponse::Recover2(res.0), res.1)
        }
        SecretsRequest::Delete(req) => {
            let res = delete_generations(ctx, req, user_record_in);
            (SecretsResponse::Delete(res.0), res.1)
        }
    };
    let rc = user_record_out.map(|u| RecordChange::Update(rmp_serde::to_vec(&u).unwrap()));
    (result, rc)
}
