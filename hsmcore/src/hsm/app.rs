extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::trace;

use super::types::RecordId;
use loam_sdk_core::{
    marshalling,
    requests::{
        DeleteRequest, DeleteResponse, Recover1Response, Recover2Request, Recover2Response,
        Recover3Request, Recover3Response, Register1Response, Register2Request, Register2Response,
        SecretsRequest, SecretsResponse,
    },
    types::{
        GenerationNumber, MaskedTgkShare, OprfBlindedResult, OprfKey, OprfServer, Policy, Salt,
        UnlockTag, UserSecretShare,
    },
};

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
struct GenerationRecord {
    oprf_key: OprfKey,
    salt: Salt,
    guess_count: u16,
    policy: Policy,
    masked_tgk_share: MaskedTgkShare,
    tag: UnlockTag,
    secret_share: UserSecretShare,
}

fn register1(
    ctx: &AppContext,
    record_id: &RecordId,
    user_record: UserRecord,
) -> (Register1Response, Option<UserRecord>) {
    trace!(hsm = ctx.hsm_name, ?record_id, "register1 request",);

    (
        Register1Response {
            next_generation_number: user_record.first_available_generation,
        },
        Some(user_record),
    )
}

fn register2(
    ctx: &AppContext,
    record_id: &RecordId,
    request: Register2Request,
    mut user_record: UserRecord,
) -> (Register2Response, Option<UserRecord>) {
    trace!(
        hsm = ctx.hsm_name,
        ?record_id,
        generation = %request.generation,
        "register2 request",
    );

    if request.generation < user_record.first_available_generation {
        trace!(
            hsm = ctx.hsm_name,
            ?record_id,
            generation = %request.generation,
            first_available_generation = %user_record.first_available_generation,
            "can't re-register generation",
        );
        return (Register2Response::AlreadyRegistered, None);
    }

    match request.generation.0.checked_add(1) {
        None => return (Register2Response::BadGeneration, None),
        Some(avail) => {
            user_record.first_available_generation = GenerationNumber(avail);
        }
    }

    // Delete older generations.
    user_record.generations.clear();

    user_record.generations.insert(
        request.generation,
        GenerationRecord {
            oprf_key: request.oprf_key,
            salt: request.salt,
            guess_count: 0,
            policy: request.policy,
            masked_tgk_share: request.masked_tgk_share,
            tag: request.tag,
            secret_share: request.secret_share,
        },
    );

    (Register2Response::Ok, Some(user_record))
}

fn recover1(
    ctx: &AppContext,
    record_id: &RecordId,
    user_record: UserRecord,
) -> (Recover1Response, Option<UserRecord>) {
    trace!(hsm = ctx.hsm_name, ?record_id, "recover1 request",);

    match user_record.generations.last_key_value() {
        Some((generation, record)) => (
            Recover1Response::Ok {
                generation: *generation,
                salt: record.salt.clone(),
            },
            Some(user_record),
        ),
        None => (Recover1Response::NotRegistered, None),
    }
}

fn recover2(
    ctx: &AppContext,
    record_id: &RecordId,
    request: Recover2Request,
    mut user_record: UserRecord,
) -> (Recover2Response, Option<UserRecord>) {
    trace!(
        hsm = ctx.hsm_name,
        ?record_id,
        %request.generation,
        "recover2 request"
    );

    let (oprf_key, masked_tgk_share) = match user_record.generations.get_mut(&request.generation) {
        Some(record) => {
            if record.guess_count >= record.policy.num_guesses {
                trace!(
                    hsm = ctx.hsm_name,
                    ?record_id,
                    %request.generation,
                    "can't recover: out of guesses"
                );
                return (Recover2Response::NoGuesses, None);
            }
            record.guess_count += 1;
            (record.oprf_key.clone(), record.masked_tgk_share.clone())
        }
        None => {
            trace!(hsm = ctx.hsm_name, ?record_id, ?request.generation, "can't recover: not registered");
            return (Recover2Response::NotRegistered, None);
        }
    };

    let server =
        OprfServer::new_with_key(oprf_key.expose_secret()).expect("error constructing OprfServer");
    let blinded_oprf_pin: OprfBlindedResult = server.blind_evaluate(&request.blinded_pin);

    trace!(?record_id, %request.generation, "recover2 completed");
    (
        Recover2Response::Ok {
            blinded_oprf_pin,
            masked_tgk_share,
        },
        Some(user_record),
    )
}

fn recover3(
    ctx: &AppContext,
    record_id: &RecordId,
    request: Recover3Request,
    mut user_record: UserRecord,
) -> (Recover3Response, Option<UserRecord>) {
    match user_record.generations.get_mut(&request.generation) {
        None => {
            trace!(hsm = ctx.hsm_name, ?record_id, %request.generation, "can't recover: not registered");
            (Recover3Response::NotRegistered, None)
        }
        Some(record) => {
            if !bool::from(request.tag.ct_eq(&record.tag)) {
                trace!(hsm = ctx.hsm_name, ?record_id, %request.generation, "can't recover: bad unlock tag");
                (
                    Recover3Response::BadUnlockTag {
                        guesses_remaining: record.policy.num_guesses - record.guess_count,
                    },
                    None,
                )
            } else {
                record.guess_count = 0;
                trace!(hsm = ctx.hsm_name, ?record_id, %request.generation, "recovered secret share successfully");
                (
                    Recover3Response::Ok(record.secret_share.clone()),
                    Some(user_record),
                )
            }
        }
    }
}

fn delete_generations(
    ctx: &AppContext,
    record_id: &RecordId,
    request: DeleteRequest,
    mut user_record: UserRecord,
) -> (DeleteResponse, Option<UserRecord>) {
    match request.up_to {
        // Remove from 0 up to and excluding generation.
        Some(generation) => {
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                %generation,
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
            trace!(hsm = ctx.hsm_name, ?record_id, "delete all generations");
            user_record.generations.clear();
        }
    }

    (DeleteResponse::Ok, Some(user_record))
}

pub enum RecordChange {
    Update(Vec<u8>),
}

pub struct AppContext<'a> {
    pub hsm_name: &'a str,
}

pub fn process(
    ctx: &AppContext,
    record_id: &RecordId,
    request: SecretsRequest,
    record_val: Option<&[u8]>,
) -> (SecretsResponse, Option<RecordChange>) {
    let user_record_in = match record_val {
        None => UserRecord::new(),
        Some(data) => marshalling::from_slice(data).expect("TODO"),
    };
    let (result, user_record_out) = match request {
        SecretsRequest::Register1 => {
            let res = register1(ctx, record_id, user_record_in);
            (SecretsResponse::Register1(res.0), res.1)
        }
        SecretsRequest::Register2(req) => {
            let res = register2(ctx, record_id, req, user_record_in);
            (SecretsResponse::Register2(res.0), res.1)
        }
        SecretsRequest::Recover1 => {
            let res = recover1(ctx, record_id, user_record_in);
            (SecretsResponse::Recover1(res.0), res.1)
        }
        SecretsRequest::Recover2(req) => {
            let res = recover2(ctx, record_id, req, user_record_in);
            (SecretsResponse::Recover2(res.0), res.1)
        }
        SecretsRequest::Recover3(req) => {
            let res = recover3(ctx, record_id, req, user_record_in);
            (SecretsResponse::Recover3(res.0), res.1)
        }
        SecretsRequest::Delete(req) => {
            let res = delete_generations(ctx, record_id, req, user_record_in);
            (SecretsResponse::Delete(res.0), res.1)
        }
    };
    let rc = user_record_out.map(|u| RecordChange::Update(marshalling::to_vec(&u).expect("TODO")));
    (result, rc)
}
