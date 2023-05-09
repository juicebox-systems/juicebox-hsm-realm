extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::trace;

use super::types::RecordId;
use loam_sdk_core::{
    marshalling,
    requests::{
        DeleteResponse, Recover1Response, Recover2Request, Recover2Response, Recover3Request,
        Recover3Response, Register1Response, Register2Request, Register2Response, SecretsRequest,
        SecretsResponse,
    },
    types::{
        MaskedTgkShare, OprfBlindedResult, OprfKey, OprfServer, Policy, Salt, UnlockTag,
        UserSecretShare,
    },
};

/// Persistent state for a particular user.
#[derive(Debug, Serialize, Deserialize)]
struct UserRecord {
    registration_state: RegistrationState,
    // TODO: audit log
}

impl UserRecord {
    fn new() -> Self {
        Self {
            registration_state: RegistrationState::NotRegistered,
        }
    }
}

/// Persistent state for a particular registration of a particular user.
#[derive(Debug, Serialize, Deserialize)]
enum RegistrationState {
    NotRegistered,
    Registered {
        oprf_key: OprfKey,
        salt: Salt,
        guess_count: u16,
        policy: Policy,
        masked_tgk_share: MaskedTgkShare,
        tag: UnlockTag,
        secret_share: UserSecretShare,
    },
    NoGuesses,
}

fn register1(ctx: &AppContext, record_id: &RecordId) -> Register1Response {
    trace!(hsm = ctx.hsm_name, ?record_id, "register1 request",);
    Register1Response::Ok
}

fn register2(
    ctx: &AppContext,
    record_id: &RecordId,
    request: Register2Request,
    mut user_record: UserRecord,
) -> (Register2Response, Option<UserRecord>) {
    trace!(hsm = ctx.hsm_name, ?record_id, "register2 request",);

    user_record.registration_state = RegistrationState::Registered {
        oprf_key: request.oprf_key,
        salt: request.salt,
        guess_count: 0,
        policy: request.policy,
        masked_tgk_share: request.masked_tgk_share,
        tag: request.tag,
        secret_share: request.secret_share,
    };

    (Register2Response::Ok, Some(user_record))
}

fn recover1(
    ctx: &AppContext,
    record_id: &RecordId,
    mut user_record: UserRecord,
) -> (Recover1Response, Option<UserRecord>) {
    trace!(hsm = ctx.hsm_name, ?record_id, "recover1 request",);

    match &user_record.registration_state {
        RegistrationState::Registered {
            guess_count,
            policy,
            ..
        } if *guess_count >= policy.num_guesses => {
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                "can't recover: out of guesses"
            );
            user_record.registration_state = RegistrationState::NoGuesses;
            (Recover1Response::NoGuesses, Some(user_record))
        }
        RegistrationState::Registered { salt, .. } => (
            Recover1Response::Ok { salt: salt.clone() },
            Some(user_record),
        ),
        RegistrationState::NoGuesses => {
            trace!(hsm = ctx.hsm_name, ?record_id, "can't recover: no guesses");
            (Recover1Response::NoGuesses, None)
        }
        RegistrationState::NotRegistered => {
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                "can't recover: not registered"
            );
            (Recover1Response::NotRegistered, None)
        }
    }
}

fn recover2(
    ctx: &AppContext,
    record_id: &RecordId,
    request: Recover2Request,
    mut user_record: UserRecord,
) -> (Recover2Response, Option<UserRecord>) {
    trace!(hsm = ctx.hsm_name, ?record_id, "recover2 request");

    let (oprf_key, masked_tgk_share) = match &mut user_record.registration_state {
        RegistrationState::Registered {
            guess_count,
            policy,
            ..
        } if *guess_count >= policy.num_guesses => {
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                "can't recover: out of guesses"
            );
            user_record.registration_state = RegistrationState::NoGuesses;
            return (Recover2Response::NoGuesses, Some(user_record));
        }
        RegistrationState::Registered {
            guess_count,
            oprf_key,
            masked_tgk_share,
            ..
        } => {
            *guess_count += 1;
            (oprf_key.clone(), masked_tgk_share.clone())
        }
        RegistrationState::NoGuesses => {
            trace!(hsm = ctx.hsm_name, ?record_id, "can't recover: no guesses");
            return (Recover2Response::NoGuesses, None);
        }
        RegistrationState::NotRegistered => {
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                "can't recover: not registered"
            );
            return (Recover2Response::NotRegistered, None);
        }
    };

    let server =
        OprfServer::new_with_key(oprf_key.expose_secret()).expect("error constructing OprfServer");
    let blinded_oprf_pin: OprfBlindedResult = server.blind_evaluate(&request.blinded_pin);

    trace!(?record_id, "recover2 completed");
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
    trace!(hsm = ctx.hsm_name, ?record_id, "recover3 request");

    match &mut user_record.registration_state {
        RegistrationState::NotRegistered => {
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                "can't recover: not registered"
            );
            (Recover3Response::NotRegistered, None)
        }
        RegistrationState::Registered {
            tag,
            policy,
            guess_count,
            ..
        } if !bool::from(request.tag.ct_eq(tag)) => {
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                "can't recover: bad unlock tag"
            );
            let guesses_remaining = policy.num_guesses - *guess_count;
            let mut user_record_out = None;

            if guesses_remaining == 0 {
                user_record.registration_state = RegistrationState::NoGuesses;
                user_record_out = Some(user_record);
            }

            (
                Recover3Response::BadUnlockTag { guesses_remaining },
                user_record_out,
            )
        }
        RegistrationState::NoGuesses => {
            trace!(hsm = ctx.hsm_name, ?record_id, "can't recover: no guesses");
            (Recover3Response::NoGuesses, None)
        }
        RegistrationState::Registered {
            guess_count,
            secret_share,
            ..
        } => {
            *guess_count = 0;
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                "recovered secret share successfully"
            );
            (
                Recover3Response::Ok {
                    secret_share: secret_share.clone(),
                },
                Some(user_record),
            )
        }
    }
}

fn delete(
    ctx: &AppContext,
    record_id: &RecordId,
    mut user_record: UserRecord,
) -> (DeleteResponse, Option<UserRecord>) {
    trace!(hsm = ctx.hsm_name, ?record_id, "delete request");

    user_record.registration_state = RegistrationState::NotRegistered;
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
            let res = register1(ctx, record_id);
            (SecretsResponse::Register1(res), None)
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
        SecretsRequest::Delete => {
            let res = delete(ctx, record_id, user_record_in);
            (SecretsResponse::Delete(res.0), res.1)
        }
    };
    let rc = user_record_out.map(|u| RecordChange::Update(marshalling::to_vec(&u).expect("TODO")));
    (result, rc)
}
