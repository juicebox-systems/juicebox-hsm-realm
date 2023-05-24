extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::trace;

use super::types::RecordId;
use juicebox_sdk_core::{
    marshalling,
    requests::{
        DeleteResponse, Recover1Response, Recover2Request, Recover2Response, Recover3Request,
        Recover3Response, Register1Response, Register2Request, Register2Response, SecretsRequest,
        SecretsResponse,
    },
    types::{
        MaskedTgkShare, OprfBlindedResult, OprfSeed, OprfServer, Policy, Salt, UnlockTag,
        UserSecretShare, OPRF_KEY_INFO,
    },
};

/// Persistent state for a particular user.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
enum RegistrationState {
    NotRegistered,
    Registered(Box<RegisteredState>),
    NoGuesses,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RegisteredState {
    oprf_seed: OprfSeed,
    salt: Salt,
    guess_count: u16,
    policy: Policy,
    masked_tgk_share: MaskedTgkShare,
    tag: UnlockTag,
    secret_share: UserSecretShare,
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

    user_record.registration_state = RegistrationState::Registered(Box::new(RegisteredState {
        oprf_seed: request.oprf_seed,
        salt: request.salt,
        guess_count: 0,
        policy: request.policy,
        masked_tgk_share: request.masked_tgk_share,
        tag: request.tag,
        secret_share: request.secret_share,
    }));

    (Register2Response::Ok, Some(user_record))
}

fn recover1(
    ctx: &AppContext,
    record_id: &RecordId,
    mut user_record: UserRecord,
) -> (Recover1Response, Option<UserRecord>) {
    trace!(hsm = ctx.hsm_name, ?record_id, "recover1 request",);

    match &user_record.registration_state {
        RegistrationState::Registered(state) if state.guess_count >= state.policy.num_guesses => {
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                "can't recover: out of guesses"
            );
            user_record.registration_state = RegistrationState::NoGuesses;
            (Recover1Response::NoGuesses, Some(user_record))
        }
        RegistrationState::Registered(state) => (
            Recover1Response::Ok {
                salt: state.salt.clone(),
            },
            None,
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

    let (oprf_seed, masked_tgk_share) = match &mut user_record.registration_state {
        RegistrationState::Registered(state) if state.guess_count >= state.policy.num_guesses => {
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                "can't recover: out of guesses"
            );
            user_record.registration_state = RegistrationState::NoGuesses;
            return (Recover2Response::NoGuesses, Some(user_record));
        }
        RegistrationState::Registered(state) => {
            state.guess_count += 1;
            (state.oprf_seed.clone(), state.masked_tgk_share.clone())
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

    let server = OprfServer::new_from_seed(oprf_seed.expose_secret(), OPRF_KEY_INFO)
        .expect("error constructing OprfServer");
    let blinded_oprf_result: OprfBlindedResult = server
        .blind_evaluate(&request.blinded_oprf_input.expose_secret())
        .into();

    trace!(?record_id, "recover2 completed");
    (
        Recover2Response::Ok {
            blinded_oprf_result,
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
        RegistrationState::Registered(state) if !bool::from(request.tag.ct_eq(&state.tag)) => {
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                "can't recover: bad unlock tag"
            );
            let guesses_remaining = state.policy.num_guesses - state.guess_count;
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
        RegistrationState::Registered(state) => {
            state.guess_count = 0;
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                "recovered secret share successfully"
            );
            (
                Recover3Response::Ok {
                    secret_share: state.secret_share.clone(),
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
            let res = register2(ctx, record_id, *req, user_record_in);
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

#[cfg(test)]
mod test {
    use juicebox_sdk_core::{
        requests::{
            DeleteResponse, Recover1Response, Recover2Request, Recover2Response, Recover3Request,
            Recover3Response, Register1Response, Register2Request, Register2Response,
        },
        types::{
            MaskedTgkShare, OprfBlindedInput, OprfBlindedResult, OprfSeed, Policy, Salt, UnlockTag,
            UserSecretShare,
        },
    };

    use crate::hsm::{
        app::{RegisteredState, RegistrationState, UserRecord},
        types::RecordId,
    };

    use super::{delete, recover1, recover2, recover3, register1, register2, AppContext};

    #[test]
    fn test_register1() {
        let response = register1(&AppContext { hsm_name: "test" }, &RecordId([0; 32]));
        assert_eq!(response, Register1Response::Ok)
    }

    #[test]
    fn test_register2() {
        let request = Register2Request {
            salt: salt(),
            oprf_seed: oprf_seed(),
            tag: unlock_tag(),
            masked_tgk_share: masked_tgk_share(),
            secret_share: user_secret_share(),
            policy: policy(),
        };
        let user_record_in = UserRecord::new();
        let expected_user_record_out = registered_record(0);
        let (response, user_record_out) = register2(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            request,
            user_record_in,
        );
        assert_eq!(response, Register2Response::Ok);
        assert_eq!(user_record_out, Some(expected_user_record_out));
    }

    #[test]
    fn test_recover1_registered() {
        let user_record_in = registered_record(0);
        let (response, user_record_out) = recover1(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            user_record_in,
        );
        assert_eq!(response, Recover1Response::Ok { salt: salt() });
        assert!(user_record_out.is_none());
    }

    #[test]
    fn test_recover1_no_guesses() {
        let user_record_in = UserRecord {
            registration_state: RegistrationState::NoGuesses,
        };
        let (response, user_record_out) = recover1(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            user_record_in,
        );
        assert_eq!(response, Recover1Response::NoGuesses);
        assert!(user_record_out.is_none());
    }

    #[test]
    fn test_recover1_not_registered() {
        let user_record_in = UserRecord {
            registration_state: RegistrationState::NotRegistered,
        };
        let (response, user_record_out) = recover1(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            user_record_in,
        );
        assert_eq!(response, Recover1Response::NotRegistered);
        assert!(user_record_out.is_none());
    }

    #[test]
    fn test_recover2_registered() {
        let request = Recover2Request {
            blinded_oprf_input: oprf_blinded_input(),
        };
        let user_record_in = registered_record(0);
        let expected_user_record_out = registered_record(1);
        let (response, user_record_out) = recover2(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            request,
            user_record_in,
        );
        assert_eq!(
            response,
            Recover2Response::Ok {
                blinded_oprf_result: oprf_blinded_result(),
                masked_tgk_share: masked_tgk_share()
            }
        );
        assert_eq!(user_record_out, Some(expected_user_record_out));
    }

    #[test]
    fn test_recover2_no_guesses() {
        let request = Recover2Request {
            blinded_oprf_input: oprf_blinded_input(),
        };
        let user_record_in = UserRecord {
            registration_state: RegistrationState::NoGuesses,
        };
        let (response, user_record_out) = recover2(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            request,
            user_record_in,
        );
        assert_eq!(response, Recover2Response::NoGuesses);
        assert!(user_record_out.is_none());
    }

    #[test]
    fn test_recover2_not_registered() {
        let request = Recover2Request {
            blinded_oprf_input: oprf_blinded_input(),
        };
        let user_record_in = UserRecord {
            registration_state: RegistrationState::NotRegistered,
        };
        let (response, user_record_out) = recover2(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            request,
            user_record_in,
        );
        assert_eq!(response, Recover2Response::NotRegistered);
        assert!(user_record_out.is_none());
    }

    #[test]
    fn test_recover3_correct_unlock_tag() {
        let request = Recover3Request { tag: unlock_tag() };
        let user_record_in = registered_record(1);
        let expected_user_record_out = registered_record(0);
        let (response, user_record_out) = recover3(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            request,
            user_record_in,
        );
        assert_eq!(
            response,
            Recover3Response::Ok {
                secret_share: user_secret_share()
            }
        );
        assert_eq!(user_record_out, Some(expected_user_record_out));
    }

    #[test]
    fn test_recover3_wrong_unlock_tag_guesses_remaining() {
        let request = Recover3Request {
            tag: UnlockTag::from([5; 32]),
        };
        let user_record_in = registered_record(1);
        let (response, user_record_out) = recover3(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            request,
            user_record_in,
        );
        assert_eq!(
            response,
            Recover3Response::BadUnlockTag {
                guesses_remaining: 1
            }
        );
        assert!(user_record_out.is_none());
    }

    #[test]
    fn test_recover3_wrong_unlock_tag_no_guesses_remaining() {
        let request = Recover3Request {
            tag: UnlockTag::from([5; 32]),
        };
        let user_record_in = registered_record(2);
        let expected_user_record_out = UserRecord {
            registration_state: RegistrationState::NoGuesses,
        };
        let (response, user_record_out) = recover3(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            request,
            user_record_in,
        );
        assert_eq!(
            response,
            Recover3Response::BadUnlockTag {
                guesses_remaining: 0
            }
        );
        assert_eq!(user_record_out, Some(expected_user_record_out));
    }

    #[test]
    fn test_recover3_no_guesses() {
        let request = Recover3Request { tag: unlock_tag() };
        let user_record_in = UserRecord {
            registration_state: RegistrationState::NoGuesses,
        };
        let (response, user_record_out) = recover3(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            request,
            user_record_in,
        );
        assert_eq!(response, Recover3Response::NoGuesses);
        assert!(user_record_out.is_none());
    }

    #[test]
    fn test_recover3_not_registered() {
        let request = Recover3Request { tag: unlock_tag() };
        let user_record_in = UserRecord {
            registration_state: RegistrationState::NotRegistered,
        };
        let (response, user_record_out) = recover3(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            request,
            user_record_in,
        );
        assert_eq!(response, Recover3Response::NotRegistered);
        assert!(user_record_out.is_none());
    }

    #[test]
    fn test_delete() {
        let user_record_in = registered_record(0);
        let expected_user_record_out = UserRecord {
            registration_state: RegistrationState::NotRegistered,
        };
        let (response, user_record_out) = delete(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            user_record_in,
        );
        assert_eq!(response, DeleteResponse::Ok);
        assert_eq!(user_record_out, Some(expected_user_record_out));
    }

    fn registered_record(guess_count: u16) -> UserRecord {
        UserRecord {
            registration_state: RegistrationState::Registered(Box::new(RegisteredState {
                oprf_seed: oprf_seed(),
                salt: salt(),
                guess_count,
                policy: policy(),
                masked_tgk_share: masked_tgk_share(),
                tag: unlock_tag(),
                secret_share: user_secret_share(),
            })),
        }
    }

    fn oprf_seed() -> OprfSeed {
        OprfSeed::from([2; 32])
    }

    fn oprf_blinded_input() -> OprfBlindedInput {
        OprfBlindedInput::from([
            0xe6, 0x92, 0xd0, 0xf3, 0x22, 0x96, 0xe9, 0x01, 0x97, 0xf4, 0x55, 0x7c, 0x74, 0x42,
            0x99, 0xd2, 0x3e, 0x1d, 0xc2, 0x6c, 0xda, 0x1a, 0xea, 0x5a, 0xa7, 0x54, 0xb4, 0x6c,
            0xee, 0x59, 0x55, 0x7c,
        ])
    }

    fn oprf_blinded_result() -> OprfBlindedResult {
        OprfBlindedResult::from([
            0xee, 0x8d, 0x91, 0x39, 0xf7, 0x3e, 0xe8, 0x5, 0x99, 0xb7, 0x19, 0x4a, 0x15, 0x57,
            0x2d, 0x88, 0x38, 0xb9, 0x31, 0x41, 0x13, 0x29, 0x99, 0x57, 0xa7, 0x48, 0x25, 0x1a,
            0xf9, 0x6a, 0x76, 0x27,
        ])
    }

    fn salt() -> Salt {
        Salt::from([1; 32])
    }

    fn masked_tgk_share() -> MaskedTgkShare {
        MaskedTgkShare::try_from(vec![1; 33]).unwrap()
    }
    fn unlock_tag() -> UnlockTag {
        UnlockTag::from([3; 32])
    }

    fn user_secret_share() -> UserSecretShare {
        UserSecretShare::try_from(vec![1; 146]).unwrap()
    }

    fn policy() -> Policy {
        Policy { num_guesses: 2 }
    }
}
