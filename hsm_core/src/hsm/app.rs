extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;
use marshalling::{DeserializationError, SerializationError};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::trace;

use hsm_api::RecordId;
use juicebox_sdk_core::{
    oprf::{OprfBlindedResult, OprfPrivateKey, OprfPublicKeySignature, OprfSignedPublicKey},
    requests::{
        DeleteResponse, Recover1Response, Recover2Request, Recover2Response, Recover3Request,
        Recover3Response, Register1Response, Register2Request, Register2Response, SecretsRequest,
        SecretsResponse,
    },
    types::{
        to_be4, EncryptedUserSecret, EncryptedUserSecretCommitment, Policy, RegistrationVersion,
        UnlockKeyCommitment, UnlockKeyTag, UserSecretEncryptionKeyScalarShare,
    },
};
use juicebox_sdk_marshalling as marshalling;

/// Persistent state for a particular user.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum RegistrationState {
    NotRegistered,
    Registered(Box<RegisteredState>),
    NoGuesses,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RegisteredState {
    version: RegistrationVersion,
    oprf_private_key: OprfPrivateKey,
    oprf_public_key_signature: OprfPublicKeySignature,
    unlock_key_commitment: UnlockKeyCommitment,
    unlock_key_tag: UnlockKeyTag,
    user_secret_encryption_key_scalar_share: UserSecretEncryptionKeyScalarShare,
    encrypted_user_secret: EncryptedUserSecret,
    encrypted_user_secret_commitment: EncryptedUserSecretCommitment,
    guess_count: u16,
    policy: Policy,
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
        version: request.version,
        oprf_private_key: request.oprf_private_key,
        oprf_public_key_signature: request.oprf_public_key_signature,
        unlock_key_commitment: request.unlock_key_commitment,
        unlock_key_tag: request.unlock_key_tag,
        user_secret_encryption_key_scalar_share: request.encryption_key_scalar_share,
        encrypted_user_secret: request.encrypted_secret,
        encrypted_user_secret_commitment: request.encrypted_secret_commitment,
        guess_count: 0,
        policy: request.policy,
    }));

    (Register2Response::Ok, Some(user_record))
}

fn recover1(
    ctx: &AppContext,
    record_id: &RecordId,
    mut user_record: UserRecord,
) -> (Recover1Response, Option<UserRecord>) {
    trace!(hsm = ctx.hsm_name, ?record_id, "recover1 request",);

    // Some of these state's don't alter the user record. However that can leak
    // a result before the commit by examining the returned store delta. For
    // those cases we return the UserRecord unchanged so that there's a write
    // either way. As the leaf is encrypted with a random nonce, the externalized
    // leaf value will change even when the UserRecord has not.
    // This applies to recover2 and 3 as well.
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
                version: state.version.clone(),
            },
            Some(user_record),
        ),
        RegistrationState::NoGuesses => {
            trace!(hsm = ctx.hsm_name, ?record_id, "can't recover: no guesses");
            (Recover1Response::NoGuesses, Some(user_record))
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

    let (
        oprf_public_key_signature,
        oprf_private_key,
        unlock_key_commitment,
        num_guesses,
        guess_count,
    ) = match &mut user_record.registration_state {
        RegistrationState::Registered(state) if state.version != request.version => {
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                "can't recover: wrong version"
            );
            return (Recover2Response::VersionMismatch, Some(user_record));
        }
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
            (
                state.oprf_public_key_signature.clone(),
                state.oprf_private_key.clone(),
                state.unlock_key_commitment.clone(),
                state.policy.num_guesses,
                state.guess_count,
            )
        }
        RegistrationState::NoGuesses => {
            trace!(hsm = ctx.hsm_name, ?record_id, "can't recover: no guesses");
            return (Recover2Response::NoGuesses, Some(user_record));
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

    let oprf_blinded_result =
        OprfBlindedResult::new(&oprf_private_key, &request.oprf_blinded_input);

    trace!(?record_id, "recover2 completed");
    (
        Recover2Response::Ok {
            oprf_signed_public_key: Box::from(OprfSignedPublicKey {
                public_key: oprf_private_key.public_key(),
                signature: oprf_public_key_signature.clone(),
            }),
            oprf_blinded_result: Box::from(oprf_blinded_result),
            unlock_key_commitment,
            num_guesses,
            guess_count,
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
        RegistrationState::Registered(state) if state.version != request.version => {
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                "can't recover: wrong version"
            );
            (Recover3Response::VersionMismatch, Some(user_record))
        }
        RegistrationState::Registered(state)
            if !bool::from(request.unlock_key_tag.ct_eq(&state.unlock_key_tag)) =>
        {
            trace!(
                hsm = ctx.hsm_name,
                ?record_id,
                "can't recover: bad unlock tag"
            );
            let guesses_remaining = state.policy.num_guesses - state.guess_count;

            if guesses_remaining == 0 {
                user_record.registration_state = RegistrationState::NoGuesses;
            }

            (
                Recover3Response::BadUnlockKeyTag { guesses_remaining },
                Some(user_record),
            )
        }
        RegistrationState::NoGuesses => {
            trace!(hsm = ctx.hsm_name, ?record_id, "can't recover: no guesses");
            (Recover3Response::NoGuesses, Some(user_record))
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
                    encrypted_secret: state.encrypted_user_secret.clone(),
                    encryption_key_scalar_share: state
                        .user_secret_encryption_key_scalar_share
                        .clone(),
                    encrypted_secret_commitment: state.encrypted_user_secret_commitment.clone(),
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
        Some(data) => unmarshal_user_record(data).expect("TODO"),
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
    let rc = user_record_out.map(|u| RecordChange::Update(marshal_user_record(&u).expect("TODO")));
    (result, rc)
}

// A serialized NoGuesses is very small compared to a Registered. When the leaf
// changes from Registered to NoGuesses, the size of the leaf can leak this
// state before the change is committed. We pad the leaf to this size to hide
// that side channel. There's no need to pad NotRegistered, as the only way that
// gets written is with the delete call. This size includes the bytes needed to
// store the size in the trailer.
const SERIALIZED_RECORD_SIZE: usize = 700;
const TRAILER_LEN: usize = u32::BITS as usize / 8;

fn marshal_user_record(u: &UserRecord) -> Result<Vec<u8>, SerializationError> {
    let mut s = marshalling::to_vec(u)?;
    let should_pad = match u.registration_state {
        RegistrationState::NotRegistered => false,
        RegistrationState::Registered(_) => true,
        RegistrationState::NoGuesses => true,
    };

    // The actual length is stored at the end of the serialized state.
    // The length is a big endian encoded u32.
    assert!(s.len() < SERIALIZED_RECORD_SIZE - TRAILER_LEN);
    if should_pad {
        s.resize(SERIALIZED_RECORD_SIZE - TRAILER_LEN, 0);
    }
    s.extend_from_slice(&to_be4(s.len()));
    Ok(s)
}

fn unmarshal_user_record(padded: &[u8]) -> Result<UserRecord, DeserializationError> {
    let padded_len = padded.len();
    if padded_len < TRAILER_LEN {
        return Err(DeserializationError(format!(
            "user record data is too small, only got {padded_len} bytes",
        )));
    }
    if padded.len() > SERIALIZED_RECORD_SIZE {
        return Err(DeserializationError(format!(
            "user record data is too large. got {padded_len} bytes, but \
            should be no more than {SERIALIZED_RECORD_SIZE}",
        )));
    }
    let trailer = &padded[padded_len - TRAILER_LEN..];
    let data_len: usize = (u32::from_be_bytes(trailer.try_into().unwrap()))
        .try_into()
        .unwrap();
    let limit = padded_len - TRAILER_LEN;
    if data_len > limit {
        return Err(DeserializationError(format!(
            "embedded length of {data_len} can't be larger than the {limit} bytes present",
        )));
    }
    marshalling::from_slice(&padded[..data_len])
}

#[cfg(test)]
mod tests {
    use juicebox_sdk_core::{
        oprf::{
            OprfBlindedInput, OprfBlindedResult, OprfPrivateKey, OprfPublicKeySignature,
            OprfSignedPublicKey, OprfVerifyingKey,
        },
        requests::{
            DeleteResponse, Recover1Response, Recover2Request, Recover2Response, Recover3Request,
            Recover3Response, Register1Response, Register2Request, Register2Response,
        },
        types::{
            to_be4, EncryptedUserSecret, EncryptedUserSecretCommitment, Policy,
            RegistrationVersion, SecretBytesArray, UnlockKeyCommitment, UnlockKeyTag,
            UserSecretEncryptionKeyScalarShare,
        },
    };

    use super::{delete, recover1, recover2, recover3, register1, register2, AppContext};
    use crate::hsm::app::{
        marshal_user_record, unmarshal_user_record, RegisteredState, RegistrationState, UserRecord,
        SERIALIZED_RECORD_SIZE, TRAILER_LEN,
    };
    use hsm_api::RecordId;

    #[test]
    fn test_user_record_marshalling() {
        let mut registered = registered_record(u16::MAX);
        let RegistrationState::Registered(ref mut state) = registered.registration_state else { panic!("unexpected registration state") };
        state.policy.num_guesses = u16::MAX;

        let unpadded = juicebox_sdk_marshalling::to_vec(&registered).unwrap();
        println!(
            "unpadded length {}, SERIALIZED_RECORD_SIZE: {SERIALIZED_RECORD_SIZE}",
            unpadded.len()
        );
        assert!(unpadded.len() < SERIALIZED_RECORD_SIZE - TRAILER_LEN);
        assert!(SERIALIZED_RECORD_SIZE - TRAILER_LEN - unpadded.len() < 32);

        let s = marshal_user_record(&registered).unwrap();
        assert_eq!(SERIALIZED_RECORD_SIZE, s.len());
        let d = unmarshal_user_record(&s).unwrap();
        assert_eq!(d, registered);

        let no_guesses = UserRecord {
            registration_state: RegistrationState::NoGuesses,
        };
        let s = marshal_user_record(&no_guesses).unwrap();
        assert_eq!(SERIALIZED_RECORD_SIZE, s.len());
        let d = unmarshal_user_record(&s).unwrap();
        assert_eq!(d, no_guesses);

        let not_registered = UserRecord {
            registration_state: RegistrationState::NotRegistered,
        };
        let s = marshal_user_record(&not_registered).unwrap();
        assert_ne!(SERIALIZED_RECORD_SIZE, s.len());
        let d = unmarshal_user_record(&s).unwrap();
        assert_eq!(d, not_registered);
    }

    #[test]
    fn test_user_record_marshalling_errors() {
        assert_eq!(
            "Deserialization error: user record data is too small, only got 0 bytes",
            unmarshal_user_record(&[]).unwrap_err().to_string()
        );
        let mut big: Vec<u8> = vec![0u8; SERIALIZED_RECORD_SIZE + 1];
        assert_eq!("Deserialization error: user record data is too large. got 701 bytes, but should be no more than 700", unmarshal_user_record(&big).unwrap_err().to_string());

        big[SERIALIZED_RECORD_SIZE - 4..SERIALIZED_RECORD_SIZE]
            .copy_from_slice(&to_be4(SERIALIZED_RECORD_SIZE + 1));
        assert_eq!(
            "Deserialization error: embedded length of 701 can't be larger than the 696 bytes present",
            unmarshal_user_record(&big[..SERIALIZED_RECORD_SIZE])
                .unwrap_err()
                .to_string()
        );
    }

    #[test]
    fn test_register1() {
        let response = register1(&AppContext { hsm_name: "test" }, &RecordId([0; 32]));
        assert_eq!(response, Register1Response::Ok)
    }

    #[test]
    fn test_register2() {
        let request = Register2Request {
            version: version(),
            oprf_private_key: oprf_private_key(),
            oprf_public_key_signature: oprf_public_key_signature(),
            unlock_key_commitment: unlock_key_commitment(),
            unlock_key_tag: unlock_key_tag(),
            encryption_key_scalar_share: user_secret_encryption_key_scalar_share(),
            encrypted_secret: encrypted_user_secret(),
            encrypted_secret_commitment: encrypted_user_secret_commitment(),
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
            user_record_in.clone(),
        );
        assert_eq!(response, Recover1Response::Ok { version: version() });
        assert_eq!(Some(user_record_in), user_record_out);
    }

    #[test]
    fn test_recover1_no_guesses() {
        let user_record_in = UserRecord {
            registration_state: RegistrationState::NoGuesses,
        };
        let (response, user_record_out) = recover1(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            user_record_in.clone(),
        );
        assert_eq!(response, Recover1Response::NoGuesses);
        assert_eq!(Some(user_record_in), user_record_out);
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
            version: version(),
            oprf_blinded_input: oprf_blinded_input(),
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
                oprf_signed_public_key: Box::new(oprf_signed_public_key()),
                oprf_blinded_result: Box::new(oprf_blinded_result()),
                unlock_key_commitment: unlock_key_commitment(),
                num_guesses: 2,
                guess_count: 1,
            }
        );
        assert_eq!(user_record_out, Some(expected_user_record_out));
    }

    #[test]
    fn test_recover2_wrong_version() {
        let request = Recover2Request {
            version: RegistrationVersion::from([1; 16]),
            oprf_blinded_input: oprf_blinded_input(),
        };
        let user_record_in = registered_record(0);
        let (response, user_record_out) = recover2(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            request,
            user_record_in.clone(),
        );
        assert_eq!(response, Recover2Response::VersionMismatch,);
        assert_eq!(Some(user_record_in), user_record_out);
    }

    #[test]
    fn test_recover2_no_guesses() {
        let request = Recover2Request {
            version: version(),
            oprf_blinded_input: oprf_blinded_input(),
        };
        let user_record_in = UserRecord {
            registration_state: RegistrationState::NoGuesses,
        };
        let (response, user_record_out) = recover2(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            request,
            user_record_in.clone(),
        );
        assert_eq!(response, Recover2Response::NoGuesses);
        assert_eq!(Some(user_record_in), user_record_out);
    }

    #[test]
    fn test_recover2_not_registered() {
        let request = Recover2Request {
            version: version(),
            oprf_blinded_input: oprf_blinded_input(),
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
        let request = Recover3Request {
            version: version(),
            unlock_key_tag: unlock_key_tag(),
        };
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
                encrypted_secret: encrypted_user_secret(),
                encrypted_secret_commitment: encrypted_user_secret_commitment(),
                encryption_key_scalar_share: user_secret_encryption_key_scalar_share(),
            }
        );
        assert_eq!(user_record_out, Some(expected_user_record_out));
    }

    #[test]
    fn test_recover3_wrong_version() {
        let request = Recover3Request {
            version: RegistrationVersion::from([1; 16]),
            unlock_key_tag: unlock_key_tag(),
        };
        let user_record_in = registered_record(0);
        let (response, user_record_out) = recover3(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            request,
            user_record_in.clone(),
        );
        assert_eq!(response, Recover3Response::VersionMismatch,);
        assert_eq!(Some(user_record_in), user_record_out);
    }

    #[test]
    fn test_recover3_wrong_unlock_tag_guesses_remaining() {
        let request = Recover3Request {
            version: version(),
            unlock_key_tag: UnlockKeyTag::from([5; 16]),
        };
        let user_record_in = registered_record(1);
        let (response, user_record_out) = recover3(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            request,
            user_record_in.clone(),
        );
        assert_eq!(
            response,
            Recover3Response::BadUnlockKeyTag {
                guesses_remaining: 1
            }
        );
        assert_eq!(Some(user_record_in), user_record_out);
    }

    #[test]
    fn test_recover3_wrong_unlock_tag_no_guesses_remaining() {
        let request = Recover3Request {
            version: version(),
            unlock_key_tag: UnlockKeyTag::from([5; 16]),
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
            Recover3Response::BadUnlockKeyTag {
                guesses_remaining: 0
            }
        );
        assert_eq!(user_record_out, Some(expected_user_record_out));
    }

    #[test]
    fn test_recover3_no_guesses() {
        let request = Recover3Request {
            version: version(),
            unlock_key_tag: unlock_key_tag(),
        };
        let user_record_in = UserRecord {
            registration_state: RegistrationState::NoGuesses,
        };
        let (response, user_record_out) = recover3(
            &AppContext { hsm_name: "test" },
            &RecordId([0; 32]),
            request,
            user_record_in.clone(),
        );
        assert_eq!(response, Recover3Response::NoGuesses);
        assert_eq!(Some(user_record_in), user_record_out);
    }

    #[test]
    fn test_recover3_not_registered() {
        let request = Recover3Request {
            version: version(),
            unlock_key_tag: unlock_key_tag(),
        };
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
                version: version(),
                oprf_private_key: oprf_private_key(),
                oprf_public_key_signature: oprf_public_key_signature(),
                unlock_key_commitment: unlock_key_commitment(),
                unlock_key_tag: unlock_key_tag(),
                user_secret_encryption_key_scalar_share: user_secret_encryption_key_scalar_share(),
                encrypted_user_secret: encrypted_user_secret(),
                encrypted_user_secret_commitment: encrypted_user_secret_commitment(),
                guess_count,
                policy: policy(),
            })),
        }
    }

    fn version() -> RegistrationVersion {
        RegistrationVersion::from([0; 16])
    }

    fn oprf_private_key() -> OprfPrivateKey {
        OprfPrivateKey::try_from([2; 32]).unwrap()
    }

    fn oprf_public_key_signature() -> OprfPublicKeySignature {
        OprfPublicKeySignature {
            verifying_key: OprfVerifyingKey::from([0xff; 32]),
            bytes: SecretBytesArray::from([0xff; 64]),
        }
    }

    fn oprf_signed_public_key() -> OprfSignedPublicKey {
        OprfSignedPublicKey {
            public_key: oprf_private_key().public_key(),
            signature: oprf_public_key_signature(),
        }
    }

    fn oprf_blinded_input() -> OprfBlindedInput {
        OprfBlindedInput::try_from([
            0xe6, 0x92, 0xd0, 0xf3, 0x22, 0x96, 0xe9, 0x01, 0x97, 0xf4, 0x55, 0x7c, 0x74, 0x42,
            0x99, 0xd2, 0x3e, 0x1d, 0xc2, 0x6c, 0xda, 0x1a, 0xea, 0x5a, 0xa7, 0x54, 0xb4, 0x6c,
            0xee, 0x59, 0x55, 0x7c,
        ])
        .unwrap()
    }

    fn oprf_blinded_result() -> OprfBlindedResult {
        OprfBlindedResult::try_from([
            0x1c, 0x63, 0xe0, 0x37, 0xd5, 0x99, 0x2, 0x32, 0xa8, 0xfd, 0x52, 0xd9, 0x89, 0x83,
            0x82, 0xfc, 0xe1, 0x88, 0xe0, 0xcc, 0xe3, 0x18, 0x57, 0x82, 0x9e, 0x3b, 0x93, 0xf9,
            0x77, 0xc0, 0x79, 0x5c,
        ])
        .unwrap()
    }

    fn unlock_key_commitment() -> UnlockKeyCommitment {
        UnlockKeyCommitment::from([2; 32])
    }

    fn unlock_key_tag() -> UnlockKeyTag {
        UnlockKeyTag::from([3; 16])
    }

    fn user_secret_encryption_key_scalar_share() -> UserSecretEncryptionKeyScalarShare {
        UserSecretEncryptionKeyScalarShare::try_from([4; 32]).unwrap()
    }

    fn encrypted_user_secret() -> EncryptedUserSecret {
        EncryptedUserSecret::from([5; 145])
    }

    fn encrypted_user_secret_commitment() -> EncryptedUserSecretCommitment {
        EncryptedUserSecretCommitment::from([6; 16])
    }

    fn policy() -> Policy {
        Policy { num_guesses: 2 }
    }
}
