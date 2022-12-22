use actix::prelude::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::{self, Debug};
use subtle::ConstantTimeEq;

use super::types::{
    AuthToken, DeleteRequest, DeleteResponse, MaskedPgkShare, OprfBlindedInput, OprfBlindedResult,
    OprfCipherSuite, Policy, Recover1Request, Recover1Response, Recover2Request, Recover2Response,
    Register1Request, Register1Response, Register2Request, Register2Response, UnlockPassword,
    UserSecretShare,
};

type OprfServer = voprf::OprfServer<OprfCipherSuite>;

#[derive(Debug)]
enum UserRecord {
    Registering,
    Registered(RegisteredUserRecord),
}

#[derive(Debug)]
struct RegisteredUserRecord {
    guess_count: u16,
    policy: Policy,
    masked_pgk_share: MaskedPgkShare,
    password: UnlockPassword,
    secret_share: UserSecretShare,
}

struct RootOprfKey(Vec<u8>);

impl RootOprfKey {
    fn user_key(&self, user: &str) -> digest::Output<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("failed to initialize HMAC");
        mac.update(user.as_bytes());
        mac.finalize().into_bytes()
    }
}

impl Debug for RootOprfKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

#[derive(Debug)]
pub struct Server {
    root_oprf_key: RootOprfKey,
    users: HashMap<String, UserRecord>,
}

impl Server {
    pub fn new() -> Self {
        Self {
            root_oprf_key: RootOprfKey(b"very secret".to_vec()),
            users: HashMap::new(),
        }
    }

    fn check_auth(&self, token: &AuthToken) -> Result<String, ()> {
        if token.signature == "it's-a-me!" {
            Ok(token.user.clone())
        } else {
            println!("server: failed auth for {:?}", token.user);
            Err(())
        }
    }

    fn evaluate_oprf(&self, user: &str, blinded_pin: &OprfBlindedInput) -> OprfBlindedResult {
        let oprf_key = self.root_oprf_key.user_key(user);
        let oprf = OprfServer::new_from_seed(&oprf_key, &[ /* TODO: what is this "info" for? */])
            .expect("error constructing OprfServer");
        oprf.blind_evaluate(blinded_pin)
    }
}

impl Actor for Server {
    type Context = Context<Self>;
}

impl Handler<Register1Request> for Server {
    type Result = Register1Response;

    fn handle(&mut self, request: Register1Request, _ctx: &mut Context<Self>) -> Self::Result {
        let Ok(user) = self.check_auth(&request.auth_token) else {
            return Register1Response::InvalidAuth
        };
        println!("server: register1 request for {user:?}");

        match self.users.entry(user.clone()) {
            Entry::Occupied(_) => {
                println!("server: can't re-register {user:?} (no generations in this verison)");
                Register1Response::AlreadyRegistered
            }
            Entry::Vacant(entry) => {
                entry.insert(UserRecord::Registering);
                let blinded_oprf_pin = self.evaluate_oprf(&user, &request.blinded_pin);
                println!("server: register1 {user:?} completed");
                Register1Response::Ok { blinded_oprf_pin }
            }
        }
    }
}

impl Handler<Register2Request> for Server {
    type Result = Register2Response;

    fn handle(&mut self, request: Register2Request, _ctx: &mut Context<Self>) -> Self::Result {
        let Ok(user) = self.check_auth(&request.auth_token) else {
            return Register2Response::InvalidAuth
        };
        println!("server: register2 request for {user:?}");

        match self.users.get_mut(&user) {
            None => {
                println!("server: can't do register2 for {user:?}: haven't done register1");
                Register2Response::NotRegistering
            }
            Some(UserRecord::Registered(_)) => {
                println!("server: can't do register2 for {user:?}: already registered");
                Register2Response::AlreadyRegistered
            }
            Some(record @ UserRecord::Registering) => {
                *record = UserRecord::Registered(RegisteredUserRecord {
                    guess_count: 0,
                    policy: request.policy,
                    masked_pgk_share: request.masked_pgk_share,
                    password: request.password,
                    secret_share: request.secret_share,
                });
                Register2Response::Ok
            }
        }
    }
}

impl Handler<Recover1Request> for Server {
    type Result = Recover1Response;

    fn handle(&mut self, request: Recover1Request, _ctx: &mut Context<Self>) -> Self::Result {
        let Ok(user) = self.check_auth(&request.auth_token) else {
            return Recover1Response::InvalidAuth
        };
        println!("server: recover1 request for {user:?}");

        let masked_pgk_share = match self.users.get_mut(&user) {
            None | Some(UserRecord::Registering) => {
                println!("server: can't recover {user:?}: not registered");
                return Recover1Response::NotRegistered;
            }
            Some(UserRecord::Registered(record)) => {
                if record.guess_count >= record.policy.num_guesses {
                    println!("server: can't recover {user:?}: out of guesses");
                    return Recover1Response::NoGuesses;
                }
                record.guess_count += 1;
                record.masked_pgk_share.clone()
            }
        };

        let blinded_oprf_pin = self.evaluate_oprf(&user, &request.blinded_pin);
        println!("server: recover1 {user:?} completed");
        Recover1Response::Ok {
            blinded_oprf_pin,
            masked_pgk_share,
        }
    }
}

impl Handler<Recover2Request> for Server {
    type Result = Recover2Response;

    fn handle(&mut self, request: Recover2Request, _ctx: &mut Context<Self>) -> Self::Result {
        let Ok(user) = self.check_auth(&request.auth_token) else {
            return Recover2Response::InvalidAuth
        };
        println!("server: recover2 request for {user:?}");

        match self.users.get_mut(&user) {
            None | Some(UserRecord::Registering) => {
                println!("server: can't recover {user:?}: not registered");
                Recover2Response::NotRegistered
            }
            Some(UserRecord::Registered(record)) => {
                if !bool::from(request.password.ct_eq(&record.password)) {
                    println!("server: can't recover {user:?}: bad unlock password");
                    Recover2Response::BadUnlockPassword
                } else {
                    record.guess_count = 0;
                    println!("server: recovered {user:?} secret share successfully");
                    Recover2Response::Ok(record.secret_share.clone())
                }
            }
        }
    }
}

impl Handler<DeleteRequest> for Server {
    type Result = DeleteResponse;

    fn handle(&mut self, request: DeleteRequest, _ctx: &mut Context<Self>) -> Self::Result {
        let Ok(user) = self.check_auth(&request.auth_token) else {
            return DeleteResponse::InvalidAuth
        };
        println!("server: delete request for {user:?}");
        self.users.remove(&user);
        DeleteResponse::Ok
    }
}
