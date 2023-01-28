//! A reference implementation of a realm that serves requests from clients.
//! See [`Server`].

use actix::prelude::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::{self, Debug};
use subtle::ConstantTimeEq;

use super::types::{
    AuthToken, DeleteRequest, DeleteResponse, GenerationNumber, MaskedPgkShare, OprfBlindedInput,
    OprfBlindedResult, OprfCipherSuite, Policy, Recover1Request, Recover1Response, Recover2Request,
    Recover2Response, Register1Request, Register1Response, Register2Request, Register2Response,
    UnlockPassword, UserSecretShare,
};

type OprfServer = voprf::OprfServer<OprfCipherSuite>;

/// Persistent state for a particular user.
#[derive(Debug)]
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
#[derive(Debug)]
enum GenerationRecord {
    /// The record has gone through the first phase but not the second phase of
    /// registration. This is a stub record.
    Registering,
    /// The record has completed both phases of registration.
    Registered(RegisteredUserRecord),
}

/// Persistent state for a fully registered generation.
#[derive(Debug)]
struct RegisteredUserRecord {
    guess_count: u16,
    policy: Policy,
    masked_pgk_share: MaskedPgkShare,
    password: UnlockPassword,
    secret_share: UserSecretShare,
}

/// A private root key used to derive keys for each user-generation's OPRF.
struct RootOprfKey(Vec<u8>);

impl RootOprfKey {
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

#[derive(Debug)]
pub struct Server {
    /// Server's friendly name, used in log messages.
    name: String,
    root_oprf_key: RootOprfKey,
    users: HashMap<String, UserRecord>,
}

impl Server {
    #[allow(dead_code)]
    pub fn new(name: String) -> Self {
        Self {
            name,
            root_oprf_key: RootOprfKey(b"very secret".to_vec()),
            users: HashMap::new(),
        }
    }

    /// Returns the username if the auth token is valid, or an error otherwise.
    fn check_auth(&self, token: &AuthToken) -> Result<String, ()> {
        if token.signature == "it's-a-me!" {
            Ok(token.user.clone())
        } else {
            println!("{}: failed auth for {:?}", self.name, token.user);
            Err(())
        }
    }

    /// Returns the user record for the given user. Creates one if necessary.
    fn get_user(&mut self, user: &str) -> &mut UserRecord {
        self.users
            .entry(user.to_owned())
            .or_insert_with(UserRecord::new)
    }

    /// Computes an OPRF for a user-generation.
    fn evaluate_oprf(
        &self,
        user: &str,
        generation: GenerationNumber,
        blinded_pin: &OprfBlindedInput,
    ) -> OprfBlindedResult {
        let oprf_key = self.root_oprf_key.user_generation_key(user, generation);
        let oprf = OprfServer::new_from_seed(&oprf_key, &[ /* TODO: what is this "info" for? */])
            .expect("error constructing OprfServer");
        oprf.blind_evaluate(blinded_pin)
    }
}

impl Actor for Server {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        let name = &self.name;
        println!("{name}: starting");
        if name.starts_with("dead-") {
            println!("{name}: exiting immediately (since my name starts with 'dead-')");
            ctx.stop()
        }
    }
}

impl Handler<Register1Request> for Server {
    type Result = Register1Response;

    fn handle(&mut self, request: Register1Request, _ctx: &mut Context<Self>) -> Self::Result {
        let Ok(user) = self.check_auth(&request.auth_token) else {
            return Register1Response::InvalidAuth
        };
        let server_name = self.name.clone();
        println!(
            "{server_name}: register1 request for {user:?} at generation {}",
            request.generation
        );

        let user_record = self.get_user(&user);

        if request.generation < user_record.first_available_generation {
            println!(
                "{server_name}: can't re-register {user:?} at generation {} (first available generation is {})",
                request.generation,
                user_record.first_available_generation
            );
            return Register1Response::BadGeneration {
                first_available: user_record.first_available_generation,
            };
        }

        match request.generation.0.checked_add(1) {
            None => {
                return Register1Response::BadGeneration {
                    first_available: user_record.first_available_generation,
                };
            }

            Some(avail) => {
                user_record.first_available_generation = GenerationNumber(avail);
            }
        }

        user_record
            .generations
            .insert(request.generation, GenerationRecord::Registering);
        let blinded_oprf_pin = self.evaluate_oprf(&user, request.generation, &request.blinded_pin);
        println!(
            "{server_name}: register1 {user:?} at generation {} completed",
            request.generation
        );
        Register1Response::Ok { blinded_oprf_pin }
    }
}

impl Handler<Register2Request> for Server {
    type Result = Register2Response;

    fn handle(&mut self, request: Register2Request, _ctx: &mut Context<Self>) -> Self::Result {
        let Ok(user) = self.check_auth(&request.auth_token) else {
            return Register2Response::InvalidAuth
        };
        let server_name = self.name.clone();
        println!(
            "{server_name}: register2 request for {user:?} at generation {}",
            request.generation
        );

        let user_record = self.get_user(&user);

        match user_record.generations.get_mut(&request.generation) {
            None => {
                println!(
                    "{server_name}: can't do register2 for {user:?} at {}: haven't done register1",
                    request.generation
                );
                Register2Response::NotRegistering
            }
            Some(GenerationRecord::Registered(_)) => {
                println!(
                    "{server_name}: can't do register2 for {user:?} at {}: already registered",
                    request.generation
                );
                Register2Response::AlreadyRegistered
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
                Register2Response::Ok {
                    found_earlier_generations: first_generation < request.generation,
                }
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
        let server_name = self.name.clone();
        match request.generation {
            Some(generation) => println!(
                "{server_name}: recover1 request for {user:?} at generation {generation:?}"
            ),
            None => println!("{server_name}: recover1 request for {user:?} at latest generation"),
        };

        let user_record = self.get_user(&user);

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
                println!(
                    "{server_name}: can't recover {user:?} at generation {:?}: not registered",
                    request.generation
                );
                return Recover1Response::NotRegistered {
                    generation: request.generation,
                    previous_generation,
                };
            }

            Some((generation, GenerationRecord::Registering)) => {
                println!(
                    "{server_name}: can't recover {user:?} at generation {generation:?}: partially registered"
                );
                return Recover1Response::PartiallyRegistered {
                    generation,
                    previous_generation,
                };
            }

            Some((generation, GenerationRecord::Registered(record))) => {
                if record.guess_count >= record.policy.num_guesses {
                    println!(
                        "{server_name}: can't recover {user:?} at generation {generation}: out of guesses"
                    );
                    return Recover1Response::NoGuesses {
                        generation,
                        previous_generation,
                    };
                }
                record.guess_count += 1;
                (generation, record.masked_pgk_share.clone())
            }
        };

        let blinded_oprf_pin = self.evaluate_oprf(&user, generation, &request.blinded_pin);
        println!("{server_name}: recover1 {user:?} at generation {generation} completed");
        Recover1Response::Ok {
            generation,
            blinded_oprf_pin,
            masked_pgk_share,
            previous_generation,
        }
    }
}

impl Handler<Recover2Request> for Server {
    type Result = Recover2Response;

    fn handle(&mut self, request: Recover2Request, _ctx: &mut Context<Self>) -> Self::Result {
        let Ok(user) = self.check_auth(&request.auth_token) else {
            return Recover2Response::InvalidAuth
        };
        let server_name = self.name.clone();
        println!(
            "{server_name}: recover2 request for {user:?} at generation {}",
            request.generation
        );

        let user_record = self.get_user(&user);

        match user_record.generations.get_mut(&request.generation) {
            None | Some(GenerationRecord::Registering) => {
                println!(
                    "{server_name}: can't recover {user:?} at generation {}: not registered",
                    request.generation
                );
                Recover2Response::NotRegistered
            }
            Some(GenerationRecord::Registered(record)) => {
                if !bool::from(request.password.ct_eq(&record.password)) {
                    println!(
                        "{server_name}: can't recover {user:?} at generation {}: bad unlock password",
                        request.generation
                    );
                    Recover2Response::BadUnlockPassword
                } else {
                    record.guess_count = 0;
                    println!(
                        "{server_name}: recovered {user:?} at generation {}'s secret share successfully",
                        request.generation,
                    );
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
        let server_name = self.name.clone();
        let user_record = self.get_user(&user);

        match request.up_to {
            // Remove from 0 up to and excluding generation.
            Some(generation) => {
                println!(
                    "{server_name}: delete request for {user:?} (up to generation {generation})"
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
                println!("{server_name}: delete request for {user:?} (all generations)");
                user_record.generations.clear();
            }
        }

        DeleteResponse::Ok
    }
}
