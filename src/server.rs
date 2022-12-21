use actix::prelude::*;
use std::collections::hash_map::Entry;
use std::collections::HashMap;

use super::types::{
    AuthToken, DeleteRequest, DeleteResponse, Pin, Policy, RecoverRequest, RecoverResponse,
    RegisterRequest, RegisterResponse, UserSecret,
};

#[derive(Debug)]
struct UserRecord {
    guess_count: u16,
    policy: Policy,
    pin: Pin,
    secret: UserSecret,
}

#[derive(Debug)]
pub struct Server {
    users: HashMap<String, UserRecord>,
}

impl Server {
    pub fn new() -> Self {
        Self {
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
}

impl Actor for Server {
    type Context = Context<Self>;
}

impl Handler<RegisterRequest> for Server {
    type Result = RegisterResponse;

    fn handle(&mut self, request: RegisterRequest, _ctx: &mut Context<Self>) -> Self::Result {
        let Ok(user) = self.check_auth(&request.auth_token) else {
            return RegisterResponse::InvalidAuth
        };
        println!("server: register request for {user:?}");

        match self.users.entry(user.clone()) {
            Entry::Occupied(_) => {
                println!("server: can't re-register {user:?} (no generations in this verison)");
                RegisterResponse::AlreadyRegistered
            }
            Entry::Vacant(entry) => {
                entry.insert(UserRecord {
                    guess_count: 0,
                    policy: request.policy,
                    pin: request.pin,
                    secret: request.secret,
                });

                println!("server: registered {user:?} successfully");
                RegisterResponse::Ok
            }
        }
    }
}

impl Handler<RecoverRequest> for Server {
    type Result = RecoverResponse;

    fn handle(&mut self, request: RecoverRequest, _ctx: &mut Context<Self>) -> Self::Result {
        let Ok(user) = self.check_auth(&request.auth_token) else {
            return RecoverResponse::InvalidAuth
        };
        println!("server: recover request for {user:?}");

        match self.users.get_mut(&user) {
            None => {
                println!("server: can't recover {user:?}: not registered");
                RecoverResponse::NotRegistered
            }
            Some(record) => {
                if record.guess_count >= record.policy.num_guesses {
                    println!("server: can't recover {user:?}: out of guesses");
                    RecoverResponse::NoGuesses
                } else if request.pin != record.pin {
                    record.guess_count += 1;
                    println!("server: can't recover {user:?}: bad pin");
                    RecoverResponse::BadPin
                } else {
                    record.guess_count = 0;
                    println!("server: recovered {user:?} secret successfully");
                    RecoverResponse::Ok(record.secret.clone())
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
