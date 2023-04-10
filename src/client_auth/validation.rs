use jsonwebtoken::{self, Algorithm, DecodingKey, Validation};
use secrecy::ExposeSecret;
use serde::Deserialize;

use super::{AuthKey, AuthToken, Claims};

#[derive(Debug, Deserialize)]
struct InternalClaims {
    iss: String,
    sub: String,
    exp: u64, // seconds since Unix epoch
    nbf: u64, // seconds since Unix epoch
}

#[derive(Debug)]
pub enum Error {
    Jwt(jsonwebtoken::errors::Error),
    LifetimeTooLong,
}

pub struct Validator {
    validation: Validation,
    // This is exposed to support unit testing.
    pub max_lifetime_seconds: Option<u64>,
}

impl Validator {
    pub fn new() -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["loam.me"]);
        validation.set_required_spec_claims(&["exp", "nbf", "aud", "iss", "sub"]);
        Self {
            validation,
            max_lifetime_seconds: Some(60 * 60 * 24),
        }
    }

    pub fn validate(&self, token: &AuthToken, key: &AuthKey) -> Result<Claims, Error> {
        let key = DecodingKey::from_secret(key.0.expose_secret().as_bytes());

        let claims =
            jsonwebtoken::decode::<InternalClaims>(token.0.expose_secret(), &key, &self.validation)
                .map_err(Error::Jwt)?
                .claims;

        if let Some(max) = self.max_lifetime_seconds {
            if claims.exp - claims.nbf > max {
                return Err(Error::LifetimeTooLong);
            }
        }

        Ok(Claims {
            issuer: claims.iss,
            subject: claims.sub,
        })
    }
}

// clippy wanted this
impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}
