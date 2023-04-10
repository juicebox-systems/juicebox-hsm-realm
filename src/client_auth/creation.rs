use jsonwebtoken::{self, get_current_timestamp, Algorithm, EncodingKey, Header};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use super::{AuthKey, AuthToken, Claims};

#[derive(Serialize)]
struct InternalClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'static str,
    exp: u64, // seconds since Unix epoch
    nbf: u64, // seconds since Unix epoch
}

pub fn create_token(claims: &Claims, key: &AuthKey) -> AuthToken {
    create_token_at(claims, key, get_current_timestamp())
}

// split from `create_token` for testing
pub(super) fn create_token_at(claims: &Claims, key: &AuthKey, now: u64) -> AuthToken {
    AuthToken(SecretString::from(
        jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &InternalClaims {
                iss: &claims.issuer,
                sub: &claims.subject,
                aud: "loam.me",
                exp: now + 60 * 10,
                nbf: now - 10,
            },
            &EncodingKey::from_secret(key.0.expose_secret().as_bytes()),
        )
        .expect("failed to mint token"),
    ))
}
