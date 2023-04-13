use jsonwebtoken::{self, get_current_timestamp, Algorithm, EncodingKey, Header};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use super::{AuthKey, AuthToken, Claims, SecretVersion};

#[derive(Serialize)]
pub(super) struct InternalClaims<'a> {
    pub iss: &'a str,
    pub sub: &'a str,
    pub aud: &'static str,
    pub exp: u64, // seconds since Unix epoch
    pub nbf: u64, // seconds since Unix epoch
}

pub fn create_token(claims: &Claims, key: &AuthKey, key_version: SecretVersion) -> AuthToken {
    create_token_at(claims, key, key_version, get_current_timestamp())
}

// split from `create_token` for testing
pub(super) fn create_token_at(
    claims: &Claims,
    key: &AuthKey,
    key_version: SecretVersion,
    now: u64,
) -> AuthToken {
    let mut header = Header::new(Algorithm::HS256);
    assert!(
        !claims.issuer.contains(':'),
        "tenant names cannot contain ':'. found {:?}",
        claims.issuer,
    );
    header.kid = Some(format!("{}:{}", claims.issuer, key_version.0));
    AuthToken(SecretString::from(
        jsonwebtoken::encode(
            &header,
            &InternalClaims {
                iss: &claims.issuer,
                sub: &claims.subject,
                aud: "loam.me",
                exp: now + 60 * 10,
                nbf: now - 10,
            },
            &EncodingKey::from_secret(key.0 .0.expose_secret()),
        )
        .expect("failed to mint token"),
    ))
}
