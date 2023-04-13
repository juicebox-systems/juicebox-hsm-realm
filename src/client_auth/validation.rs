use jsonwebtoken::{self, Algorithm, DecodingKey, TokenData, Validation};
use secrecy::ExposeSecret;
use serde::Deserialize;

use super::{AuthKey, AuthToken, Claims, SecretVersion};

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
    BadKeyId,
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

    pub fn parse_key_id(&self, token: &AuthToken) -> Result<(String, SecretVersion), Error> {
        let header = jsonwebtoken::decode_header(token.0.expose_secret()).map_err(Error::Jwt)?;
        match header.kid.as_deref().and_then(parse_key_id) {
            Some((tenant, version)) => Ok((tenant, version)),
            None => Err(Error::BadKeyId),
        }
    }

    pub fn validate(&self, token: &AuthToken, key: &AuthKey) -> Result<Claims, Error> {
        let key = DecodingKey::from_secret(key.0 .0.expose_secret());

        let TokenData { header, claims } =
            jsonwebtoken::decode::<InternalClaims>(token.0.expose_secret(), &key, &self.validation)
                .map_err(Error::Jwt)?;

        if header
            .kid
            .as_deref()
            .and_then(parse_key_id)
            .filter(|(tenant, _version)| tenant == &claims.iss)
            .is_none()
        {
            return Err(Error::BadKeyId);
        }

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

/// Returns tenant and version.
fn parse_key_id(key_id: &str) -> Option<(String, SecretVersion)> {
    let (tenant, version) = key_id.split_once(':')?;
    let version = version.parse::<u64>().ok()?;
    Some((tenant.to_owned(), SecretVersion(version)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_id() {
        assert_eq!(
            parse_key_id("acme:99"),
            Some((String::from("acme"), SecretVersion(99)))
        );
        assert_eq!(parse_key_id("acme-99"), None);
        assert_eq!(parse_key_id("tenant-acme"), None);
        assert_eq!(parse_key_id("tenant-acme:latest"), None);
    }
}
