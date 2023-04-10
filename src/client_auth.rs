use secrecy::SecretString;

pub use loam_sdk_core::types::AuthToken;

pub mod creation;
pub mod validation;

/// A symmetric key used for creating and vaildating JWT tokens for clients
/// (see [`AuthToken`]).
pub struct AuthKey(SecretString);

impl From<SecretString> for AuthKey {
    fn from(key: SecretString) -> Self {
        Self(key)
    }
}

/// The data from an [`AuthToken`].
#[derive(Debug, Eq, PartialEq)]
pub struct Claims {
    /// Tenant ID.
    pub issuer: String,
    /// User ID.
    pub subject: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic() {
        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
        };
        let key = AuthKey(SecretString::from(String::from("it's-a-me!")));
        let token = creation::create_token(&claims, &key);
        assert_eq!(
            validation::Validator::new().validate(&token, &key).unwrap(),
            claims
        );
    }

    #[test]
    fn test_bogus() {
        let key = AuthKey(SecretString::from(String::from("it's-a-me!")));
        let token = AuthToken(SecretString::from(String::from("bogus")));
        assert_eq!(
            format!(
                "{:?}",
                validation::Validator::new()
                    .validate(&token, &key)
                    .unwrap_err()
            ),
            "Jwt(Error(InvalidToken))"
        );
    }

    #[test]
    fn test_expired() {
        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
        };
        let key = AuthKey(SecretString::from(String::from("it's-a-me!")));
        let token = creation::create_token_at(&claims, &key, 1400);
        assert_eq!(
            format!("{:?}", validation::Validator::new().validate(&token, &key)),
            "Err(Jwt(Error(ExpiredSignature)))"
        );
    }

    #[test]
    fn test_lifetime_too_long() {
        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
        };
        let key = AuthKey(SecretString::from(String::from("it's-a-me!")));
        let token = creation::create_token(&claims, &key);
        let mut validator = validation::Validator::new();
        validator.max_lifetime_seconds = Some(5);
        assert_eq!(
            format!("{:?}", validator.validate(&token, &key)),
            "Err(LifetimeTooLong)"
        );
        validator.max_lifetime_seconds = None;
        assert!(validator.validate(&token, &key).is_ok());
    }
}
