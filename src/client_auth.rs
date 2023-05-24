use loam_sdk::RealmId;
pub use loam_sdk_core::types::AuthToken;
use std::sync::Arc;
use std::time::Duration;

pub mod creation;
pub mod validation;

use super::secret_manager::{
    self, GoogleSecretManagerClient, Periodic, SecretManager, SecretName, SecretVersion,
};

/// A symmetric key used for creating and vaildating JWT tokens for clients
/// (see [`AuthToken`]).
pub struct AuthKey(secret_manager::Secret);

impl From<secret_manager::Secret> for AuthKey {
    fn from(key: secret_manager::Secret) -> Self {
        Self(key)
    }
}

impl From<Vec<u8>> for AuthKey {
    fn from(key: Vec<u8>) -> Self {
        Self(secret_manager::Secret::from(key))
    }
}

/// The data from an [`AuthToken`].
#[derive(Debug, Eq, PartialEq)]
pub struct Claims {
    /// Tenant ID.
    pub issuer: String,
    /// User ID.
    pub subject: String,
    /// Realm ID.
    pub audience: RealmId,
}

/// Constructs a new Google Cloud Secret Manager client that's limited to
/// accessing tenant auth keys.
pub async fn new_google_secret_manager(
    project: &str,
    auth_manager: Arc<gcp_auth::AuthenticationManager>,
    refresh_interval: Duration,
) -> Result<impl SecretManager, secret_manager::Error> {
    const TENANT_KEY_FILTER: &str = "name:tenant- AND labels.kind=tenant_auth_key";
    let client =
        GoogleSecretManagerClient::new(project, auth_manager, Some(TENANT_KEY_FILTER.to_owned()))
            .await?;
    let manager = Periodic::new(client, refresh_interval).await?;
    Ok(manager)
}

pub fn tenant_secret_name(tenant: &str) -> SecretName {
    SecretName(format!("tenant-{tenant}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::{ExposeSecret, SecretString};

    #[test]
    fn test_token_basic() {
        let realm_id = RealmId([5; 16]);
        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
            audience: realm_id,
        };
        let key = AuthKey::from(b"it's-a-me!".to_vec());
        let token = creation::create_token(&claims, &key, SecretVersion(32));
        let validator = validation::Validator::new(realm_id);
        assert_eq!(
            validator.parse_key_id(&token).unwrap(),
            (String::from("tenant"), SecretVersion(32))
        );
        assert_eq!(validator.validate(&token, &key).unwrap(), claims);
    }

    #[test]
    fn test_token_bogus() {
        let realm_id = RealmId([5; 16]);
        let key = AuthKey::from(b"it's-a-me!".to_vec());
        let token = AuthToken(SecretString::from(String::from("bogus")));
        assert_eq!(
            format!(
                "{:?}",
                validation::Validator::new(realm_id)
                    .validate(&token, &key)
                    .unwrap_err()
            ),
            "Jwt(Error(InvalidToken))"
        );
    }

    #[test]
    fn test_token_expired() {
        let realm_id = RealmId([5; 16]);
        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
            audience: realm_id,
        };
        let key = AuthKey::from(b"it's-a-me!".to_vec());
        let token = creation::create_token_at(&claims, &key, SecretVersion(32), 1400);
        assert_eq!(
            format!(
                "{:?}",
                validation::Validator::new(realm_id).validate(&token, &key)
            ),
            "Err(Jwt(Error(ExpiredSignature)))"
        );
    }

    #[test]
    fn test_token_lifetime_too_long() {
        let realm_id = RealmId([5; 16]);
        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
            audience: realm_id,
        };
        let key = AuthKey::from(b"it's-a-me!".to_vec());
        let token = creation::create_token(&claims, &key, SecretVersion(32));
        let mut validator = validation::Validator::new(realm_id);
        validator.max_lifetime_seconds = Some(5);
        assert_eq!(
            format!("{:?}", validator.validate(&token, &key)),
            "Err(LifetimeTooLong)"
        );
        validator.max_lifetime_seconds = None;
        assert!(validator.validate(&token, &key).is_ok());
    }

    #[test]
    fn test_token_wrong_audience() {
        let realm_id_token = RealmId([5; 16]);
        let realm_id_validator = RealmId([1; 16]);
        let claims = Claims {
            issuer: String::from("tenant"),
            subject: String::from("mario"),
            audience: realm_id_token,
        };
        let key = AuthKey::from(b"it's-a-me!".to_vec());
        let token = creation::create_token(&claims, &key, SecretVersion(32));
        let validator = validation::Validator::new(realm_id_validator);
        assert_eq!(
            format!("{:?}", validator.validate(&token, &key)),
            "Err(Jwt(Error(InvalidAudience)))"
        );
    }

    #[test]
    fn test_token_bad_key_id() {
        use jsonwebtoken::{encode, get_current_timestamp, Algorithm, EncodingKey, Header};

        let realm_id = RealmId([5; 16]);
        let key = AuthKey::from(b"it's-a-me!".to_vec());
        let mint = |key_id| {
            let mut header = Header::new(Algorithm::HS256);
            header.kid = Some(String::from(key_id));
            AuthToken(SecretString::from(
                encode(
                    &header,
                    &creation::InternalClaims {
                        iss: "tenant",
                        sub: "mario",
                        aud: &hex::encode(realm_id.0),
                        exp: get_current_timestamp() + 60 * 10,
                        nbf: get_current_timestamp() - 10,
                    },
                    &EncodingKey::from_secret(key.0 .0.expose_secret()),
                )
                .unwrap(),
            ))
        };

        let validator = validation::Validator::new(realm_id);
        validator.validate(&mint("tenant:32"), &key).unwrap();
        assert_eq!(
            format!("{:?}", validator.validate(&mint("ten:ant:32"), &key)),
            "Err(BadKeyId)"
        );
        assert_eq!(
            format!("{:?}", validator.validate(&mint("antenna:32"), &key)),
            "Err(BadKeyId)"
        );
        assert_eq!(
            format!("{:?}", validator.validate(&mint("tenant:latest"), &key)),
            "Err(BadKeyId)"
        );
        assert_eq!(
            format!("{:?}", validator.validate(&mint("tenant:"), &key)),
            "Err(BadKeyId)"
        );
    }
}
