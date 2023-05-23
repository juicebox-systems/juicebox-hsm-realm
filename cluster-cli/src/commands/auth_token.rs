use anyhow::{anyhow, Context};

use loam_mvp::client_auth::{creation::create_token, tenant_secret_name, AuthKey, Claims};
use loam_mvp::secret_manager::SecretManager;
use loam_sdk::RealmId;

pub async fn mint_auth_token(
    secret_manager: &impl SecretManager,
    tenant: String,
    user: String,
    realm: RealmId,
) -> anyhow::Result<()> {
    if !tenant.starts_with("test-") {
        return Err(anyhow!("tenant must start with 'test-'"));
    }

    let (auth_key_version, auth_key) = secret_manager
        .get_secrets(&tenant_secret_name(&tenant))
        .await
        .context("failed to get test tenant auth key")?
        .into_iter()
        .map(|(version, key)| (version, AuthKey::from(key)))
        .next()
        .ok_or_else(|| anyhow!("tenant has no secrets"))?;

    let auth_token = create_token(
        &Claims {
            issuer: tenant,
            subject: user,
            audience: realm,
        },
        &auth_key,
        auth_key_version,
    );

    println!("{}", auth_token.expose_secret());

    Ok(())
}
