use anyhow::{anyhow, Context};

use juicebox_realm_auth::creation::create_token;
use juicebox_realm_auth::{Claims, Scope};
use juicebox_sdk::RealmId;
use secret_manager::{tenant_secret_name, SecretManager};

pub async fn mint_auth_token(
    secret_manager: &impl SecretManager,
    tenant: String,
    user: String,
    realm: RealmId,
    scope: Scope,
) -> anyhow::Result<()> {
    if !tenant.starts_with("test-") {
        return Err(anyhow!("tenant must start with 'test-'"));
    }

    let (secret_version, secret) = secret_manager
        .get_latest_secret_version(&tenant_secret_name(&tenant))
        .await
        .context("failed to get test tenant auth key")?
        .ok_or_else(|| anyhow!("tenant has no secrets"))?;

    let auth_token = create_token(
        &Claims {
            issuer: tenant,
            subject: user,
            audience: realm,
            scope: Some(scope),
        },
        &secret.try_into()?,
        secret_version.into(),
    );

    println!("{}", auth_token.expose_secret());

    Ok(())
}
