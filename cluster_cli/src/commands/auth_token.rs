use anyhow::{anyhow, Context};

use juicebox_hsm::secret_manager::{tenant_secret_name, SecretManager};
use juicebox_sdk::RealmId;
use juicebox_sdk_util::realm_auth::{creation::create_token, Claims};

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
        .map(|(version, secret)| (version.into(), secret.into()))
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
