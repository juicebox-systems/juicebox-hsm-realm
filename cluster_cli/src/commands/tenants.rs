use futures::future::join_all;
use futures::FutureExt;

use agent_api::{ReloadTenantConfigurationRequest, ReloadTenantConfigurationResponse};
use juicebox_networking::rpc;
use juicebox_sdk::reqwest::Client;
use store::tenant_config::TenantConfiguration;
use store::StoreClient;

pub(crate) async fn set_capacity(
    store: &StoreClient,
    agents_client: &Client,
    tenant: String,
    ops_per_sec: usize,
) -> anyhow::Result<()> {
    let config = TenantConfiguration {
        capacity_ops_per_sec: ops_per_sec,
    };
    store.update_tenant(&tenant, &config).await?;
    let agents = store.get_addresses(Some(store::ServiceKind::Agent)).await?;
    for (url, result) in join_all(agents.iter().map(|(url, _)| {
        rpc::send(agents_client, url, ReloadTenantConfigurationRequest {})
            .map(|res| (url.clone(), res))
    }))
    .await
    {
        match result {
            Ok(ReloadTenantConfigurationResponse::Ok { num_tenants }) => {
                println!("agent {url} reloaded tenant config for {num_tenants} tenants")
            }
            Ok(ReloadTenantConfigurationResponse::NoStore) => {
                eprintln!("agent {url} reports bigtable error")
            }
            Err(e) => eprintln!("rpc error to agent {url}: {e:?}"),
        }
    }

    println!("Updated tenant configuration");
    Ok(())
}
