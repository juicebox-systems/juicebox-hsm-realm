use anyhow::anyhow;
use reqwest::Url;
use std::collections::HashMap;

use loam_mvp::http_client::Client;
use loam_mvp::realm::agent::types::AgentService;
use loam_mvp::realm::store::bigtable::StoreClient;
use loam_sdk::Configuration;
use loam_sdk::PinHashingMode;
use loam_sdk::Realm;
use loam_sdk_core::types::RealmId;

use crate::get_hsm_statuses;

pub async fn print_sensible_configuration(
    load_balancer: &Url,
    agents_client: &Client<AgentService>,
    store: &StoreClient,
) -> anyhow::Result<()> {
    let hsm_statuses = get_hsm_statuses(agents_client, store).await?;
    let realms: HashMap<RealmId, Vec<u8>> = hsm_statuses
        .into_iter()
        .filter_map(|(_, hsm)| hsm.realm.map(|realm| (realm.id, hsm.public_key)))
        .collect();

    if realms.is_empty() {
        return Err(anyhow!("found no usable realms"));
    }

    let configuration = Configuration {
        register_threshold: realms.len().try_into().unwrap(),
        recover_threshold: realms.len().try_into().unwrap(),
        realms: realms
            .into_iter()
            .map(|(id, public_key)| Realm {
                address: load_balancer.clone(),
                id,
                public_key: Some(public_key),
            })
            .collect(),
        pin_hashing_mode: PinHashingMode::Standard2019,
    };

    println!("{}", serde_json::to_string(&configuration).unwrap());
    Ok(())
}
