use anyhow::anyhow;
use reqwest::Url;
use std::collections::HashMap;

use agent_api::AgentService;
use hsmcore::hsm::types::PublicKey;
use juicebox_hsm::realm::store::bigtable::StoreClient;
use juicebox_sdk::Configuration;
use juicebox_sdk::PinHashingMode;
use juicebox_sdk::Realm;
use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_networking::reqwest::Client;

use crate::get_hsm_statuses;

pub async fn print_sensible_configuration(
    load_balancer: &Url,
    agents_client: &Client<AgentService>,
    store: &StoreClient,
) -> anyhow::Result<()> {
    let hsm_statuses = get_hsm_statuses(agents_client, store).await?;
    let realms: HashMap<RealmId, PublicKey> = hsm_statuses
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
                public_key: Some(public_key.0),
            })
            .collect(),
        pin_hashing_mode: PinHashingMode::Standard2019,
    };

    println!("{}", serde_json::to_string(&configuration).unwrap());
    Ok(())
}
