use anyhow::anyhow;
use reqwest::Url;
use std::collections::HashMap;

use hsm_api::PublicKey;
use juicebox_realm_api::types::RealmId;
use juicebox_sdk::Configuration;
use juicebox_sdk::PinHashingMode;
use juicebox_sdk::Realm;

use crate::cluster::ClusterInfo;

pub async fn print_sensible_configuration(
    load_balancer: &Url,
    cluster: &ClusterInfo,
) -> anyhow::Result<()> {
    let realms: HashMap<RealmId, PublicKey> = cluster
        .hsm_statuses()
        .filter_map(|(hsm, _)| {
            hsm.realm
                .as_ref()
                .map(|realm| (realm.id, hsm.public_key.clone()))
        })
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
