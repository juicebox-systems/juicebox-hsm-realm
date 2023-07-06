use hsmcore::hsm::types::{GroupId, OwnedRange};
use juicebox_sdk_core::types::RealmId;
use store::StoreClient;

pub async fn transfer(
    realm: RealmId,
    source: GroupId,
    destination: GroupId,
    range: OwnedRange,
    store: &StoreClient,
) -> anyhow::Result<()> {
    println!("Transferring range {range:?} from group {source:?} to {destination:?}");
    juicebox_hsm::realm::cluster::transfer(realm, source, destination, range, store).await?;
    Ok(())
}
