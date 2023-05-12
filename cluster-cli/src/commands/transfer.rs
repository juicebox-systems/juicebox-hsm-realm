use hsmcore::hsm::types::{GroupId, OwnedRange};
use loam_mvp::realm::store::bigtable::StoreClient;
use loam_sdk_core::types::RealmId;

pub async fn transfer(
    realm: RealmId,
    source: GroupId,
    destination: GroupId,
    range: OwnedRange,
    store: &StoreClient,
) -> anyhow::Result<()> {
    println!("Transferring range {range:?} from group {source:?} to {destination:?}");
    loam_mvp::realm::cluster::transfer(realm, source, destination, range, store).await?;
    Ok(())
}
