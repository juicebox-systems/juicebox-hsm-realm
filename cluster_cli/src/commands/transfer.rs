use hsm_api::{GroupId, OwnedRange};
use juicebox_api::types::RealmId;
use store::StoreClient;

pub async fn transfer(
    realm: RealmId,
    source: GroupId,
    destination: GroupId,
    range: OwnedRange,
    store: &StoreClient,
) -> anyhow::Result<()> {
    println!("Transferring range {range:?} from group {source:?} to {destination:?}");
    cluster_core::transfer(realm, source, destination, range, store).await?;
    Ok(())
}
