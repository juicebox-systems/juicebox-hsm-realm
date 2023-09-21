use async_trait::async_trait;
use std::error::Error;
use std::fmt::Debug;

use juicebox_realm_api::types::RealmId;

pub struct Message(pub Vec<u8>);

#[async_trait]
pub trait Publisher: Send + Sync + Debug {
    async fn publish(&self, r: RealmId, tenant: &str, m: Message) -> Result<(), Box<dyn Error>>;
}

#[derive(Debug)]
pub struct NullPublisher;

#[async_trait]
impl Publisher for NullPublisher {
    async fn publish(&self, _r: RealmId, _tenant: &str, _m: Message) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}
