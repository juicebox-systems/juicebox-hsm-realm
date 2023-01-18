use super::types::{SecretsRequest, SecretsResponse};

#[derive(Clone, Debug)]
pub struct Record(u64);

impl Record {
    // This is used in hashing, so it must be deterministic.
    pub fn serialized(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

pub enum RecordChange {
    #[allow(dead_code)]
    Delete,
    Update(Record),
}

pub fn process(
    request: SecretsRequest,
    record: Option<&Record>,
) -> (SecretsResponse, Option<RecordChange>) {
    match request {
        SecretsRequest::Increment => {
            let value = match record {
                Some(Record(value)) => value + 1,
                None => 1,
            };
            (
                SecretsResponse::Increment(value),
                Some(RecordChange::Update(Record(value))),
            )
        }
    }
}
