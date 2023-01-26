use super::types::{SecretsRequest, SecretsResponse};

#[derive(Clone, Debug)]
pub struct Record(u64);

impl Record {
    // This is used in hashing, so it must be deterministic.
    pub fn serialized(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
    fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(bytes);
            Some(Record(u64::from_be_bytes(b)))
        } else {
            None
        }
    }
}

pub enum RecordChange {
    #[allow(dead_code)]
    Delete,
    Update(Vec<u8>),
}

pub fn process(
    request: SecretsRequest,
    record_val: Option<Vec<u8>>,
) -> (SecretsResponse, Option<RecordChange>) {
    let record = match record_val {
        None => None,
        Some(data) => Record::deserialize(&data),
    };
    match request {
        SecretsRequest::Increment => {
            let value = match record {
                Some(Record(value)) => value + 1,
                None => 1,
            };
            (
                SecretsResponse::Increment(value),
                Some(RecordChange::Update(Record(value).serialized().to_vec())),
            )
        }
    }
}
