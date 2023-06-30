extern crate alloc;

use alloc::fmt;
use blake2::Blake2sMac256;
use digest::Mac;
use juicebox_sdk_core::types::RealmId;
use juicebox_sdk_marshalling::bytes;
use serde::{Deserialize, Serialize};

use super::configuration::GroupConfiguration;
use super::types::{
    CtBytes, EntryMac, GroupId, HsmId, LogEntry, LogIndex, Partition, TransferNonce,
    TransferringOut,
};
use super::RealmKeys;

#[derive(Clone, Deserialize, Serialize)]
pub struct MacKey(#[serde(with = "bytes")] [u8; 32]);

impl fmt::Debug for MacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("(redacted)")
    }
}

impl From<[u8; 32]> for MacKey {
    fn from(key: [u8; 32]) -> Self {
        Self(key)
    }
}

impl MacKey {
    pub fn group_configuration_mac(&self, msg: &GroupConfigurationStatementMessage) -> CtBytes<32> {
        self.calculate(msg, b"groupcfg")
    }

    pub fn hsm_realm_mac(&self, msg: &HsmRealmStatementMessage) -> CtBytes<32> {
        self.calculate(msg, b"hsmrealm")
    }

    pub fn captured_mac(&self, msg: &CapturedStatementMessage) -> CtBytes<32> {
        self.calculate(msg, b"capture")
    }

    pub fn log_entry_mac(&self, msg: &EntryMacMessage) -> CtBytes<32> {
        self.calculate(msg, b"logentry")
    }

    pub fn transfer_mac(&self, msg: &TransferStatementMessage) -> CtBytes<32> {
        self.calculate(msg, b"transfer")
    }

    fn calculate(&self, value: &impl Serialize, persona: &[u8]) -> CtBytes<32> {
        let mut mac = Blake2sMac256::new_with_salt_and_personal(&self.0, &[], persona)
            .expect("failed to initialize Blake2sMac");
        ciborium::ser::into_writer(value, DigestWriter(&mut mac))
            .expect("failed to serialize value");
        mac.finalize().into()
    }
}

#[derive(Serialize)]
pub struct GroupConfigurationStatementMessage<'a> {
    pub realm: RealmId,
    pub group: GroupId,
    pub configuration: &'a GroupConfiguration,
}

#[derive(Serialize)]
pub struct HsmRealmStatementMessage<'a> {
    pub realm: RealmId,
    pub hsm: HsmId,
    pub keys: &'a RealmKeys,
}

#[derive(Serialize)]
pub struct CapturedStatementMessage<'a> {
    pub hsm: HsmId,
    pub realm: RealmId,
    pub group: GroupId,
    pub index: LogIndex,
    pub entry_mac: &'a EntryMac,
}

#[derive(Serialize)]
pub struct EntryMacMessage<'a> {
    pub realm: RealmId,
    pub group: GroupId,
    pub index: LogIndex,
    pub partition: &'a Option<Partition>,
    pub transferring_out: &'a Option<TransferringOut>,
    pub prev_mac: &'a EntryMac,
}

impl<'a> EntryMacMessage<'a> {
    pub fn verify_entry(
        key: &MacKey,
        realm: RealmId,
        group: GroupId,
        entry: &'a LogEntry,
    ) -> Result<(), digest::MacError> {
        key.log_entry_mac(&EntryMacMessage {
            realm,
            group,
            index: entry.index,
            partition: &entry.partition,
            transferring_out: &entry.transferring_out,
            prev_mac: &entry.prev_mac,
        })
        .verify(&entry.entry_mac)
    }
}

#[derive(Serialize)]
pub struct TransferStatementMessage<'a> {
    pub realm: RealmId,
    pub partition: &'a Partition,
    pub destination: GroupId,
    pub nonce: TransferNonce,
}

pub trait CtMac {
    fn verify(&self, other: &Self) -> Result<(), digest::MacError>;
}

impl<const N: usize> CtMac for CtBytes<N> {
    fn verify(&self, other: &Self) -> Result<(), digest::MacError> {
        if self == other {
            Ok(())
        } else {
            Err(digest::MacError)
        }
    }
}

pub struct DigestWriter<'a, D: digest::Update>(pub &'a mut D);

impl<'a, D: digest::Update> ciborium_io::Write for DigestWriter<'a, D> {
    type Error = ();

    fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.0.update(data);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::hsm::types::{DataHash, OwnedRange};
    use crate::hsm::RecordEncryptionKey;

    use super::*;
    use expect_test::expect_file;
    use juicebox_sdk_marshalling as marshalling;

    #[test]
    fn mac_message_cbor() {
        let group_cfg = GroupConfigurationStatementMessage {
            realm: RealmId([1; 16]),
            group: GroupId([2; 16]),
            configuration: &GroupConfiguration::from_sorted_including_local(
                vec![HsmId([3; 16]), HsmId([4; 16]), HsmId([5; 16])],
                &HsmId([5; 16]),
            )
            .unwrap(),
        };
        let hsm_realm = HsmRealmStatementMessage {
            realm: RealmId([2; 16]),
            hsm: HsmId([17; 16]),
            keys: &RealmKeys {
                communication: (
                    x25519_dalek::StaticSecret::from([64; 32]),
                    x25519_dalek::PublicKey::from([128; 32]),
                ),
                record: RecordEncryptionKey([16; 32]),
                mac: MacKey([224; 32]),
            },
        };
        let captured = CapturedStatementMessage {
            hsm: HsmId([1; 16]),
            realm: RealmId([2; 16]),
            group: GroupId([3; 16]),
            index: LogIndex(u64::MAX),
            entry_mac: &EntryMac::from([5; 32]),
        };
        let entry = EntryMacMessage {
            realm: RealmId([1; 16]),
            group: GroupId([2; 16]),
            index: LogIndex(u64::MAX),
            partition: &Some(Partition {
                range: OwnedRange::full(),
                root_hash: DataHash([3; 32]),
            }),
            transferring_out: &Some(TransferringOut {
                destination: GroupId([4; 16]),
                partition: Partition {
                    range: OwnedRange::full(),
                    root_hash: DataHash([5; 32]),
                },
                at: LogIndex(u64::MAX - 1),
            }),
            prev_mac: &EntryMac::from([6; 32]),
        };
        let transfer = TransferStatementMessage {
            realm: RealmId([1; 16]),
            partition: &Partition {
                range: OwnedRange::full(),
                root_hash: DataHash([2; 32]),
            },
            destination: GroupId([3; 16]),
            nonce: TransferNonce([4; 16]),
        };

        fn add_diag<S: Serialize>(out: &mut String, k: &MacKey, val: &S) {
            let bytes = marshalling::to_vec(val).unwrap();
            let parsed = cbor_diag::parse_bytes(bytes).unwrap();
            let mac = k.calculate(val, b"test");

            out.push_str(&format!("{}\nmac: {:?}\n", std::any::type_name::<S>(), mac));
            out.push_str(&parsed.to_diag_pretty());
            out.push_str("\n\n");
        }

        let mut out = String::new();
        let k = MacKey::from([42; 32]);
        add_diag(&mut out, &k, &group_cfg);
        add_diag(&mut out, &k, &hsm_realm);
        add_diag(&mut out, &k, &captured);
        add_diag(&mut out, &k, &entry);
        add_diag(&mut out, &k, &transfer);
        expect_file!["mac.txt"].assert_eq(&out);
    }
}
