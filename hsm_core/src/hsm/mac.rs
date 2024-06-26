extern crate alloc;

use alloc::fmt;
use blake2::Blake2sMac256;
use digest::Mac;
use serde::{Deserialize, Serialize};

use super::configuration::GroupConfiguration;
use super::RealmKeys;
use hsm_api::{
    CapturedStatement, CtBytes, EntryMac, GroupConfigurationStatement, GroupId, HsmId,
    HsmRealmStatement, LogEntry, LogIndex, OwnedRange, Partition, PreparedTransferStatement,
    TransferNonce, TransferStatement, Transferring, TransferringIn, TransferringOut,
};
use juicebox_marshalling::bytes;
use juicebox_realm_api::types::RealmId;

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
    pub fn group_configuration_mac(
        &self,
        msg: &GroupConfigurationStatementMessage,
    ) -> GroupConfigurationStatement {
        self.calculate(msg, b"groupcfg").into()
    }

    pub fn hsm_realm_mac(&self, msg: &HsmRealmStatementMessage) -> HsmRealmStatement {
        self.calculate(msg, b"hsmrealm").into()
    }

    pub fn captured_mac(&self, msg: &CapturedStatementMessage) -> CapturedStatement {
        self.calculate(msg, b"capture").into()
    }

    pub fn log_entry_mac(&self, msg: &EntryMacMessage) -> EntryMac {
        assert!(!(msg.transferring_in.is_some() && msg.transferring_out.is_some()));
        self.calculate(msg, b"logentry").into()
    }

    pub fn prepared_transfer_mac(
        &self,
        msg: &PreparedTransferStatementMessage,
    ) -> PreparedTransferStatement {
        self.calculate(msg, b"prepared_transfer").into()
    }

    pub fn transfer_mac(&self, msg: &TransferStatementMessage) -> TransferStatement {
        self.calculate(msg, b"transfer").into()
    }

    fn calculate(&self, value: &impl Serialize, domain: &[u8]) -> CtBytes<32> {
        let mut mac =
            Blake2sMac256::new_from_slice(&self.0).expect("failed to initialize Blake2sMac");
        mac.update(&[u8::try_from(domain.len()).unwrap()]);
        mac.update(domain);
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
    pub hsm: HsmId,
    pub realm: RealmId,
    pub group: GroupId,
    pub index: LogIndex,
    pub partition: &'a Option<Partition>,
    pub transferring_out: Option<&'a TransferringOut>,
    // This lets the mac calculation generate the same answer for older log
    // entries that only had transferring_out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transferring_in: Option<&'a TransferringIn>,
    pub prev_mac: &'a EntryMac,
}

impl<'a> EntryMacMessage<'a> {
    pub fn new(realm: RealmId, group: GroupId, entry: &'a LogEntry) -> Self {
        EntryMacMessage {
            hsm: entry.hsm,
            realm,
            group,
            index: entry.index,
            partition: &entry.partition,
            transferring_out: transferring_out(&entry.transferring),
            transferring_in: transferring_in(&entry.transferring),
            prev_mac: &entry.prev_mac,
        }
    }
}

pub(crate) fn transferring_in(t: &Option<Transferring>) -> Option<&TransferringIn> {
    match t {
        None => None,
        Some(Transferring::In(tin)) => Some(tin),
        Some(Transferring::Out(_)) => None,
    }
}

pub(crate) fn transferring_out(t: &Option<Transferring>) -> Option<&TransferringOut> {
    match t {
        None => None,
        Some(Transferring::In(_)) => None,
        Some(Transferring::Out(tout)) => Some(tout),
    }
}

#[derive(Serialize)]
pub struct PreparedTransferStatementMessage<'a> {
    pub realm: RealmId,
    pub source: GroupId,
    pub destination: GroupId,
    pub range: &'a OwnedRange,
    pub nonce: TransferNonce,
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
mod tests {
    use crate::hsm::RecordEncryptionKey;
    use hsm_api::{DataHash, OwnedRange, TransferringOut};

    use super::*;
    use expect_test::expect_file;
    use juicebox_marshalling as marshalling;

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
        let transferring_out = TransferringOut {
            destination: GroupId([4; 16]),
            partition: Partition {
                range: OwnedRange::full(),
                root_hash: DataHash([5; 32]),
            },
            at: LogIndex(u64::MAX - 1),
        };
        let transferring_in = TransferringIn {
            source: GroupId([14; 16]),
            range: OwnedRange::full(),
            at: LogIndex(u64::MAX - 2),
        };
        let full_entry_transfer_out = EntryMacMessage {
            realm: RealmId([1; 16]),
            group: GroupId([2; 16]),
            index: LogIndex(u64::MAX),
            partition: &Some(Partition {
                range: OwnedRange::full(),
                root_hash: DataHash([3; 32]),
            }),
            transferring_out: Some(&transferring_out),
            transferring_in: None,
            prev_mac: &EntryMac::from([6; 32]),
            hsm: HsmId([7; 16]),
        };
        let full_entry_transfer_in = EntryMacMessage {
            realm: RealmId([1; 16]),
            group: GroupId([2; 16]),
            index: LogIndex(u64::MAX),
            partition: &Some(Partition {
                range: OwnedRange::full(),
                root_hash: DataHash([3; 32]),
            }),
            transferring_out: None,
            transferring_in: Some(&transferring_in),
            prev_mac: &EntryMac::from([6; 32]),
            hsm: HsmId([7; 16]),
        };
        let entry = EntryMacMessage {
            realm: RealmId([1; 16]),
            group: GroupId([2; 16]),
            index: LogIndex(u64::MAX),
            partition: &None,
            transferring_out: None,
            transferring_in: None,
            prev_mac: &EntryMac::from([6; 32]),
            hsm: HsmId([7; 16]),
        };
        let prepared = PreparedTransferStatementMessage {
            realm: RealmId([10; 16]),
            source: GroupId([11; 16]),
            destination: GroupId([12; 16]),
            range: &OwnedRange::full(),
            nonce: TransferNonce([13; 16]),
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
        add_diag(&mut out, &k, &full_entry_transfer_out);
        add_diag(&mut out, &k, &full_entry_transfer_in);
        add_diag(&mut out, &k, &prepared);
        add_diag(&mut out, &k, &transfer);
        expect_file!["mac.txt"].assert_eq(&out);
    }

    #[test]
    fn verify() {
        let captured = CapturedStatementMessage {
            hsm: HsmId([1; 16]),
            realm: RealmId([2; 16]),
            group: GroupId([3; 16]),
            index: LogIndex(u64::MAX),
            entry_mac: &EntryMac::from([5; 32]),
        };
        let key = MacKey([42; 32]);
        let m = key.captured_mac(&captured);
        assert!(key.captured_mac(&captured).verify(&m).is_ok());
        let captured2 = CapturedStatementMessage {
            index: LogIndex(u64::MAX - 1),
            ..captured
        };
        assert!(key.captured_mac(&captured2).verify(&m).is_err());
    }
}
