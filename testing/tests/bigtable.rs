use once_cell::sync::Lazy;
use reqwest::Url;
use std::time::{Duration, SystemTime};
use store::discovery;

use agent_api::merkle::TreeStoreReader;
use bitvec::BitVec;
use hsm_api::merkle::{NodeKey, StoreDelta};
use hsm_api::{EntryMac, GroupId, LogEntry, LogIndex, OwnedRange, RecordId};
use hsm_core::hsm::MerkleHasher;
use hsm_core::merkle::Tree;
use juicebox_api::types::RealmId;
use juicebox_process_group::ProcessGroup;
use observability::metrics;
use store::{self, AppendError::LogPrecondition, ServiceKind, StoreAdminClient, StoreClient};
use testing::exec::bigtable::emulator;
use testing::exec::{bigtable::BigtableRunner, PortIssuer};

const REALM: RealmId = RealmId([200; 16]);
const GROUP_1: GroupId = GroupId([1; 16]);
const GROUP_2: GroupId = GroupId([3; 16]);
const GROUP_3: GroupId = GroupId([15; 16]);

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8222));

async fn init_bt(pg: &mut ProcessGroup, args: store::Args) -> (StoreAdminClient, StoreClient) {
    BigtableRunner::run(pg, &args).await;

    let store_admin = args
        .connect_admin(None)
        .await
        .expect("failed to connect to bigtable admin service");

    store_admin
        .initialize_realm(&REALM)
        .await
        .expect("failed to initialize realm tables");

    let store = args
        .connect_data(None, store::Options::default())
        .await
        .expect("failed to connect to bigtable data service");

    (store_admin, store)
}

#[tokio::test]
async fn read_log_entry() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;

    // Log should start empty.
    assert!(data
        .read_last_log_entry(&REALM, &GROUP_2)
        .await
        .unwrap()
        .is_none());
    assert!(data
        .read_log_entry(&REALM, &GROUP_2, LogIndex::FIRST)
        .await
        .unwrap()
        .is_none());

    // Insert a row with a single log entry, that should then be the last entry.
    let entry = LogEntry {
        index: LogIndex(1),
        partition: None,
        transferring_out: None,
        prev_mac: EntryMac::from([0; 32]),
        entry_mac: EntryMac::from([1; 32]),
    };
    data.append(&REALM, &GROUP_2, &[entry.clone()], StoreDelta::default())
        .await
        .unwrap();
    assert_eq!(
        data.read_last_log_entry(&REALM, &GROUP_2)
            .await
            .unwrap()
            .unwrap(),
        entry
    );

    // insert a batch of log entries, the last one in the batch should then be the last_log_entry
    let mut entries = create_log_batch(entry.index.next(), entry.entry_mac.clone(), 10);
    data.append(&REALM, &GROUP_2, &entries, StoreDelta::default())
        .await
        .unwrap();
    assert_eq!(
        data.read_last_log_entry(&REALM, &GROUP_2)
            .await
            .unwrap()
            .as_ref(),
        entries.last()
    );
    // and we should be able to read all the rows
    entries.insert(0, entry);
    for e in &entries {
        assert_eq!(
            data.read_log_entry(&REALM, &GROUP_2, e.index)
                .await
                .unwrap()
                .as_ref()
                .unwrap(),
            e
        );
    }
    // but not the one after the last
    assert!(data
        .read_log_entry(
            &REALM,
            &GROUP_2,
            entries.last().as_ref().unwrap().index.next()
        )
        .await
        .unwrap()
        .is_none());
    // reads from adjacent groups shouldn't pick up any of these rows
    assert!(data
        .read_log_entry(&REALM, &GROUP_1, LogIndex(1))
        .await
        .unwrap()
        .is_none());
    assert!(data
        .read_last_log_entry(&REALM, &GROUP_1)
        .await
        .unwrap()
        .is_none());
    assert!(data
        .read_log_entry(&REALM, &GROUP_3, LogIndex(1))
        .await
        .unwrap()
        .is_none());
    assert!(data
        .read_last_log_entry(&REALM, &GROUP_3)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn last_log_entry_does_not_cross_groups() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;
    let (_, delta) = Tree::<MerkleHasher>::new_tree(&OwnedRange::full());

    for g in &[GROUP_1, GROUP_2, GROUP_3] {
        assert!(data.read_last_log_entry(&REALM, g).await.unwrap().is_none());
    }
    let entry1 = LogEntry {
        index: LogIndex(1),
        partition: None,
        transferring_out: None,
        prev_mac: EntryMac::from([0; 32]),
        entry_mac: EntryMac::from([1; 32]),
    };

    // with a row in group 1, other groups should still see an empty log
    data.append(&REALM, &GROUP_1, &[entry1.clone()], delta)
        .await
        .expect("should have appended log entry");
    assert_eq!(
        data.read_last_log_entry(&REALM, &GROUP_1)
            .await
            .unwrap()
            .unwrap(),
        entry1
    );
    for g in [GROUP_2, GROUP_3] {
        assert!(data
            .read_last_log_entry(&REALM, &g)
            .await
            .unwrap()
            .is_none());
    }

    // with a row in group 1 & 3, group 2 should still see an empty log
    let entry3 = LogEntry {
        index: LogIndex(1),
        partition: None,
        transferring_out: None,
        prev_mac: EntryMac::from([2; 32]),
        entry_mac: EntryMac::from([3; 32]),
    };
    data.append(&REALM, &GROUP_3, &[entry3.clone()], StoreDelta::default())
        .await
        .expect("should have appended log entry");
    assert!(data
        .read_last_log_entry(&REALM, &GROUP_2)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        data.read_last_log_entry(&REALM, &GROUP_1)
            .await
            .unwrap()
            .unwrap(),
        entry1
    );
    assert_eq!(
        data.read_last_log_entry(&REALM, &GROUP_3)
            .await
            .unwrap()
            .unwrap(),
        entry3
    );
}

#[tokio::test]
async fn read_log_entries() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;
    let mut entries = create_log_batch(LogIndex::FIRST, EntryMac::from([0; 32]), 4);
    data.append(&REALM, &GROUP_1, &entries, StoreDelta::default())
        .await
        .unwrap();

    let more_entries = create_log_batch(LogIndex(5), entries[3].entry_mac.clone(), 6);
    data.append(&REALM, &GROUP_1, &more_entries, StoreDelta::default())
        .await
        .unwrap();
    entries.extend(more_entries);

    let more_entries = create_log_batch(LogIndex(11), entries[9].entry_mac.clone(), 5);
    data.append(&REALM, &GROUP_1, &more_entries, StoreDelta::default())
        .await
        .unwrap();
    entries.extend(more_entries);

    // first read will return the entries from the first row only, even if
    // subsequent rows would fit in the chunk size. reads after that can span
    // multiple rows
    let mut it = data.read_log_entries_iter(REALM, GROUP_1, LogIndex::FIRST, 10);
    let r = it.next().await.unwrap();
    assert_eq!(entries[..4], r, "should have returned first log row");
    let r = it.next().await.unwrap();
    assert_eq!(
        entries[4..],
        r,
        "should have returned all remaining log rows"
    );
    assert!(it.next().await.unwrap().is_empty());

    // Read with chunk size < log row sizes should return one row at a time
    let mut it = data.read_log_entries_iter(REALM, GROUP_1, LogIndex::FIRST, 2);
    let r = it.next().await.unwrap();
    assert_eq!(&entries[0..4], &r, "should have returned entire log row");
    let r = it.next().await.unwrap();
    assert_eq!(
        &entries[4..10],
        &r,
        "should have returned entire 2nd log row"
    );
    let r = it.next().await.unwrap();
    assert_eq!(
        &entries[10..],
        &r,
        "should have returned entire 2nd log row"
    );
    assert!(it.next().await.unwrap().is_empty());

    // Read starting from an index that's not the first in the row should work.
    let mut it = data.read_log_entries_iter(REALM, GROUP_1, LogIndex(2), 12);
    let r = it.next().await.unwrap();
    assert_eq!(
        &entries[1..4],
        &r,
        "should have returned tail of first log row"
    );
    let r = it.next().await.unwrap();
    assert_eq!(
        &entries[4..],
        &r,
        "should have returned entire remaining rows"
    );
    assert!(it.next().await.unwrap().is_empty());

    // Read for a log index that doesn't yet exist should return an empty vec.
    let mut it = data.read_log_entries_iter(REALM, GROUP_1, LogIndex(22), 100);
    assert!(it.next().await.unwrap().is_empty());

    // Read to the tail, then write to the log, then read again should return the new entries.
    let mut it = data.read_log_entries_iter(REALM, GROUP_1, LogIndex::FIRST, 100);
    let r = it.next().await.unwrap();
    assert_eq!(&entries[0..4], &r, "should have returned entire log row");
    let r = it.next().await.unwrap();
    assert_eq!(&entries[4..], &r, "should have returned remaining log rows");

    let last = entries.last().unwrap();
    let more_entries = create_log_batch(last.index.next(), last.entry_mac.clone(), 2);
    data.append(&REALM, &GROUP_1, &more_entries, StoreDelta::default())
        .await
        .unwrap();
    let r = it.next().await.unwrap();
    assert_eq!(more_entries, r);
}

#[tokio::test]
async fn append_log_precondition() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;
    let entries = create_log_batch(LogIndex(2), EntryMac::from([0; 32]), 4);
    // previous log entry should exist
    assert!(matches!(
        data.append(&REALM, &GROUP_1, &entries, StoreDelta::default())
            .await,
        Err(LogPrecondition),
    ));

    let entry = LogEntry {
        index: LogIndex::FIRST,
        partition: None,
        transferring_out: None,
        prev_mac: EntryMac::from([0; 32]),
        entry_mac: EntryMac::from([1; 32]),
    };
    data.append(&REALM, &GROUP_1, &[entry.clone()], StoreDelta::default())
        .await
        .unwrap();
    // the prev_mac in entries[0] doesn't match the entry_mac at LogIndex 1
    assert!(matches!(
        data.append(&REALM, &GROUP_1, &entries, StoreDelta::default())
            .await,
        Err(LogPrecondition),
    ));

    // can't append if the entry is already in the store.
    assert!(matches!(
        data.append(&REALM, &GROUP_1, &[entry], StoreDelta::default())
            .await,
        Err(LogPrecondition)
    ));
}

#[tokio::test]
#[should_panic]
async fn batch_index_chain_verified() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;
    let mut entries = create_log_batch(LogIndex::FIRST, EntryMac::from([0; 32]), 4);
    entries[3].index = LogIndex(100);
    let _ = data
        .append(&REALM, &GROUP_1, &entries, StoreDelta::default())
        .await;
}

#[tokio::test]
#[should_panic]
async fn batch_mac_chain_verified() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;
    let mut entries = create_log_batch(LogIndex::FIRST, EntryMac::from([0; 32]), 4);
    entries[2].entry_mac = EntryMac::from([33; 32]);
    let _ = data
        .append(&REALM, &GROUP_1, &entries, StoreDelta::default())
        .await;
}

#[tokio::test]
async fn append_store_delta() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;
    let entries = create_log_batch(LogIndex::FIRST, EntryMac::from([0; 32]), 4);
    let (starting_root, delta) = Tree::<MerkleHasher>::new_tree(&OwnedRange::full());

    data.append(&REALM, &GROUP_3, &entries, delta)
        .await
        .unwrap();

    // get a readproof, mutate the merkle tree and append the changes to the store.
    let rp = agent_core::merkle::read(
        &REALM,
        &data,
        &OwnedRange::full(),
        &starting_root,
        &RecordId([1; RecordId::NUM_BYTES]),
        &metrics::Client::NONE,
        &[],
    )
    .await
    .unwrap();

    // The `Tree` instance includes an overlay. It's normally part of the HSM.
    // The overlay includes hash tables which need an RNG registered.
    hsm_core::hash::set_global_rng_owned(rand_core::OsRng);

    let mut tree = Tree::<MerkleHasher>::with_existing_root(starting_root, 15);
    let vp = tree.latest_proof(rp).unwrap();
    let (new_root, delta) = tree.insert(vp, vec![1, 2, 3]).unwrap();
    let last_log_entry = entries.last().unwrap();
    let entries = create_log_batch(
        last_log_entry.index.next(),
        last_log_entry.entry_mac.clone(),
        1,
    );
    // Verify the original root is readable.
    data.read_node(
        &REALM,
        NodeKey::new(BitVec::new(), starting_root),
        metrics::NO_TAGS,
    )
    .await
    .unwrap();

    // Apply the delta, the original root, and the new root should both be
    // readable until the deferred delete kicks in.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let delete_handle = data
        .append_inner(&REALM, &GROUP_3, &entries, delta, rx)
        .await
        .unwrap();

    data.read_node(
        &REALM,
        NodeKey::new(BitVec::new(), starting_root),
        metrics::NO_TAGS,
    )
    .await
    .unwrap();
    data.read_node(
        &REALM,
        NodeKey::new(BitVec::new(), new_root),
        metrics::NO_TAGS,
    )
    .await
    .unwrap();

    tx.send(()).unwrap();
    delete_handle.unwrap().await.unwrap();

    // The deferred delete should have executed and the original root be deleted.
    data.read_node(
        &REALM,
        NodeKey::new(BitVec::new(), starting_root),
        metrics::NO_TAGS,
    )
    .await
    .expect_err("should have failed to find node");
    data.read_node(
        &REALM,
        NodeKey::new(BitVec::new(), new_root),
        metrics::NO_TAGS,
    )
    .await
    .unwrap();
}

fn create_log_batch(first_idx: LogIndex, prev_mac: EntryMac, count: usize) -> Vec<LogEntry> {
    let mut entries = Vec::with_capacity(count);
    let mut prev_mac = prev_mac;
    let mut index = first_idx;
    for _ in 0..count {
        let e = LogEntry {
            index,
            partition: None,
            transferring_out: None,
            prev_mac,
            entry_mac: EntryMac::from([(index.0 % 255) as u8; 32]),
        };
        prev_mac = e.entry_mac.clone();
        index = index.next();
        entries.push(e);
    }
    entries
}

#[tokio::test]
async fn service_discovery() {
    let mut pg = ProcessGroup::new();
    let (admin, data) = init_bt(&mut pg, emulator(PORT.next())).await;

    admin.initialize_discovery().await.unwrap();
    assert!(data.get_addresses(None).await.unwrap().is_empty());

    let url1: Url = "http://localhost:9999".parse().unwrap();
    let url2: Url = "http://localhost:9998".parse().unwrap();

    // Should be able to read what we just wrote.
    data.set_address(&url1, ServiceKind::Agent, SystemTime::now())
        .await
        .unwrap();
    assert_eq!(
        vec![(url1.clone(), ServiceKind::Agent)],
        data.get_addresses(Some(ServiceKind::Agent)).await.unwrap()
    );

    data.set_address(&url2, ServiceKind::Agent, SystemTime::now())
        .await
        .unwrap();
    let addresses = data.get_addresses(None).await.unwrap();
    assert_eq!(2, addresses.len());
    // addresses are returned in Url order.
    assert_eq!(
        vec![
            (url2.clone(), ServiceKind::Agent),
            (url1.clone(), ServiceKind::Agent)
        ],
        addresses
    );

    // reading with an old timestamp should result in it being expired.
    data.set_address(
        &url1,
        ServiceKind::Agent,
        SystemTime::now() - discovery::EXPIRY_AGE - Duration::from_secs(1),
    )
    .await
    .unwrap();
    assert_eq!(
        vec![(url2.clone(), ServiceKind::Agent)],
        data.get_addresses(None).await.unwrap()
    );

    // reads should filter based on service type
    let cm_url = "http://10.10.10.10:1234".parse().unwrap();
    data.set_address(&cm_url, ServiceKind::ClusterManager, SystemTime::now())
        .await
        .unwrap();
    assert_eq!(
        vec![(url2.clone(), ServiceKind::Agent)],
        data.get_addresses(Some(ServiceKind::Agent)).await.unwrap()
    );
    assert_eq!(
        vec![(cm_url.clone(), ServiceKind::ClusterManager)],
        data.get_addresses(Some(ServiceKind::ClusterManager))
            .await
            .unwrap()
    );
    // With a filter of None, should see all service types
    assert_eq!(
        vec![
            (url2.clone(), ServiceKind::Agent),
            (cm_url.clone(), ServiceKind::ClusterManager),
        ],
        data.get_addresses(None).await.unwrap()
    );
}
