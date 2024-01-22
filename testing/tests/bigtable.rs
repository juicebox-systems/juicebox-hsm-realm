use chrono::{Datelike, Days, Months, Utc};
use once_cell::sync::Lazy;
use reqwest::Url;
use std::time::{Duration, SystemTime};

use agent_api::merkle::TreeStoreReader;
use bitvec::BitVec;
use hsm_api::merkle::{NodeKey, StoreDelta};
use hsm_api::{EntryMac, GroupId, HsmId, LogEntry, LogIndex, OwnedRange, RecordId};
use hsm_core::hsm::MerkleHasher;
use hsm_core::merkle::Tree;
use juicebox_process_group::ProcessGroup;
use juicebox_realm_api::types::RealmId;
use observability::metrics;
use store::log::testing::{new_log_row, read_log_entry, ReadLogEntryError, TOMBSTONE_WINDOW_SIZE};
use store::tenants::UserAccounting;
use store::AppendError::LogPrecondition;
use store::{
    self, discovery, tenants, ExtendLeaseError, LeaseKey, LeaseType, LogEntriesIterError,
    ReadLastLogEntryError, ServiceKind, StoreAdminClient, StoreClient,
};
use testing::exec::bigtable::emulator;
use testing::exec::{bigtable::BigtableRunner, PortIssuer};

const REALM: RealmId = RealmId([200; 16]);
const GROUP_1: GroupId = GroupId([1; 16]);
const GROUP_2: GroupId = GroupId([3; 16]);
const GROUP_3: GroupId = GroupId([15; 16]);

// rust runs the tests in parallel, so we need each test to get its own port.
static PORT: Lazy<PortIssuer> = Lazy::new(|| PortIssuer::new(8222));

async fn init_bt(
    pg: &mut ProcessGroup,
    args: store::BigtableArgs,
) -> (StoreAdminClient, StoreClient) {
    BigtableRunner::run(pg, &args).await;

    let store_admin = args
        .connect_admin(None, metrics::Client::NONE)
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
async fn test_tenant() {
    use tenants::UserAccountingEvent::*;

    let mut pg = ProcessGroup::new();
    let args = emulator(PORT.next());
    let (_, data) = init_bt(&mut pg, args).await;

    // we need to be able to go a few days either side and stay in the same month.
    let now = Utc::now().with_day(15).unwrap();

    let bob = RecordId([1; 32]);
    let eve = RecordId([2; 32]);
    let alice = RecordId([3; 32]);
    let simon = RecordId([4; 32]);
    let diego = RecordId([5; 32]);

    let events = vec![
        // bob registered 3 months ago and hasn't done anything since
        UserAccounting::new(
            "jb",
            bob,
            now.checked_sub_months(Months::new(3)).unwrap(),
            SecretRegistered,
        ),
        // alice registered this month
        UserAccounting::new("jb", alice, now, SecretRegistered),
        // eve registered last month, and deleted their secret this month
        UserAccounting::new(
            "jb",
            eve.clone(),
            now.checked_sub_months(Months::new(1)).unwrap(),
            SecretRegistered,
        ),
        UserAccounting::new("jb", eve, now, SecretDeleted),
        // simon registered last month & deleted his secret last month.
        UserAccounting::new(
            "jb",
            simon.clone(),
            now.checked_sub_months(Months::new(1)).unwrap(),
            SecretRegistered,
        ),
        UserAccounting::new(
            "jb",
            simon,
            now.checked_sub_months(Months::new(1))
                .unwrap()
                .checked_add_days(Days::new(1))
                .unwrap(),
            SecretDeleted,
        ),
        // diego registered & deleted a few times in this month
        UserAccounting::new(
            "teylacorp",
            diego.clone(),
            now.checked_sub_days(Days::new(5)).unwrap(),
            SecretRegistered,
        ),
        UserAccounting::new(
            "teylacorp",
            diego.clone(),
            now.checked_sub_days(Days::new(4)).unwrap(),
            SecretDeleted,
        ),
        UserAccounting::new(
            "teylacorp",
            diego.clone(),
            now.checked_add_days(Days::new(3)).unwrap(),
            SecretRegistered,
        ),
        UserAccounting::new(
            "teylacorp",
            diego.clone(),
            now.checked_add_days(Days::new(4)).unwrap(),
            SecretDeleted,
        ),
    ];
    data.write_user_accounting(&REALM, events).await.unwrap();

    // this month
    let counts = data
        .count_realm_users(
            &REALM,
            now.with_day(1).unwrap(),
            now.checked_add_months(Months::new(1))
                .unwrap()
                .with_day(1)
                .unwrap(),
        )
        .await
        .unwrap();
    // bob, alice, eve, diego
    assert_eq!(
        vec![(String::from("jb"), 3), (String::from("teylacorp"), 1)],
        counts.tenant_user_counts
    );

    // last month
    let counts = data
        .count_realm_users(
            &REALM,
            now.checked_sub_months(Months::new(1))
                .unwrap()
                .with_day(1)
                .unwrap(),
            now.with_day(1).unwrap(),
        )
        .await
        .unwrap();
    // bob, eve, simon
    assert_eq!(vec![(String::from("jb"), 3)], counts.tenant_user_counts);

    // 3 months ago
    let counts = data
        .count_realm_users(
            &REALM,
            now.checked_sub_months(Months::new(3)).unwrap(),
            now.checked_sub_months(Months::new(2))
                .unwrap()
                .with_day(1)
                .unwrap(),
        )
        .await
        .unwrap();
    // bob
    assert_eq!(vec![(String::from("jb"), 1)], counts.tenant_user_counts);

    // 3 months ago to the end of this month
    let counts = data
        .count_realm_users(
            &REALM,
            now.checked_sub_months(Months::new(3)).unwrap(),
            now.checked_add_months(Months::new(1))
                .unwrap()
                .with_day(1)
                .unwrap(),
        )
        .await
        .unwrap();
    // bob,alice,eve,simon,diego
    assert_eq!(
        vec![(String::from("jb"), 4), (String::from("teylacorp"), 1)],
        counts.tenant_user_counts
    );
}

#[tokio::test]
async fn test_read_log_entry() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;

    // Log should start empty.
    assert!(matches!(
        data.read_last_log_entry(&REALM, &GROUP_2).await,
        Err(ReadLastLogEntryError::EmptyLog)
    ));
    assert!(matches!(
        read_log_entry(&data, &REALM, &GROUP_2, LogIndex::FIRST).await,
        Err(ReadLogEntryError::NotFound)
    ));

    // Insert a row with a single log entry, that should then be the last entry.
    let entry = LogEntry {
        index: LogIndex(1),
        partition: None,
        transferring: None,
        prev_mac: EntryMac::from([0; 32]),
        entry_mac: EntryMac::from([1; 32]),
        hsm: HsmId([2; 16]),
    };
    data.append(&REALM, &GROUP_2, &[entry.clone()], StoreDelta::default())
        .await
        .unwrap();
    assert_eq!(
        data.read_last_log_entry(&REALM, &GROUP_2).await.unwrap(),
        entry
    );
    assert_eq!(
        read_log_entry(&data, &REALM, &GROUP_2, entry.index)
            .await
            .unwrap(),
        entry
    );
    // insert a batch of log entries, the last one in the batch should then be the last_log_entry
    let mut entries = create_log_batch(entry.index.next(), entry.entry_mac.clone(), 10);
    data.append(&REALM, &GROUP_2, &entries, StoreDelta::default())
        .await
        .unwrap();
    assert_eq!(
        &data.read_last_log_entry(&REALM, &GROUP_2).await.unwrap(),
        entries.last().unwrap()
    );
    // and we should be able to read all the rows
    entries.insert(0, entry);
    for e in &entries {
        assert_eq!(
            read_log_entry(&data, &REALM, &GROUP_2, e.index)
                .await
                .unwrap(),
            *e
        );
    }
    // but not the one after the last
    assert!(matches!(
        read_log_entry(
            &data,
            &REALM,
            &GROUP_2,
            entries.last().as_ref().unwrap().index.next()
        )
        .await,
        Err(ReadLogEntryError::NotFound)
    ));
    // reads from adjacent groups shouldn't pick up any of these rows
    assert!(matches!(
        read_log_entry(&data, &REALM, &GROUP_1, LogIndex(1)).await,
        Err(ReadLogEntryError::NotFound)
    ));
    assert!(matches!(
        data.read_last_log_entry(&REALM, &GROUP_1).await,
        Err(ReadLastLogEntryError::EmptyLog)
    ));
    assert!(matches!(
        read_log_entry(&data, &REALM, &GROUP_3, LogIndex(1)).await,
        Err(ReadLogEntryError::NotFound)
    ));
    assert!(matches!(
        data.read_last_log_entry(&REALM, &GROUP_3).await,
        Err(ReadLastLogEntryError::EmptyLog)
    ));
}

#[tokio::test]
async fn test_last_log_entry_does_not_cross_groups() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;
    let (_, delta) = Tree::<MerkleHasher>::new_tree(&OwnedRange::full());

    for g in &[GROUP_1, GROUP_2, GROUP_3] {
        assert!(matches!(
            data.read_last_log_entry(&REALM, g).await,
            Err(ReadLastLogEntryError::EmptyLog)
        ));
    }
    let entry1 = LogEntry {
        index: LogIndex(1),
        partition: None,
        transferring: None,
        prev_mac: EntryMac::from([0; 32]),
        entry_mac: EntryMac::from([1; 32]),
        hsm: HsmId([2; 16]),
    };

    // with a row in group 1, other groups should still see an empty log
    data.append(&REALM, &GROUP_1, &[entry1.clone()], delta)
        .await
        .expect("should have appended log entry");
    assert_eq!(
        data.read_last_log_entry(&REALM, &GROUP_1).await.unwrap(),
        entry1
    );
    for g in [GROUP_2, GROUP_3] {
        assert!(matches!(
            data.read_last_log_entry(&REALM, &g).await,
            Err(ReadLastLogEntryError::EmptyLog)
        ));
    }

    // with a row in group 1 & 3, group 2 should still see an empty log
    let entry3 = LogEntry {
        index: LogIndex(1),
        partition: None,
        transferring: None,
        prev_mac: EntryMac::from([0; 32]),
        entry_mac: EntryMac::from([3; 32]),
        hsm: HsmId([2; 16]),
    };
    data.append(&REALM, &GROUP_3, &[entry3.clone()], StoreDelta::default())
        .await
        .expect("should have appended log entry");
    assert!(matches!(
        data.read_last_log_entry(&REALM, &GROUP_2).await,
        Err(ReadLastLogEntryError::EmptyLog)
    ));
    assert_eq!(
        data.read_last_log_entry(&REALM, &GROUP_1).await.unwrap(),
        entry1
    );
    assert_eq!(
        data.read_last_log_entry(&REALM, &GROUP_3).await.unwrap(),
        entry3
    );
}

#[tokio::test]
async fn test_read_log_entries() {
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
        "should have returned entire 3rd log row"
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
async fn test_read_log_entries_compacted() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;

    let entries = create_log_batch(LogIndex::FIRST, EntryMac::from([0; 32]), 18);
    let batches = [
        &entries[0..4],
        &entries[4..10],
        &entries[10..15],
        &entries[15..18],
    ];
    for batch in batches {
        println!(
            "appending entries {:?} through {:?}",
            batch.first().unwrap().index,
            batch.last().unwrap().index,
        );
        data.append(&REALM, &GROUP_1, batch, StoreDelta::default())
            .await
            .unwrap();
    }

    println!("writing tombstone at index 11");
    data.replace_oldest_rows_with_tombstones(&REALM, &GROUP_1, &[new_log_row(LogIndex(11), false)])
        .await
        .unwrap();
    read_log_entries_compacted_assertions(&data, &batches).await;

    println!("deleting row at index 11");
    store::log::testing::delete_row(&data, &REALM, &GROUP_1, LogIndex(11))
        .await
        .unwrap();
    read_log_entries_compacted_assertions(&data, &batches).await;

    assert_eq!(
        vec![
            new_log_row(LogIndex(1), false),
            new_log_row(LogIndex(5), false),
            new_log_row(LogIndex(16), false),
        ],
        data.list_log_rows(&REALM, &GROUP_1, LogIndex(17))
            .await
            .unwrap()
    );
}

async fn read_log_entries_compacted_assertions(data: &StoreClient, batches: &[&[LogEntry]; 4]) {
    let mut it = data.read_log_entries_iter(REALM, GROUP_1, LogIndex::FIRST, 20);
    assert_eq!(
        batches[0],
        it.next().await.unwrap(),
        "should have returned 1st log row"
    );

    let r = it.next().await;
    assert!(
        matches!(r, Err(LogEntriesIterError::Compacted(LogIndex(11)))),
        "should have returned that index 11 is compacted, got {r:?}",
    );
    // same error if we retry
    let r = it.next().await;
    assert!(
        matches!(r, Err(LogEntriesIterError::Compacted(LogIndex(11)))),
        "should have returned that index 11 is compacted, got {r:?}",
    );

    let mut it = data.read_log_entries_iter(REALM, GROUP_1, LogIndex(16), 20);
    assert_eq!(
        batches[3],
        it.next().await.unwrap(),
        "should have returned 4th log row"
    );

    // read exactly compacted row index
    let mut it = data.read_log_entries_iter(REALM, GROUP_1, LogIndex(11), 20);
    let r = it.next().await;
    assert!(
        matches!(r, Err(LogEntriesIterError::Compacted(LogIndex(11)))),
        "should have returned that index 11 is compacted, got {r:?}",
    );

    // read 1 past compacted row index
    let mut it = data.read_log_entries_iter(REALM, GROUP_1, LogIndex(12), 20);
    let r = it.next().await;
    assert!(
        matches!(r, Err(LogEntriesIterError::Compacted(LogIndex(12)))),
        "should have returned that index 12 is compacted, got {r:?}",
    );

    // read last index in compacted row
    let mut it = data.read_log_entries_iter(REALM, GROUP_1, LogIndex(15), 20);
    let r = it.next().await;
    assert!(
        matches!(r, Err(LogEntriesIterError::Compacted(LogIndex(15)))),
        "should have returned that index 15 is compacted, got {r:?}",
    );
}

#[tokio::test]
async fn test_list_log_rows_end_of_log() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;

    assert_eq!(
        Vec::<store::LogRow>::new(),
        data.list_log_rows(&REALM, &GROUP_1, LogIndex(u64::MAX))
            .await
            .unwrap()
    );

    let entries = create_log_batch(
        LogIndex::FIRST,
        EntryMac::from([0; 32]),
        TOMBSTONE_WINDOW_SIZE * 2 + 5,
    );
    let batches = entries.chunks(2);
    let mut rows = Vec::new();
    for batch in batches.clone() {
        println!(
            "appending entries {:?} through {:?}",
            batch.first().unwrap().index,
            batch.last().unwrap().index,
        );
        rows.push(
            data.append(&REALM, &GROUP_1, batch, StoreDelta::default())
                .await
                .unwrap(),
        );
    }

    assert_eq!(
        rows,
        data.list_log_rows(&REALM, &GROUP_1, LogIndex(u64::MAX))
            .await
            .unwrap()
    );

    // This is intended to test when the page boundary is equal to or near the
    // log start.
    for i in 1..=5 {
        let expected = &rows[..rows.len() - i];
        println!("expect {} rows", expected.len());
        assert_eq!(
            expected,
            data.list_log_rows(&REALM, &GROUP_1, rows[rows.len() - i].index)
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn test_list_log_rows_compacted() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;

    let entries = create_log_batch(
        LogIndex::FIRST,
        EntryMac::from([0; 32]),
        TOMBSTONE_WINDOW_SIZE * 3,
    );
    let mut rows = Vec::new();
    for entry in entries {
        rows.push(
            data.append(&REALM, &GROUP_1, &[entry], StoreDelta::default())
                .await
                .unwrap(),
        );
    }

    // Leave a log entry row at the start of the log. This violates the log
    // invariants, but it enables us to check that the query terminates before
    // reaching that entry.
    data.replace_oldest_rows_with_tombstones(
        &REALM,
        &GROUP_1,
        &rows[1..(TOMBSTONE_WINDOW_SIZE * 2 + 2)],
    )
    .await
    .unwrap();

    assert_eq!(
        &rows[(TOMBSTONE_WINDOW_SIZE * 2 + 2)..],
        data.list_log_rows(&REALM, &GROUP_1, LogIndex(u64::MAX))
            .await
            .unwrap()
    );

    data.replace_oldest_rows_with_tombstones(
        &REALM,
        &GROUP_1,
        &rows[(TOMBSTONE_WINDOW_SIZE * 2 + 10)..(TOMBSTONE_WINDOW_SIZE * 2 + 15)],
    )
    .await
    .unwrap();
    store::log::testing::delete_row(
        &data,
        &REALM,
        &GROUP_1,
        rows[TOMBSTONE_WINDOW_SIZE * 2 + 13].index,
    )
    .await
    .unwrap();
    store::log::testing::delete_row(
        &data,
        &REALM,
        &GROUP_1,
        rows[TOMBSTONE_WINDOW_SIZE * 2 + 18].index,
    )
    .await
    .unwrap();

    assert_eq!(
        (rows[(TOMBSTONE_WINDOW_SIZE * 2 + 2)..(TOMBSTONE_WINDOW_SIZE * 2 + 10)]
            .iter()
            .cloned())
        .chain(
            rows[(TOMBSTONE_WINDOW_SIZE * 2 + 10)..(TOMBSTONE_WINDOW_SIZE * 2 + 13)]
                .iter()
                .map(|row| new_log_row(row.index, true))
        )
        .chain(
            rows[(TOMBSTONE_WINDOW_SIZE * 2 + 14)..(TOMBSTONE_WINDOW_SIZE * 2 + 15)]
                .iter()
                .map(|row| new_log_row(row.index, true))
        )
        .chain(
            rows[(TOMBSTONE_WINDOW_SIZE * 2 + 15)..(TOMBSTONE_WINDOW_SIZE * 2 + 18)]
                .iter()
                .cloned()
        )
        .chain(rows[(TOMBSTONE_WINDOW_SIZE * 2 + 19)..].iter().cloned())
        .collect::<Vec<store::LogRow>>(),
        data.list_log_rows(&REALM, &GROUP_1, LogIndex(u64::MAX))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_replace_oldest_rows_with_tombstones() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;

    // Replacing only tombstones is OK. This will do nothing.
    data.replace_oldest_rows_with_tombstones(&REALM, &GROUP_1, &[new_log_row(LogIndex(40), true)])
        .await
        .unwrap();
    let result = store::log::testing::read_log_entry(&data, &REALM, &GROUP_1, LogIndex(40)).await;
    assert!(
        matches!(result, Err(ReadLogEntryError::NotFound)),
        "{result:?}"
    );

    // Replacing something nonexistent is OK (assuming it used to exist). This
    // will write a tombstone.
    data.replace_oldest_rows_with_tombstones(&REALM, &GROUP_1, &[new_log_row(LogIndex(41), false)])
        .await
        .unwrap();
    let result = store::log::testing::read_log_entry(&data, &REALM, &GROUP_1, LogIndex(41)).await;
    assert!(
        matches!(result, Err(ReadLogEntryError::Tombstone)),
        "{result:?}"
    );

    // Replacing an existing tombstone is OK. This will overwrite a tombstone
    // with a tombstone.
    data.replace_oldest_rows_with_tombstones(&REALM, &GROUP_1, &[new_log_row(LogIndex(41), false)])
        .await
        .unwrap();
    let result = store::log::testing::read_log_entry(&data, &REALM, &GROUP_1, LogIndex(41)).await;
    assert!(
        matches!(result, Err(ReadLogEntryError::Tombstone)),
        "{result:?}"
    );
}

#[tokio::test]
async fn test_replace_oldest_rows_with_tombstones_chunked() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;

    let entries = create_log_batch(
        LogIndex::FIRST,
        EntryMac::from([0; 32]),
        TOMBSTONE_WINDOW_SIZE * 2,
    );
    let mut rows = Vec::new();
    for entry in entries {
        rows.push(
            data.append(&REALM, &GROUP_1, &[entry], StoreDelta::default())
                .await
                .unwrap(),
        );
    }

    // This tests that replacing more than TOMBSTONE_WINDOW_SIZE rows at once
    // works. Unfortunately, it's hard to assert that it's actually chunked.
    data.replace_oldest_rows_with_tombstones(&REALM, &GROUP_1, &rows[..TOMBSTONE_WINDOW_SIZE + 10])
        .await
        .unwrap();
    // Repeating it is OK.
    data.replace_oldest_rows_with_tombstones(&REALM, &GROUP_1, &rows[..TOMBSTONE_WINDOW_SIZE + 10])
        .await
        .unwrap();
    assert_eq!(
        &rows[(TOMBSTONE_WINDOW_SIZE + 10)..],
        data.list_log_rows(&REALM, &GROUP_1, LogIndex(u64::MAX))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_append_log_precondition() {
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
        transferring: None,
        prev_mac: EntryMac::from([0; 32]),
        entry_mac: EntryMac::from([1; 32]),
        hsm: HsmId([2; 16]),
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
async fn test_append_log_precondition_row_boundary() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;
    let entries = create_log_batch(LogIndex::FIRST, EntryMac::from([0; 32]), 6);

    data.append(&REALM, &GROUP_1, &entries[..2], StoreDelta::default())
        .await
        .unwrap();
    data.append(&REALM, &GROUP_1, &entries[2..4], StoreDelta::default())
        .await
        .unwrap();

    // Although the preceding entry exists, it's not at the end of a row.
    assert!(matches!(
        data.append(&REALM, &GROUP_1, &entries[1..5], StoreDelta::default())
            .await,
        Err(LogPrecondition)
    ));

    // Although the preceding entry exists at the end of a row, it's not the
    // last row.
    assert!(matches!(
        data.append(&REALM, &GROUP_1, &entries[2..5], StoreDelta::default())
            .await,
        Err(LogPrecondition)
    ));
}

#[tokio::test]
#[should_panic]
async fn test_batch_index_chain_verified() {
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
async fn test_batch_mac_chain_verified() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator(PORT.next())).await;
    let mut entries = create_log_batch(LogIndex::FIRST, EntryMac::from([0; 32]), 4);
    entries[2].entry_mac = EntryMac::from([33; 32]);
    let _ = data
        .append(&REALM, &GROUP_1, &entries, StoreDelta::default())
        .await;
}

#[tokio::test]
async fn test_append_store_delta() {
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
    hsm_core::hash::set_global_rng(Box::new(rand_core::OsRng));

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

    let (_row, delete_handle) = data
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
            transferring: None,
            prev_mac,
            entry_mac: EntryMac::from([(index.0 % 255) as u8; 32]),
            hsm: HsmId([2; 16]),
        };
        prev_mac = e.entry_mac.clone();
        index = index.next();
        entries.push(e);
    }
    entries
}

#[tokio::test]
async fn test_service_discovery() {
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

#[tokio::test]
async fn test_lease() {
    let mut pg = ProcessGroup::new();
    let (admin, data) = init_bt(&mut pg, emulator(PORT.next())).await;
    admin.initialize_leases().await.unwrap();

    let now = SystemTime::now();

    let lease = data
        .obtain_lease(LeaseId::A, String::from("Bob"), Duration::from_secs(5), now)
        .await
        .unwrap()
        .unwrap();

    // can't get the lease while someone else has it.
    assert!(data
        .obtain_lease(
            LeaseId::A,
            String::from("Alice"),
            Duration::from_secs(5),
            now
        )
        .await
        .unwrap()
        .is_none());

    // can extend a lease
    data.extend_lease(
        lease,
        Duration::from_secs(5),
        now + Duration::from_millis(500),
    )
    .await
    .unwrap();

    // can get a different lease
    let lease_b = data
        .obtain_lease(LeaseId::B, String::from("Bob"), Duration::from_secs(5), now)
        .await
        .unwrap()
        .unwrap();

    // someone else can get the lease if its explicitly released.
    data.terminate_lease(lease_b).await.unwrap();
    let alice_lease_b = data
        .obtain_lease(
            LeaseId::B,
            String::from("Alice"),
            Duration::from_secs(5),
            now,
        )
        .await
        .unwrap()
        .unwrap();

    // can get the lease if it expired.
    data.obtain_lease(
        LeaseId::B,
        String::from("Eve"),
        Duration::from_secs(5),
        now + Duration::from_secs(6),
    )
    .await
    .unwrap()
    .unwrap();

    // can't extend a lease that was expired and someone else grabbed
    assert!(matches!(
        data.extend_lease(alice_lease_b, Duration::from_secs(5), SystemTime::now())
            .await,
        Err(ExtendLeaseError::NotOwner)
    ));
}

enum LeaseId {
    A,
    B,
}
impl From<LeaseId> for LeaseKey {
    fn from(value: LeaseId) -> Self {
        match value {
            LeaseId::A => LeaseKey(LeaseType::ClusterManagement, String::from("1")),
            LeaseId::B => LeaseKey(LeaseType::ClusterManagement, String::from("22")),
        }
    }
}
