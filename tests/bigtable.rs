use std::{
    process::Command,
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};
use tokio::time::{self, sleep};

use hsmcore::{
    bitvec::BitVec,
    hsm::{
        types::{EntryHmac, GroupId, LogEntry, LogIndex, OwnedRange, RecordId},
        MerkleHasher,
    },
    merkle::{
        agent::{StoreDelta, StoreKey},
        Tree,
    },
};
use loam_mvp::{
    process_group::ProcessGroup,
    realm::{
        merkle::agent::{self, TreeStoreReader},
        store::bigtable::{
            AppendError::LogPrecondition, BigTableArgs, StoreAdminClient, StoreClient,
        },
    },
};
use loam_sdk_core::types::RealmId;

const REALM: RealmId = RealmId([200; 16]);
const GROUP_1: GroupId = GroupId([1; 16]);
const GROUP_2: GroupId = GroupId([3; 16]);
const GROUP_3: GroupId = GroupId([15; 16]);

static PORT: AtomicU16 = AtomicU16::new(8222);

fn emulator() -> BigTableArgs {
    let u = format!("http://localhost:{}", PORT.fetch_add(1, Ordering::SeqCst))
        .parse()
        .unwrap();
    BigTableArgs {
        project: String::from("prj"),
        inst: String::from("inst"),
        url: Some(u),
    }
}

async fn init_bt(pg: &mut ProcessGroup, args: BigTableArgs) -> (StoreAdminClient, StoreClient) {
    if let Some(emulator_url) = &args.url {
        pg.spawn(
            Command::new("emulator")
                .arg("-port")
                .arg(emulator_url.port().unwrap().as_str()),
        );
    }
    async fn admin(args: &BigTableArgs) -> StoreAdminClient {
        for _ in 0..100 {
            match args.connect_admin().await {
                Ok(admin) => return admin,
                Err(_e) => {
                    sleep(Duration::from_millis(1)).await;
                }
            };
        }
        panic!("repeatedly failed to connect to bigtable admin service");
    }
    async fn data(args: &BigTableArgs) -> StoreClient {
        for _ in 0..100 {
            match args.connect_data().await {
                Ok(data) => return data,
                Err(_e) => {
                    sleep(Duration::from_millis(1)).await;
                }
            }
        }
        panic!("repeatedly failed to connect to bigtable data service");
    }
    let admin_client = admin(&args).await;
    admin_client
        .initialize_realm(&REALM)
        .await
        .expect("failed to initialize realm tables");

    (admin_client, data(&args).await)
}

#[tokio::test]
async fn read_log_entry() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator()).await;

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
        prev_hmac: EntryHmac([0; 32].into()),
        entry_hmac: EntryHmac([1; 32].into()),
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
    let mut entries = create_log_batch(entry.index.next(), entry.entry_hmac.clone(), 10);
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
    let (_, data) = init_bt(&mut pg, emulator()).await;
    let (_, delta) = Tree::new_tree(&MerkleHasher(), &OwnedRange::full());

    for g in &[GROUP_1, GROUP_2, GROUP_3] {
        assert!(data.read_last_log_entry(&REALM, g).await.unwrap().is_none());
    }
    let entry1 = LogEntry {
        index: LogIndex(1),
        partition: None,
        transferring_out: None,
        prev_hmac: EntryHmac([0; 32].into()),
        entry_hmac: EntryHmac([1; 32].into()),
    };

    // with a row in group 1, other groups should still see an empty log
    data.append(&REALM, &GROUP_1, &[entry1.clone()], delta)
        .await
        .expect("should of appended log entry");
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
        prev_hmac: EntryHmac([2; 32].into()),
        entry_hmac: EntryHmac([3; 32].into()),
    };
    data.append(&REALM, &GROUP_3, &[entry3.clone()], StoreDelta::default())
        .await
        .expect("should of appended log entry");
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
async fn append_log_precondition() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator()).await;
    let entries = create_log_batch(LogIndex(2), EntryHmac([0; 32].into()), 4);
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
        prev_hmac: EntryHmac([0; 32].into()),
        entry_hmac: EntryHmac([1; 32].into()),
    };
    data.append(&REALM, &GROUP_1, &[entry.clone()], StoreDelta::default())
        .await
        .unwrap();
    // the prev_hmac in entries[0] doesn't match the entry_hmac at LogIndex 1
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
    let (_, data) = init_bt(&mut pg, emulator()).await;
    let mut entries = create_log_batch(LogIndex::FIRST, EntryHmac([0; 32].into()), 4);
    entries[3].index = LogIndex(100);
    let _ = data
        .append(&REALM, &GROUP_1, &entries, StoreDelta::default())
        .await;
}

#[tokio::test]
#[should_panic]
async fn batch_hmac_chain_verified() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator()).await;
    let mut entries = create_log_batch(LogIndex::FIRST, EntryHmac([0; 32].into()), 4);
    entries[2].entry_hmac = EntryHmac([33; 32].into());
    let _ = data
        .append(&REALM, &GROUP_1, &entries, StoreDelta::default())
        .await;
}

#[tokio::test]
async fn append_store_delta() {
    let mut pg = ProcessGroup::new();
    let (_, data) = init_bt(&mut pg, emulator()).await;
    let entries = create_log_batch(LogIndex::FIRST, EntryHmac([0; 32].into()), 4);
    let (starting_root, delta) = Tree::new_tree(&MerkleHasher(), &OwnedRange::full());

    data.append(&REALM, &GROUP_3, &entries, delta)
        .await
        .unwrap();

    // get a readproof, mutate the merkle tree and append the changes to the store.
    let rp = agent::read(
        &REALM,
        &data,
        &OwnedRange::full(),
        &starting_root,
        &RecordId([1; 32]),
    )
    .await
    .unwrap();
    let mut tree = Tree::with_existing_root(MerkleHasher(), starting_root, 15);
    let vp = tree.latest_proof(rp).unwrap();
    let (new_root, delta) = tree.insert(vp, vec![1, 2, 3]).unwrap();
    let last_log_entry = entries.last().unwrap();
    let entries = create_log_batch(
        last_log_entry.index.next(),
        last_log_entry.entry_hmac.clone(),
        1,
    );
    // Verify the original root is readable.
    data.read_node(&REALM, StoreKey::new(&BitVec::new(), &starting_root))
        .await
        .unwrap();

    // Apply the delta, the original root, and the new root should both be
    // readable until the deferred delete kicks in.
    time::pause();
    data.append(&REALM, &GROUP_3, &entries, delta)
        .await
        .unwrap();

    data.read_node(&REALM, StoreKey::new(&BitVec::new(), &starting_root))
        .await
        .unwrap();
    data.read_node(&REALM, StoreKey::new(&BitVec::new(), &new_root))
        .await
        .unwrap();

    time::advance(Duration::from_secs(6)).await;
    // The deferred delete should of executed and the original root deleted.
    data.read_node(&REALM, StoreKey::new(&BitVec::new(), &starting_root))
        .await
        .expect_err("should of failed to find node");
    data.read_node(&REALM, StoreKey::new(&BitVec::new(), &new_root))
        .await
        .unwrap();
}

fn create_log_batch(first_idx: LogIndex, prev_hmac: EntryHmac, count: usize) -> Vec<LogEntry> {
    let mut entries = Vec::with_capacity(count);
    let mut prev_hmac = prev_hmac;
    let mut index = first_idx;
    for _ in 0..count {
        let e = LogEntry {
            index,
            partition: None,
            transferring_out: None,
            prev_hmac,
            entry_hmac: EntryHmac([(index.0 % 255) as u8; 32].into()),
        };
        prev_hmac = e.entry_hmac.clone();
        index = index.next();
        entries.push(e);
    }
    entries
}
