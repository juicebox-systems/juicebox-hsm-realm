use alloc::sync::Arc;
use core::iter::{self, zip};
use hsm_api::merkle::Dir;
use rand::Rng;
use rand_core::{CryptoRng, OsRng, RngCore};
use std::sync::Mutex;

use crate::hash::HashMap;
use crate::merkle::testing::MemStore;
use juicebox_marshalling as marshalling;
use juicebox_noise::client::Handshake;
use juicebox_realm_api::requests::DeleteResponse;
use juicebox_realm_api::types::RealmId;

use super::super::hal::MAX_NVRAM_SIZE;
use super::*;
use hsm_api::{
    CancelPreparedTransferRequest, CancelPreparedTransferResponse, CaptureNextRequest,
    CaptureNextResponse, CommitRequest, CommitResponse, CommitState, CompleteTransferRequest,
    CompleteTransferResponse, EntryMac, GroupId, GuessState, HsmId, LogIndex,
    PrepareTransferRequest, PrepareTransferResponse, PreparedTransfer, TransferInProofs,
    TransferInRequest, TransferInResponse, TransferOutRequest, TransferOutResponse,
    TransferStatement, TransferStatementRequest, TransferStatementResponse, CONFIGURATION_LIMIT,
};

fn array_big<const N: usize>(i: u8) -> [u8; N] {
    let mut r = [0xff; N];
    r[N - 1] = 0xff - i;
    r
}

// Verify that a PersistentState with GROUPS_LIMIT groups with
// CONFIGURATION_LIMIT HSMs each fits in the NVRAM limit.
#[test]
fn persistent_data_size() {
    let id = HsmId([0xff; 16]);
    let group = PersistentGroupState {
        configuration: GroupConfiguration::from_sorted_including_local(
            (0..CONFIGURATION_LIMIT)
                .map(|i| HsmId(array_big(i)))
                .rev()
                .collect::<Vec<HsmId>>(),
            &id,
        )
        .unwrap(),
        captured: Some((LogIndex(u64::MAX - 1), EntryMac::from([0xff; 32]))),
    };
    let mut groups = HashMap::new();
    for id in 0..GROUPS_LIMIT {
        groups.insert(GroupId(array_big(id)), group.clone());
    }
    let p = PersistentState {
        id,
        realm: Some(PersistentRealmState {
            id: RealmId([0xff; 16]),
            statement: HsmRealmStatement::from([0xff; 32]),
            groups,
        }),
    };
    let s = marshalling::to_vec(&p).unwrap();
    assert!(
        s.len() < MAX_NVRAM_SIZE,
        "serialized persistent state is {} bytes",
        s.len()
    );
}

fn make_leader_log() -> (LeaderLog, [EntryMac; 3]) {
    let hsm = HsmId([8; 16]);
    let e = LogEntry {
        index: LogIndex(42),
        partition: None,
        transferring: None,
        prev_mac: EntryMac::from([3; 32]),
        entry_mac: EntryMac::from([42; 32]),
        hsm,
    };
    let mut log = LeaderLog::new(e.clone());
    let e2 = LogEntry {
        index: LogIndex(43),
        partition: None,
        transferring: None,
        prev_mac: e.entry_mac.clone(),
        entry_mac: EntryMac::from([43; 32]),
        hsm,
    };
    log.append(
        e2.clone(),
        Some((
            NoiseResponse::Transport {
                ciphertext: vec![43, 43, 43],
            },
            AppResultType::Recover1,
        )),
    );
    let e3 = LogEntry {
        index: LogIndex(44),
        partition: None,
        transferring: None,

        prev_mac: e2.entry_mac.clone(),
        entry_mac: EntryMac::from([44; 32]),
        hsm,
    };
    log.append(
        e3.clone(),
        Some((
            NoiseResponse::Transport {
                ciphertext: vec![44, 44, 44],
            },
            AppResultType::Recover2 {
                updated: Some(GuessState {
                    num_guesses: 42,
                    guess_count: 4,
                }),
            },
        )),
    );
    (log, [e.entry_mac, e2.entry_mac, e3.entry_mac])
}

#[test]
#[should_panic(expected = "not sequential")]
fn leader_log_index_sequential() {
    let (mut log, macs) = make_leader_log();
    let e = LogEntry {
        index: LogIndex(55),
        partition: None,
        transferring: None,
        prev_mac: macs[2].clone(),
        entry_mac: EntryMac::from([44; 32]),
        hsm: HsmId([1; 16]),
    };
    log.append(e, None);
}

#[test]
#[should_panic(expected = "not chained")]
fn leader_log_mac_chain() {
    let (mut log, _) = make_leader_log();
    let last = log.last();
    let e = LogEntry {
        index: last.entry.index.next(),
        partition: None,
        transferring: None,
        prev_mac: EntryMac::from([45; 32]),
        entry_mac: EntryMac::from([45; 32]),
        hsm: last.entry.hsm,
    };
    log.append(e, None);
}

#[test]
#[should_panic]
fn leader_log_cant_empty_pop_first() {
    let (mut log, _) = make_leader_log();
    assert_eq!(LogIndex(42), log.pop_first().entry.index);
    assert_eq!(LogIndex(43), log.pop_first().entry.index);
    log.pop_first();
}

#[test]
#[should_panic]
fn leader_log_cant_empty_pop_last() {
    let (mut log, _) = make_leader_log();
    assert_eq!(LogIndex(44), log.pop_last().entry.index);
    assert_eq!(LogIndex(43), log.pop_last().entry.index);
    log.pop_last();
}

#[test]
fn leader_log_first_last() {
    let (mut log, _) = make_leader_log();
    assert_eq!(LogIndex(42), log.first().entry.index);
    assert_eq!(LogIndex(44), log.last().entry.index);
    assert_eq!(LogIndex(42), log.first_index());
    assert_eq!(LogIndex(44), log.last_index());
    log.pop_last();
    assert_eq!(LogIndex(43), log.last().entry.index);
}

#[test]
fn leader_log_with_index() {
    let (log, _) = make_leader_log();
    assert_eq!(
        LogIndex(44),
        log.get_index(LogIndex(44)).unwrap().entry.index
    );
    assert_eq!(
        LogIndex(42),
        log.get_index(LogIndex(42)).unwrap().entry.index
    );
    assert_eq!(
        LogIndex(43),
        log.get_index(LogIndex(43)).unwrap().entry.index
    );
    assert!(log.get_index(LogIndex(41)).is_none());
    assert!(log.get_index(LogIndex(45)).is_none());
    assert!(log.get_index(LogIndex::FIRST).is_none());
    assert!(log.get_index(LogIndex(u64::MAX)).is_none());
}

#[test]
fn leader_log_take_first() {
    let (mut log, macs) = make_leader_log();
    assert_eq!(LogIndex(42), log.pop_first().entry.index);

    match log.take_first_response() {
        Some((mac, NoiseResponse::Transport { ciphertext }, event)) => {
            assert_eq!(vec![43, 43, 43], ciphertext);
            assert_eq!(macs[1], mac);
            assert_eq!(AppResultType::Recover1, event)
        }
        _ => panic!("should of taken a noise response"),
    }
    assert!(log.take_first_response().is_none());
    assert!(log.pop_first().response.is_none());

    match log.take_first_response() {
        Some((mac, NoiseResponse::Transport { ciphertext }, event)) => {
            assert_eq!(vec![44, 44, 44], ciphertext);
            assert_eq!(macs[2], mac);
            assert_eq!(
                AppResultType::Recover2 {
                    updated: Some(GuessState {
                        num_guesses: 42,
                        guess_count: 4,
                    })
                },
                event
            );
        }
        _ => panic!("should of taken a noise response"),
    }
    assert!(log.take_first_response().is_none());
}

#[test]
fn capture_next() {
    let mut cluster = TestCluster::new(1);
    let mut metrics = Metrics::new("test", MetricsAction::Skip, TestPlatform::default());
    // Make a regular request to the leader.
    let (_handshake, res1) = cluster.hsms[0].app_request(
        &cluster.store,
        cluster.realm,
        cluster.group,
        RecordId([3; 32]),
        SecretsRequest::Delete,
    );
    let (_handshake, res2) = cluster.hsms[0].app_request(
        &cluster.store,
        cluster.realm,
        cluster.group,
        RecordId([3; 32]),
        SecretsRequest::Delete,
    );
    assert_eq!(
        CaptureNextResponse::MissingEntries,
        cluster.hsms[0].hsm.handle_capture_next(
            &mut metrics,
            CaptureNextRequest {
                realm: cluster.realm,
                group: cluster.group,
                entries: Vec::new(),
            },
        )
    );
    let (log_entry, _delta) = unpack_app_response(&res1);
    assert_eq!(
        CaptureNextResponse::InvalidRealm,
        cluster.hsms[0].hsm.handle_capture_next(
            &mut metrics,
            CaptureNextRequest {
                realm: RealmId([42; 16]),
                group: cluster.group,
                entries: vec![log_entry.clone()],
            },
        )
    );
    assert_eq!(
        CaptureNextResponse::InvalidGroup,
        cluster.hsms[0].hsm.handle_capture_next(
            &mut metrics,
            CaptureNextRequest {
                realm: cluster.realm,
                group: GroupId([42; 16]),
                entries: vec![log_entry.clone()],
            },
        )
    );
    assert_eq!(
        CaptureNextResponse::InvalidMac,
        cluster.hsms[0].hsm.handle_capture_next(
            &mut metrics,
            CaptureNextRequest {
                realm: cluster.realm,
                group: cluster.group,
                entries: vec![LogEntry {
                    entry_mac: EntryMac::from([42; 32]),
                    ..log_entry.clone()
                }],
            },
        )
    );

    let (log_entry, _delta) = unpack_app_response(&res2);
    assert_eq!(
        CaptureNextResponse::MissingPrev,
        cluster.hsms[0].hsm.handle_capture_next(
            &mut metrics,
            CaptureNextRequest {
                realm: cluster.realm,
                group: cluster.group,
                entries: vec![log_entry.clone()],
            },
        )
    );
    let bad_prev_mac_entry = LogEntryBuilder {
        hsm: cluster.hsms[0].id,
        realm: cluster.realm,
        group: cluster.group,
        index: LogIndex(2),
        partition: log_entry.partition,
        transferring: None,
        prev_mac: EntryMac::from([42; 32]),
    }
    .build(&cluster.hsms[0].hsm.realm_keys.mac);
    assert_eq!(
        CaptureNextResponse::InvalidChain,
        cluster.hsms[0].hsm.handle_capture_next(
            &mut metrics,
            CaptureNextRequest {
                realm: cluster.realm,
                group: cluster.group,
                entries: vec![bad_prev_mac_entry],
            },
        )
    );

    let (log_entry1, _delta) = unpack_app_response(&res1);
    let (log_entry2, _delta) = unpack_app_response(&res2);
    assert!(matches!(
        cluster.hsms[0].hsm.handle_capture_next(
            &mut metrics,
            CaptureNextRequest {
                realm: cluster.realm,
                group: cluster.group,
                entries: vec![log_entry1, log_entry2]
            }
        ),
        CaptureNextResponse::Ok(RoleStatus {
            role: GroupMemberRole::Leader { .. },
            ..
        }),
    ));
}

#[test]
fn persist_captures() {
    // captured entries don't count until they're persisted.
    let mut cluster = TestCluster::new(1);
    let mut metrics = Metrics::new("test", MetricsAction::Skip, TestPlatform::default());
    let (_handshake, res) = cluster.hsms[0].app_request(
        &cluster.store,
        cluster.realm,
        cluster.group,
        RecordId([3; 32]),
        SecretsRequest::Delete,
    );
    assert_eq!(
        LogIndex::FIRST,
        cluster.hsms[0].status().realm.unwrap().groups[0]
            .captured
            .as_ref()
            .unwrap()
            .0
    );
    let PersistStateResponse::Ok { captured } = cluster.hsms[0]
        .hsm
        .handle_persist_state(&mut metrics, PersistStateRequest {});
    assert_eq!(1, captured.len());
    assert_eq!(cluster.hsms[0].id, captured[0].hsm);
    assert_eq!(cluster.realm, captured[0].realm);
    assert_eq!(cluster.group, captured[0].group);
    assert_eq!(LogIndex(1), captured[0].index);

    let (log_entry, _delta) = unpack_app_response(&res);
    cluster.hsms[0].hsm.handle_capture_next(
        &mut metrics,
        CaptureNextRequest {
            realm: cluster.realm,
            group: cluster.group,
            entries: vec![log_entry.clone()],
        },
    );
    assert_eq!(
        LogIndex::FIRST,
        cluster.hsms[0].status().realm.unwrap().groups[0]
            .captured
            .as_ref()
            .unwrap()
            .0
    );
    let PersistStateResponse::Ok { captured } = cluster.hsms[0]
        .hsm
        .handle_persist_state(&mut metrics, PersistStateRequest {});
    assert_eq!(1, captured.len());
    assert_eq!(cluster.hsms[0].id, captured[0].hsm);
    assert_eq!(cluster.realm, captured[0].realm);
    assert_eq!(cluster.group, captured[0].group);
    assert_eq!(LogIndex(2), captured[0].index);
    assert_eq!(log_entry.entry_mac, captured[0].mac);

    assert_eq!(
        &(LogIndex(2), log_entry.entry_mac),
        cluster.hsms[0].status().realm.unwrap().groups[0]
            .captured
            .as_ref()
            .unwrap()
    );
}

#[test]
fn commit_captures_verified() {
    // Commit should verify that the captures supplied are for the realm/group
    // and have a valid mac.

    let mut cluster = TestCluster::new(3);
    let mut metrics = Metrics::new("test", MetricsAction::Skip, TestPlatform::default());

    // Make a regular request to the leader.
    let (_handshake, res) = cluster.hsms[0].app_request(
        &cluster.store,
        cluster.realm,
        cluster.group,
        RecordId([3; 32]),
        SecretsRequest::Delete,
    );
    cluster.append(cluster.group, &res);
    cluster.capture_next(cluster.group);
    // this includes captures for all groups.
    let captures: Vec<Captured> = cluster
        .hsms
        .iter_mut()
        .flat_map(|hsm| hsm.persist_state())
        .collect();

    // can't commit a bogus realm or group
    assert!(matches!(
        cluster.hsms[0].hsm.handle_commit(
            &mut metrics,
            CommitRequest {
                realm: RealmId([3; 16]),
                group: cluster.group,
                captures: captures.clone(),
            },
        ),
        CommitResponse::InvalidRealm
    ));
    assert!(matches!(
        cluster.hsms[0].hsm.handle_commit(
            &mut metrics,
            CommitRequest {
                realm: cluster.realm,
                group: GroupId([2; 16]),
                captures: captures.clone(),
            },
        ),
        CommitResponse::InvalidGroup
    ));

    // Can't use captures from other groups.
    assert!(matches!(
        cluster.hsms[0].hsm.handle_commit(
            &mut metrics,
            CommitRequest {
                realm: cluster.realm,
                group: cluster.group,
                captures: captures
                    .iter()
                    .filter(|c| c.group != cluster.group)
                    .cloned()
                    .collect(),
            },
        ),
        CommitResponse::NoQuorum
    ));

    // Can't commit without a majority
    assert!(matches!(
        cluster.hsms[0].hsm.handle_commit(
            &mut metrics,
            CommitRequest {
                realm: cluster.realm,
                group: cluster.group,
                captures: captures
                    .iter()
                    .filter(|c| c.group == cluster.group)
                    .take(1)
                    .cloned()
                    .collect(),
            },
        ),
        CommitResponse::NoQuorum
    ));

    // Can't commit with bad capture statement
    assert!(matches!(
        cluster.hsms[0].hsm.handle_commit(
            &mut metrics,
            CommitRequest {
                realm: cluster.realm,
                group: cluster.group,
                captures: captures
                    .iter()
                    .filter(|c| c.group == cluster.group)
                    .map(|c| {
                        Captured {
                            index: c.index.next(),
                            ..c.clone()
                        }
                    })
                    .collect(),
            },
        ),
        CommitResponse::NoQuorum
    ));

    // Can't commit if we're not leader
    assert!(matches!(
        cluster.hsms[1].hsm.handle_commit(
            &mut metrics,
            CommitRequest {
                realm: cluster.realm,
                group: cluster.group,
                captures: captures.clone(),
            },
        ),
        CommitResponse::NotLeader(RoleStatus {
            role: GroupMemberRole::Witness,
            at: _,
        })
    ));

    // Can commit with the good captures
    let state = cluster.hsms[0].commit(cluster.realm, cluster.group, captures.clone());
    assert_eq!(LogIndex(4), state.committed);
    assert!(matches!(state.role.role, GroupMemberRole::Leader { .. }));
    assert!(state.abandoned.is_empty());
    assert_eq!(1, state.responses.len());

    // We can commit the same index again, but the response has already been delivered.
    let state = cluster.hsms[0].commit(cluster.realm, cluster.group, captures);
    assert_eq!(LogIndex(4), state.committed);
    assert!(matches!(state.role.role, GroupMemberRole::Leader { .. }));
    assert!(state.abandoned.is_empty());
    assert!(state.responses.is_empty());
}

#[test]
fn can_commit_from_other_captures() {
    // The leader should be able to commit entries using captures from other
    // HSMs even if it hasn't itself captured to that entry yet.

    let mut cluster = TestCluster::new(3);

    let committed = cluster.commit(cluster.group);
    assert_eq!(1, committed.len());
    let commit_index = committed[0].committed;

    // Make a regular request to the leader.
    let (handshake, res) = cluster.hsms[0].app_request(
        &cluster.store,
        cluster.realm,
        cluster.group,
        RecordId([3; 32]),
        SecretsRequest::Delete,
    );
    let (entry, delta) = unpack_app_response(&res);
    cluster.store.append(cluster.group, entry.clone(), delta);

    // Entry is not captured yet, commit shouldn't find anything new.
    let committed = cluster.commit(cluster.group);
    assert_eq!(1, committed.len());
    assert_eq!(commit_index, committed[0].committed);

    // We can capture on the other HSMs and commit, even if the leader
    // hasn't captured yet.
    for hsm in &mut cluster.hsms[1..] {
        hsm.capture_next(&cluster.store, cluster.realm, cluster.group);
    }
    let committed = cluster.commit(cluster.group);
    assert_eq!(1, committed.len());
    let committed = &committed[0];
    assert_eq!(committed.committed, entry.index);
    assert!(matches!(
        committed.role.role,
        GroupMemberRole::Leader { .. }
    ));
    assert_eq!(1, committed.responses.len());
    assert_eq!(entry.entry_mac, committed.responses[0].0);
    assert!(matches!(
        finish_handshake(handshake, &committed.responses[0].1),
        SecretsResponse::Delete(DeleteResponse::Ok)
    ));
    assert!(committed.abandoned.is_empty());

    // The leader captures, commit shouldn't do anything as the entry is
    // already committed.
    cluster.hsms[0].capture_next(&cluster.store, cluster.realm, cluster.group);
    let captures = cluster.persist_state(cluster.group);
    let committed2 = cluster.hsms[0].commit(cluster.realm, cluster.group, captures);
    assert_eq!(committed.committed, committed2.committed);
    assert!(committed2.responses.is_empty());
    assert!(committed2.abandoned.is_empty());
    assert!(matches!(
        committed2.role.role,
        GroupMemberRole::Leader { .. }
    ));
}

#[test]
fn app_request_spots_future_log() {
    // During app_request a HSM can detect that some other HSM wrote
    // a log entry (by looking at the log index) and step down at that point.

    let mut cluster = TestCluster::new(2);
    // Make both HSMs leader.
    let last_entry = cluster.store.latest_log(&cluster.group);

    let hsm_role_clocks: Vec<RoleLogicalClock> = cluster
        .hsms
        .iter_mut()
        .map(|hsm| {
            let res = hsm.become_leader(cluster.realm, cluster.group, last_entry.clone());
            if let BecomeLeaderResponse::Ok { role } = res {
                role.at
            } else {
                panic!("hsm should of responded with Ok to become_leader, but got {res:?}");
            }
        })
        .collect();

    // Ensure everyone has committed the current log.
    cluster.capture_next_and_commit_group(cluster.group);

    // Have the first HSM handle a request and write it to the store.
    let (_handshake, res) = cluster.hsms[0].app_request(
        &cluster.store,
        cluster.realm,
        cluster.group,
        RecordId([3; 32]),
        SecretsRequest::Delete,
    );
    cluster.append(cluster.group, &res);

    // Have the other HSM try to handle a request, it should spot
    // that the LogIndex is higher than anything it generated.
    let (_, res) = cluster.hsms[1].app_request(
        &cluster.store,
        cluster.realm,
        cluster.group,
        RecordId([3; 32]),
        SecretsRequest::Delete,
    );
    // The 2nd HSM should of stepped down to Witness.
    assert!(
        matches!(
            res,
            AppResponse::NotLeader(RoleStatus {
                role: GroupMemberRole::Witness,
                at
            }) if at > hsm_role_clocks[1]
        ),
        "app_request unexpected result: {res:?}"
    );
}

#[test]
fn capture_next_spots_diverged_log_no_inflight_reqs() {
    // During capture_next processing a leading HSM should spot that its in
    // memory log has diverged from the externally persisted log. If this
    // HSM has no uncommitted log entries, it can step down to Witness at
    // this point.

    let mut cluster = TestCluster::new(2);

    // Make a request to hsms[0] (the original leader) and commit it.
    let (_, res) = cluster.hsms[0].app_request(
        &cluster.store,
        cluster.realm,
        cluster.group,
        RecordId([4; 32]),
        SecretsRequest::Register1,
    );
    cluster.append(cluster.group, &res);
    cluster.capture_next_and_commit_group(cluster.group);

    // Make hsms[1] also a leader.
    let last_entry = cluster.store.latest_log(&cluster.group);
    let res = cluster.hsms[1].become_leader(cluster.realm, cluster.group, last_entry);
    assert!(matches!(res, BecomeLeaderResponse::Ok { .. }));

    // Have hsms[1] handle a request and write it to the store.
    let (_, res) = cluster.hsms[1].app_request(
        &cluster.store,
        cluster.realm,
        cluster.group,
        RecordId([4; 32]),
        SecretsRequest::Recover1,
    );
    cluster.append(cluster.group, &res);

    // When the first HSM captures this new entry from a different leader it
    // should stand down. As it has no requests left to commit, it can go
    // straight to Witness.
    let clock = cluster.hsms[0].role_clock(cluster.group);
    assert!(matches!(
        cluster.hsms[0].capture_next(&cluster.store, cluster.realm, cluster.group),
        Some(RoleStatus {
            role: GroupMemberRole::Witness,
            at
        }) if at > clock,
    ));
}

#[test]
fn capture_next_spots_diverged_log() {
    // During capture_next processing a leading HSM should spot that its in
    // memory log has diverged from the externally persisted log. If this
    // HSM has uncommitted log entries after the divergence point, it can
    // transition to stepping down and those uncommitted entries should be
    // flagged as abandoned during the next commit.
    //
    // This also covers the case where the log diverges at the first new
    // entry in the log after becoming leader.

    let mut cluster = TestCluster::new(3);
    // Make all the HSMs leader.
    let last = cluster.store.latest_log(&cluster.group);
    let mut hsm_role_clocks: Vec<RoleLogicalClock> = cluster
        .hsms
        .iter_mut()
        .map(|hsm| {
            let res = hsm.become_leader(cluster.realm, cluster.group, last.clone());
            if let BecomeLeaderResponse::Ok { role } = res {
                role.at
            } else {
                panic!("hsm should of responded with Ok to become_leader, but got {res:?}");
            }
        })
        .collect();

    // They all should be able to commit the existing log.
    cluster.commit(cluster.group);

    // Have them all handle an app request.
    let responses: Vec<AppResponse> = cluster
        .hsms
        .iter_mut()
        .map(|hsm| {
            let (_, r) = hsm.app_request(
                &cluster.store,
                cluster.realm,
                cluster.group,
                RecordId([3; 32]),
                SecretsRequest::Delete,
            );
            // Everyone thinks they're leader, these should all succeed.
            assert!(matches!(r, AppResponse::Ok { .. }));
            r
        })
        .collect();

    // hsm[0] wins the log append battle.
    cluster.append(cluster.group, &responses[0]);

    // hsm[0] should happily capture next and think its still leader.
    assert!(matches!(
        cluster.hsms[0].capture_next(&cluster.store, cluster.realm, cluster.group),
        Some(RoleStatus {
            role: GroupMemberRole::Leader{..},
            at
        }) if at == hsm_role_clocks[0],
    ));

    // The other HSMs should stand down. They have uncommitted entries but
    // they can't be committed. The HSM should transition to stepping down
    // and report these uncommitted entries as abandoned.
    for (hsm, role_clock) in zip(&mut cluster.hsms[1..], hsm_role_clocks.iter_mut()) {
        let res = hsm.capture_next(&cluster.store, cluster.realm, cluster.group);
        if let Some(RoleStatus {
            role: GroupMemberRole::SteppingDown { .. },
            at,
        }) = res
        {
            assert!(at > *role_clock);
            *role_clock = at;
        } else {
            panic!("Unexpected response from capture next {res:?}")
        }
    }
    let captures = cluster.persist_state(cluster.group);
    for (hsm, role_clock) in zip(&mut cluster.hsms[1..], hsm_role_clocks.iter()) {
        let res = hsm.commit(cluster.realm, cluster.group, captures.clone());
        assert!(res.responses.is_empty());
        assert_eq!(1, res.abandoned.len());
        // Nothing left for commit to do, transition back to Witness.
        assert_eq!(res.role.role, GroupMemberRole::Witness);
        assert!(res.role.at > *role_clock);
    }
}

#[test]
fn capture_next_spots_diverged_log_pipelined() {
    // During capture_next processing a leading HSM should spot that its in
    // memory log has diverged from the externally persisted log. The HSM
    // can start stepping down at this point. There may be entries after the
    // divergence point that should be abandoned. There may also be valid
    // uncommitted entries before the divergence point that can still be
    // committed.

    let mut cluster = TestCluster::new(3);

    // Have the leader handle a series of (pipelined) requests.
    let leader1_responses: Vec<AppResponse> = iter::repeat_with(|| {
        cluster.hsms[0]
            .app_request(
                &cluster.store,
                cluster.realm,
                cluster.group,
                RecordId([3; 32]),
                SecretsRequest::Delete,
            )
            .1
    })
    .take(5)
    .collect();
    // The first 2 of these are successfully written to the log.
    cluster.append(cluster.group, &leader1_responses[0]);
    cluster.append(cluster.group, &leader1_responses[1]);

    // Make another HSM also leader.
    let last = cluster.store.latest_log(&cluster.group);
    cluster.hsms[1].capture_next(&cluster.store, cluster.realm, cluster.group);
    let r = cluster.hsms[1].become_leader(cluster.realm, cluster.group, last.clone());
    assert!(matches!(r, BecomeLeaderResponse::Ok { .. }),);

    // Have it handle an app request.
    let (_, leader2_response) = cluster.hsms[1].app_request(
        &cluster.store,
        cluster.realm,
        cluster.group,
        RecordId([3; 32]),
        SecretsRequest::Delete,
    );
    // hsm[1] wins the append battle.
    cluster.append(cluster.group, &leader2_response);

    // When hsm[0] (the original leader) captures the log it should spot
    // that it diverged and start stepping down.
    let clock = cluster.hsms[0].role_clock(cluster.group);
    assert!(matches!(
        cluster.hsms[0]
            .capture_next(&cluster.store, cluster.realm, cluster.group),
        Some(RoleStatus{
            role:GroupMemberRole::SteppingDown{..},
            at}
        ) if at > clock
    ));

    // hsm[0] is stepping down and should commit the log entries that it
    // successfully wrote to the log.
    let clock = cluster.hsms[0].role_clock(cluster.group);
    let captures = cluster.persist_state(cluster.group);
    let commit = cluster.hsms[0].commit(cluster.realm, cluster.group, captures);
    // The first leader should of committed the first 2 responses it generated.
    let (entry, _) = unpack_app_response(&leader1_responses[0]);
    assert!(commit.responses.iter().any(|r| r.0 == entry.entry_mac));
    assert!(!commit.abandoned.contains(&entry.entry_mac));

    let (entry, _) = unpack_app_response(&leader1_responses[1]);
    assert!(commit.responses.iter().any(|r| r.0 == entry.entry_mac));
    assert!(!commit.abandoned.contains(&entry.entry_mac));
    assert_eq!(commit.committed, entry.index);

    // The other requests it handled should be flagged as abandoned, they'll never get committed.
    for ar in &leader1_responses[2..] {
        let (entry, _) = unpack_app_response(ar);
        assert!(commit.abandoned.contains(&entry.entry_mac));
    }
    assert_eq!(3, commit.abandoned.len());
    // its committed everything it can, it can now go back to being a witness.
    assert_eq!(commit.role.role, GroupMemberRole::Witness);
    assert!(commit.role.at > clock);

    // hsm[1] should be able to commit the new entry it wrote once capture_next has caught up.
    cluster.capture_next(cluster.group);
    let captures = cluster.persist_state(cluster.group);
    let commit = cluster.hsms[1].commit(cluster.realm, cluster.group, captures.clone());
    let (entry, _) = unpack_app_response(&leader2_response);
    assert_eq!(entry.index, commit.committed);
    assert_eq!(1, commit.responses.len());
    assert_eq!(entry.entry_mac, commit.responses[0].0);
    assert!(commit.abandoned.is_empty());
    assert!(matches!(commit.role.role, GroupMemberRole::Leader { .. }));
}

#[test]
fn capture_next_spots_diverged_log_while_stepping_down() {
    // A Leading HSM has a number of uncommitted log entries when it is
    // asked to stepdown. While in this stepping down process, capture_next
    // spots that the log has diverged. The stepping down index should be
    // shortened to just before the divergence point, and anything after
    // that should be flagged as abandoned.

    let mut cluster = TestCluster::new(3);
    // Have the leader handle a series of (pipelined) requests.
    let leader1_responses: Vec<AppResponse> = iter::repeat_with(|| {
        cluster.hsms[0]
            .app_request(
                &cluster.store,
                cluster.realm,
                cluster.group,
                RecordId([3; 32]),
                SecretsRequest::Delete,
            )
            .1
    })
    .take(5)
    .collect();

    // Ask the HSM to gracefully step down.
    let mut clock = cluster.hsms[0].role_clock(cluster.group);
    let res = cluster.hsms[0].stepdown_as_leader(cluster.realm, cluster.group);
    if let StepDownResponse::Ok {
        role:
            RoleStatus {
                role: GroupMemberRole::SteppingDown { .. },
                at,
            },
        ..
    } = res
    {
        assert!(at > clock);
        clock = at;
    } else {
        panic!("Unexpected response to stepdown {res:?}");
    }

    // The first request is successfully written to the log.
    cluster.append(cluster.group, &leader1_responses[0]);
    // Should be able to capture & commit this fine.
    cluster.capture_next(cluster.group);
    let captures = cluster.persist_state(cluster.group);
    let res = cluster.hsms[0].commit(cluster.realm, cluster.group, captures);
    assert!(res.abandoned.is_empty());
    assert_eq!(1, res.responses.len());
    let (entry, _) = unpack_app_response(&leader1_responses[0]);
    assert_eq!(entry.entry_mac, res.responses[0].0);
    assert_eq!(entry.index, res.committed);
    assert!(matches!(
        res.role.role,
        GroupMemberRole::SteppingDown { .. }
    ));
    assert_eq!(res.role.at, clock);

    // Write the 2nd request to the log.
    cluster.append(cluster.group, &leader1_responses[1]);

    // Ask another HSM to also be leader.
    cluster.hsms[1].capture_next(&cluster.store, cluster.realm, cluster.group);
    let last_entry = cluster.store.latest_log(&cluster.group);
    let res = cluster.hsms[1].become_leader(cluster.realm, cluster.group, last_entry);
    assert!(matches!(res, BecomeLeaderResponse::Ok { .. }));

    // Have the new leader process a request and write to the log
    let (_, leader2_response) = cluster.hsms[1].app_request(
        &cluster.store,
        cluster.realm,
        cluster.group,
        RecordId([4; 32]),
        SecretsRequest::Register1,
    );
    cluster.append(cluster.group, &leader2_response);

    // hsms[0] capture next sees this diverged log. Its still stepping down.
    let res = cluster.hsms[0].capture_next(&cluster.store, cluster.realm, cluster.group);
    assert!(res.is_some_and(
        |rs| rs.at == clock && matches!(rs.role, GroupMemberRole::SteppingDown { .. })
    ));

    cluster.capture_next(cluster.group);
    let captures = cluster.persist_state(cluster.group);
    // Commit on hsms[0] should release the one entry that got persisted and
    // abandon the later ones.
    let mut res = cluster.hsms[0].commit(cluster.realm, cluster.group, captures);
    assert_eq!(res.role.role, GroupMemberRole::Witness);
    assert!(res.role.at > clock);
    let (entry2, _) = unpack_app_response(&leader1_responses[1]);
    assert_eq!(1, res.responses.len());
    assert_eq!(entry2.entry_mac, res.responses[0].0);
    // Everyone captured the log entry written by the new leader. But the
    // stepping down leader shouldn't commit past its stepping_down point.
    assert_eq!(entry2.index, res.committed);

    res.abandoned.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let mut expected: Vec<EntryMac> = leader1_responses[2..]
        .iter()
        .map(|r| unpack_app_response(r).0.entry_mac)
        .collect();
    expected.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(expected, res.abandoned);
}

#[test]
fn can_join_realm_already_member_of() {
    let mut cluster = TestCluster::new(2);
    let s = cluster.hsms[0].status();
    let stmt = s.realm.map(|r| r.statement).unwrap();
    let mut metrics = Metrics::new("test", MetricsAction::Skip, TestPlatform::default());
    let r = cluster.hsms[1].hsm.handle_join_realm(
        &mut metrics,
        JoinRealmRequest {
            realm: cluster.realm,
            peer: s.id,
            statement: stmt,
        },
    );
    assert!(matches!(r, JoinRealmResponse::Ok { hsm: _ }));
}

#[test]
fn can_join_group_already_joined() {
    let mut cluster = TestCluster::new(2);
    let mut metrics = Metrics::new("test", MetricsAction::Skip, TestPlatform::default());

    let mut members: Vec<(HsmId, HsmRealmStatement)> = cluster
        .hsms
        .iter_mut()
        .map(|h| h.status())
        .map(|s| (s.id, s.realm.unwrap().statement))
        .collect();
    members.sort_by_key(|m| m.0);

    let new_group_response = cluster.hsms[0].hsm.handle_new_group(
        &mut metrics,
        NewGroupRequest {
            realm: cluster.realm,
            members: members.clone(),
        },
    );
    let NewGroupResponse::Ok {
        group,
        statement,
        entry: log_entry,
        role: _,
    } = new_group_response
    else {
        panic!("Unexpected response to new group {:?}", new_group_response)
    };
    cluster
        .store
        .append(group, log_entry.clone(), StoreDelta::default());

    let jr = cluster.hsms[1].hsm.handle_join_group(
        &mut metrics,
        JoinGroupRequest {
            realm: cluster.realm,
            group,
            configuration: members.iter().map(|x| x.0).collect(),
            statement: statement.clone(),
        },
    );
    assert!(matches!(jr, JoinGroupResponse::Ok(_)));
    cluster.capture_next_and_commit_group(group);

    // make hsm[1] leader, this will update its internal role state

    let become_leader_response = cluster.hsms[1].become_leader(cluster.realm, group, log_entry);
    let BecomeLeaderResponse::Ok { role } = become_leader_response else {
        panic!("failed to become leader {become_leader_response:?}");
    };
    assert!(role.at > RoleLogicalClock::start());

    // telling it to join a group its already a member of shouldn't overwrite its existing role state.
    let jr = cluster.hsms[1].hsm.handle_join_group(
        &mut metrics,
        JoinGroupRequest {
            realm: cluster.realm,
            group,
            configuration: members.iter().map(|x| x.0).collect(),
            statement,
        },
    );
    assert!(matches!(jr, JoinGroupResponse::Ok(_)));
    let r = cluster.hsms[1].hsm.volatile.groups.get(&group).unwrap();
    assert_eq!(r.at, role.at);
}

#[test]
fn transfer_protocol() {
    let mut cluster = TestCluster::new(2);
    let mut metrics = Metrics::new("test", MetricsAction::Skip, TestPlatform::default());
    let realm = cluster.realm;
    let source = cluster.group;
    let destination = cluster.init_group;

    let mut t = OwnershipTransfer::new(
        &mut cluster,
        source,
        destination,
        OwnedRange {
            start: RecordId([0; 32]),
            end: RecordId([1; 32]),
        },
        false,
    );
    let prepared = match t.prepare() {
        PrepareTransferResponse::Ok(prepared) => {
            assert!(prepared.entry.is_some());
            let entry = prepared.entry.as_ref().unwrap();
            assert_eq!(entry.index, prepared.wait_til_committed);
            assert!(entry.transferring.is_some());
            prepared
        }
        other => panic!("Unexpected response from prepare_transfer {other:?}"),
    };

    // We can prepare the same transfer again, we should get a new nonce.
    let prepared = match t.prepare() {
        PrepareTransferResponse::Ok(new_prepared) => {
            assert!(new_prepared.entry.is_none());
            assert_ne!(prepared.nonce, new_prepared.nonce);
            new_prepared
        }
        other => panic!("Unexpected response from prepare_transfer {other:?}"),
    };

    // Can't prepare a different transfer
    match t
        .cluster
        .leader(destination)
        .unwrap()
        .hsm
        .handle_prepare_transfer(
            &mut metrics,
            PrepareTransferRequest {
                realm,
                source,
                destination,
                range: OwnedRange {
                    start: RecordId([45; 32]),
                    end: RecordId::max_id(),
                },
            },
        ) {
        PrepareTransferResponse::OtherTransferPending => {}
        other => panic!("Unexpected response from prepare_transfer {other:?}"),
    }

    let group3 = t.cluster.new_group();
    let group3_prep = match t
        .cluster
        .leader(group3)
        .unwrap()
        .hsm
        .handle_prepare_transfer(
            &mut metrics,
            PrepareTransferRequest {
                realm,
                source: destination,
                destination: group3,
                range: OwnedRange::full(),
            },
        ) {
        PrepareTransferResponse::Ok(prep) => prep,
        other => panic!("Unexpected response from prepare_transfer {other:?}"),
    };

    // The destination can't do a transfer out while a transfer in is pending
    match t
        .cluster
        .leader(destination)
        .unwrap()
        .hsm
        .handle_transfer_out(
            &mut metrics,
            TransferOutRequest {
                realm,
                source: destination,
                destination: group3,
                range: OwnedRange::full(),
                nonce: group3_prep.nonce,
                statement: group3_prep.statement.clone(),
                proof: None,
            },
        ) {
        TransferOutResponse::OtherTransferPending => {}
        other => panic!("transfer_out should of errored with TransferPending but got {other:?}"),
    }

    // now ask the source to transfer out
    let transferring_partition = match t.transfer_out() {
        TransferOutResponse::Ok {
            entry,
            delta,
            partition,
            wait_til_committed: after,
            ..
        } => {
            assert!(entry.is_some());
            assert!(!delta.is_empty());
            assert_eq!(entry.unwrap().index, after);
            assert_eq!(partition.range, t.range);
            partition
        }
        other => panic!("transfer out failed {other:?}"),
    };

    // we can ask the source to do the same transfer out again.
    match t.transfer_out() {
        TransferOutResponse::Ok {
            entry,
            delta,
            partition,
            wait_til_committed: _,
            clock: _,
        } => {
            assert!(entry.is_none());
            assert!(delta.is_empty());
            assert_eq!(partition.range, t.range);
            assert_eq!(partition, transferring_partition);
        }
        other => panic!("transfer out failed {other:?}"),
    };

    // the source should verify the prepared transfer statement.
    let nonce = t.prepared.as_ref().unwrap().nonce;
    t.prepared.as_mut().unwrap().nonce = TransferNonce([42; 16]);
    match t.transfer_out() {
        TransferOutResponse::InvalidStatement => {}
        other => panic!("transfer out failed {other:?}"),
    }
    t.prepared.as_mut().unwrap().nonce = nonce;

    // we can't ask the source to do a different transfer out now until this one is completed.
    let third_group = t.cluster.new_group();
    let third_prepared = match t
        .cluster
        .leader(third_group)
        .unwrap()
        .hsm
        .handle_prepare_transfer(
            &mut metrics,
            PrepareTransferRequest {
                realm,
                source,
                destination: third_group,
                range: OwnedRange::full(),
            },
        ) {
        PrepareTransferResponse::Ok(p) => p,
        other => panic!("prepare transfer failed {other:?}"),
    };

    match t.cluster.leader(source).unwrap().hsm.handle_transfer_out(
        &mut metrics,
        TransferOutRequest {
            realm,
            source,
            destination: third_group,
            range: OwnedRange::full(),
            nonce: third_prepared.nonce,
            statement: third_prepared.statement,
            proof: None,
        },
    ) {
        TransferOutResponse::OtherTransferPending => {}
        other => panic!("unexpected transfer_out response {other:?}"),
    }

    // we can't get a transfer statement until the entry is committed.
    match t.transfer_statement() {
        TransferStatementResponse::Busy => {}
        other => panic!("unexpected transfer_statement response {other:?}"),
    };

    t.cluster.capture_next_and_commit_group(source);
    let stmt = match t.transfer_statement() {
        TransferStatementResponse::Ok(stmt) => stmt,
        other => panic!("unexpected transfer_statement response {other:?}"),
    };

    // the destination should only let us transfer in the transfer that was prepared.
    match t
        .cluster
        .leader(destination)
        .unwrap()
        .hsm
        .handle_transfer_in(
            &mut metrics,
            TransferInRequest {
                realm,
                source: GroupId([12; 16]),
                destination,
                transferring: transferring_partition.clone(),
                proofs: None,
                nonce: prepared.nonce,
                statement: stmt.clone(),
            },
        ) {
        TransferInResponse::NotPrepared => {}
        other => panic!("unexpected transfer_in response {other:?}"),
    }

    // but should let us transfer in the transfer that was previously prepared.
    match t.transfer_in() {
        TransferInResponse::Ok {
            entry,
            delta,
            clock: _,
        } => {
            assert!(entry.transferring.is_none());
            // The destination group didn't own anything to start with, so
            // there's no tree merge, and no resulting tree delta.
            assert!(delta.is_empty());
            t.cluster.capture_next_and_commit_group(destination);
        }
        other => panic!("unexpected transfer_in response {other:?}"),
    }

    // and finally, we should be able to tell the source the transfer completed.
    match t.complete_transfer() {
        CompleteTransferResponse::Ok { entry, .. } => {
            assert!(entry.transferring.is_none());
            cluster.capture_next_and_commit_group(source);
        }
        other => panic!("unexpected complete transfer response {other:?}"),
    }
}

#[test]
fn transfer_protocol_with_merge() {
    let mut cluster = TestCluster::new(2);
    let source = cluster.group;
    let destination = cluster.init_group;
    let mut t = OwnershipTransfer::new(
        &mut cluster,
        source,
        destination,
        OwnedRange {
            start: RecordId([0; 32]),
            end: RecordId([1; 32]),
        },
        true,
    );
    t.do_transfer();

    let mut t = OwnershipTransfer::new(
        &mut cluster,
        source,
        destination,
        OwnedRange {
            start: RecordId([1; 32]).next().unwrap(),
            end: RecordId([4; 32]),
        },
        true,
    );
    t.do_transfer();

    let dest_exp_range = OwnedRange {
        start: RecordId::min_id(),
        end: t.range.end.clone(),
    };
    let status = t.cluster.leader(destination).unwrap().status();
    assert!(
        status
            .realm
            .as_ref()
            .is_some_and(|rs| rs.groups.iter().any(|gs| gs.id == destination
                && gs.leader.as_ref().unwrap().owned_range == Some(dest_exp_range.clone()))),
        "{status:?}"
    );

    let source_exp_range = OwnedRange {
        start: t.range.end.next().unwrap(),
        end: RecordId::max_id(),
    };
    let status = t.cluster.leader(source).unwrap().status();
    assert!(
        status
            .realm
            .as_ref()
            .is_some_and(|rs| rs.groups.iter().any(|gs| gs.id == source
                && gs.leader.as_ref().unwrap().owned_range == Some(source_exp_range.clone()))),
        "{status:?}"
    );
}

#[test]
fn transfer_protocol_source_leadership_changes() {
    // The leader for the source group changes between transferOut and transferStatement
    let mut cluster = TestCluster::new(3);
    let source = cluster.group;
    let destination = cluster.init_group;
    let mut t = OwnershipTransfer::new(
        &mut cluster,
        source,
        destination,
        OwnedRange {
            start: RecordId([0; 32]),
            end: RecordId([45; 32]),
        },
        true,
    );
    match t.prepare() {
        PrepareTransferResponse::Ok { .. } => {}
        other => panic!("prepare failed {other:?}"),
    }
    match t.transfer_out() {
        TransferOutResponse::Ok { .. } => {}
        other => panic!("transfer out failed {other:?}"),
    }
    match t
        .cluster
        .leader(source)
        .unwrap()
        .stepdown_as_leader(t.realm, source)
    {
        StepDownResponse::Ok { .. } => {}
        other => panic!("step down failed {other:?}"),
    }

    let last_entry = t.cluster.store.latest_log(&source);
    match t.cluster.hsms[2].become_leader(t.realm, source, last_entry) {
        BecomeLeaderResponse::Ok { .. } => {}
        other => panic!("become leader failed {other:?}"),
    }

    // The transfer statement request will return busy until the new leader has
    // calculated the commit index.
    match t.transfer_statement() {
        TransferStatementResponse::Busy => {}
        other => panic!("transfer statement failed {other:?}"),
    }
    t.cluster.capture_next_and_commit_group(source);
    match t.transfer_statement() {
        TransferStatementResponse::Ok(_) => {}
        other => panic!("transfer statement failed {other:?}"),
    }

    match t.transfer_in() {
        TransferInResponse::Ok { .. } => {}
        other => panic!("transfer in failed {other:?}"),
    }
    match t.complete_transfer() {
        CompleteTransferResponse::Ok { .. } => {}
        other => panic!("complete transfer failed {other:?}"),
    }
}

#[test]
fn transfer_protocol_dest_leadership_changes() {
    // The leader for the destination group changes between prepareTransfer and
    // transferIn.
    let mut cluster = TestCluster::new(3);
    let source = cluster.group;
    let destination = cluster.new_group();
    let mut t = OwnershipTransfer::new(
        &mut cluster,
        source,
        destination,
        OwnedRange {
            start: RecordId([0; 32]),
            end: RecordId([45; 32]),
        },
        true,
    );
    match t.prepare() {
        PrepareTransferResponse::Ok { .. } => {}
        other => panic!("prepare transfer failed {other:?}"),
    }

    match t
        .cluster
        .leader(destination)
        .unwrap()
        .stepdown_as_leader(t.realm, t.destination)
    {
        StepDownResponse::Ok { .. } => {}
        other => panic!("stepdown failed {other:?}"),
    }
    let last_entry = t.cluster.store.latest_log(&destination);
    match t.cluster.hsms[1].become_leader(t.realm, t.destination, last_entry) {
        BecomeLeaderResponse::Ok { .. } => {}
        other => panic!("failed to become leader {other:?}"),
    }

    match t.transfer_out() {
        TransferOutResponse::Ok { .. } => {}
        other => panic!("transfer out failed {other:?}"),
    }
    match t.transfer_statement() {
        TransferStatementResponse::Ok(_) => {}
        other => panic!("transfer statement failed {other:?}"),
    }

    // the new leader doesn't have the nonce that was generated by the first leader.
    match t.transfer_in() {
        TransferInResponse::InvalidNonce => {}
        other => panic!("transfer in failed {other:?}"),
    }
    // At this point the entire process gets retried, and should run to completion.
    t.do_transfer();
}

#[test]
fn test_cancel_prepare_transfer() {
    let mut cluster = TestCluster::new(3);
    let mut metrics = Metrics::new("test", MetricsAction::Skip, TestPlatform::default());
    let source = cluster.group;
    let destination = cluster.new_group();
    let range = OwnedRange {
        start: RecordId([0; 32]),
        end: RecordId([45; 32]),
    };
    let mut t = OwnershipTransfer::new(&mut cluster, source, destination, range.clone(), true);
    match t.prepare() {
        PrepareTransferResponse::Ok { .. } => {}
        other => panic!("prepare transfer failed {other:?}"),
    }
    match t.cancel_prepare() {
        CancelPreparedTransferResponse::Ok { .. } => {}
        other => panic!("cancel prepare transfer failed {other:?}"),
    }
    match t.prepare() {
        PrepareTransferResponse::Ok { .. } => {}
        other => panic!("prepare transfer failed {other:?}"),
    }
    // can't cancel a different transfer
    match t
        .cluster
        .leader(t.destination)
        .unwrap()
        .hsm
        .handle_cancel_prepared_transfer(
            &mut metrics,
            CancelPreparedTransferRequest {
                realm: t.realm,
                source,
                destination,
                range: OwnedRange::full(),
            },
        ) {
        CancelPreparedTransferResponse::NotPrepared => {}
        other => panic!("cancel prepare transfer failed {other:?}"),
    }
    match t.transfer_out() {
        TransferOutResponse::Ok { .. } => {}
        other => panic!("transfer out failed {other:?}"),
    }
    // cancel prepared shouldn't touch the transferOut
    match t
        .cluster
        .leader(t.source)
        .unwrap()
        .hsm
        .handle_cancel_prepared_transfer(
            &mut metrics,
            CancelPreparedTransferRequest {
                realm: t.realm,
                source,
                destination,
                range: OwnedRange::full(),
            },
        ) {
        CancelPreparedTransferResponse::NotPrepared => {}
        other => panic!("cancel prepare transfer failed {other:?}"),
    }
}

fn unpack_app_response(r: &AppResponse) -> (LogEntry, StoreDelta<DataHash>) {
    if let AppResponse::Ok { entry, delta } = r {
        (entry.clone(), delta.clone())
    } else {
        panic!("app_request failed {r:?}")
    }
}

fn finish_handshake(hs: Handshake, resp: &NoiseResponse) -> SecretsResponse {
    if let NoiseResponse::Handshake {
        handshake: result, ..
    } = resp
    {
        let app_res = hs.finish(result).unwrap();
        let padded_secrets_response: PaddedSecretsResponse =
            marshalling::from_slice(&app_res.1).unwrap();
        SecretsResponse::try_from(&padded_secrets_response).unwrap()
    } else {
        panic!("expected a NoiseResponse::Handshake but got {:?}", resp);
    }
}

struct TestCluster<'a> {
    hsms: Vec<TestHsm<'a>>,
    realm: RealmId,
    init_group: GroupId,
    // This is the same as init_group for cluster count=1
    group: GroupId,
    store: TestStore,
}

impl<'a> TestCluster<'a> {
    fn new(count: usize) -> Self {
        let mut k = [0u8; 32];
        OsRng.fill(&mut k);
        let privk = x25519::StaticSecret::from(k);
        let pubk = x25519::PublicKey::from(&privk);
        let keys = RealmKeys {
            record: RecordEncryptionKey(k),
            mac: MacKey::from(k),
            communication: (privk, pubk),
        };

        let mut store = TestStore::default();
        let mut hsms: Vec<_> = (0..count)
            .map(|i| TestHsm::new(format!("hsm_{i}"), keys.clone()))
            .collect();

        let mut m = Metrics::new("test", MetricsAction::Skip, TestPlatform::default());
        let realm = hsms[0].hsm.handle_new_realm(&mut m, NewRealmRequest {});

        let (realm, starting_group) = match realm {
            NewRealmResponse::Ok {
                realm,
                group: starting_group,
                entry,
                delta,
                ..
            } => {
                store.append(starting_group, entry, delta);
                (realm, starting_group)
            }
            NewRealmResponse::HaveRealm => panic!(),
        };

        let realm_statement = hsms[0].status().realm.unwrap().statement;
        let peer = hsms[0].id;
        for hsm in &mut hsms[1..] {
            assert!(matches!(
                hsm.hsm.handle_join_realm(
                    &mut m,
                    JoinRealmRequest {
                        realm,
                        peer,
                        statement: realm_statement.clone(),
                    },
                ),
                JoinRealmResponse::Ok { .. }
            ));
        }

        let mut cluster = TestCluster {
            hsms,
            realm,
            group: starting_group,
            init_group: starting_group,
            store,
        };
        cluster.capture_next_and_commit_group(starting_group);
        if count == 1 {
            return cluster;
        }

        let new_group = cluster.new_group();

        let mut t = OwnershipTransfer::new(
            &mut cluster,
            starting_group,
            new_group,
            OwnedRange::full(),
            true,
        );
        t.do_transfer();

        // We have a group of HSMs all initialized with a group, hsms[0] is the leader.
        cluster.group = new_group;
        cluster
    }

    // Creates a new group with all cluster members as member and have everyone join it.
    fn new_group(&mut self) -> GroupId {
        let mut metrics = Metrics::new("test", MetricsAction::Skip, TestPlatform::default());
        let mut members: Vec<_> = self
            .hsms
            .iter_mut()
            .map(|hsm| {
                let r = hsm.status();
                (r.id, r.realm.unwrap().statement)
            })
            .collect();
        members.sort_by_key(|g| g.0);

        let new_group_resp = self.hsms[0].hsm.handle_new_group(
            &mut metrics,
            NewGroupRequest {
                realm: self.realm,
                members: members.clone(),
            },
        );
        let NewGroupResponse::Ok {
            group: new_group,
            statement,
            entry,
            ..
        } = new_group_resp
        else {
            panic!("new group failed: {:?}", new_group_resp);
        };
        self.store.append(new_group, entry, StoreDelta::default());

        let config: Vec<HsmId> = members.iter().map(|(id, _stmt)| *id).collect();
        for hsm in &mut self.hsms[1..] {
            assert!(matches!(
                hsm.hsm.handle_join_group(
                    &mut hsm.metrics,
                    JoinGroupRequest {
                        realm: self.realm,
                        group: new_group,
                        configuration: config.clone(),
                        statement: statement.clone(),
                    },
                ),
                JoinGroupResponse::Ok(_)
            ));
        }
        new_group
    }

    // Brings each HSM up to date on capture_next and then does a commit.
    fn capture_next_and_commit_group(&mut self, group: GroupId) -> Vec<CommitState> {
        self.capture_next(group);
        self.commit(group)
    }

    fn capture_next(&mut self, group: GroupId) {
        for hsm in self.hsms.iter_mut() {
            if hsm.has_group(group) {
                hsm.capture_next(&self.store, self.realm, group);
            }
        }
    }

    // Collects captures from all cluster members, and asks every HSM that thinks its a leader
    // for the group to do a commit.
    fn commit(&mut self, group: GroupId) -> Vec<CommitState> {
        let captures: Vec<Captured> = self.persist_state(group);

        let mut results = Vec::new();
        for hsm in self.hsms.iter_mut() {
            if hsm.is_leader(group) {
                results.push(hsm.commit(self.realm, group, captures.clone()));
            }
        }
        results
    }

    #[allow(clippy::manual_find)] // hsm.is_leader takes &mut self but find gives you a &&mut
    fn leader(&mut self, group: GroupId) -> Option<&mut TestHsm<'a>> {
        for hsm in self.hsms.iter_mut() {
            if hsm.is_leader(group) {
                return Some(hsm);
            }
        }
        None
    }

    fn persist_state(&mut self, group: GroupId) -> Vec<Captured> {
        self.hsms
            .iter_mut()
            .flat_map(|hsm| hsm.persist_state())
            .filter(|c| c.group == group)
            .collect()
    }

    fn append(&mut self, group: GroupId, r: &AppResponse) {
        if let AppResponse::Ok { entry, delta } = r {
            self.store.append(group, entry.clone(), delta.clone());
        } else {
            panic!("app_request failed {r:?}");
        }
    }
}

struct TestHsm<'a> {
    hsm: Hsm<TestPlatform>,
    next_capture: HashMap<(RealmId, GroupId), LogIndex>,
    metrics: Metrics<'a, TestPlatform>,
    public_key: x25519_dalek::PublicKey,
    id: HsmId,
}

impl<'a> TestHsm<'a> {
    fn new(name: impl Into<String>, keys: RealmKeys) -> Self {
        let opt = HsmOptions {
            name: name.into(),
            tree_overlay_size: 15,
            max_sessions: 15,
            metrics: MetricsReporting::Disabled,
        };
        let public_key = keys.communication.1;
        let hsm = Hsm::new(opt, TestPlatform::default(), keys).unwrap();
        let id = hsm.persistent.id;
        Self {
            hsm,
            next_capture: HashMap::new(),
            metrics: Metrics::new("test", MetricsAction::Skip, TestPlatform::default()),
            public_key,
            id,
        }
    }

    fn status(&mut self) -> StatusResponse {
        self.hsm
            .handle_status_request(&mut self.metrics, StatusRequest {})
    }

    fn role_clock(&mut self, group: GroupId) -> RoleLogicalClock {
        self.status()
            .realm
            .and_then(|r| r.groups.into_iter().find(|g| g.id == group))
            .unwrap()
            .role
            .at
    }

    fn has_group(&mut self, group: GroupId) -> bool {
        self.status()
            .realm
            .is_some_and(|r| r.groups.iter().any(|g| g.id == group))
    }

    fn is_leader(&mut self, group: GroupId) -> bool {
        self.status()
            .realm
            .is_some_and(|r| r.groups.iter().any(|g| g.id == group && g.leader.is_some()))
    }

    fn persist_state(&mut self) -> Vec<Captured> {
        let PersistStateResponse::Ok { captured } = self
            .hsm
            .handle_persist_state(&mut self.metrics, PersistStateRequest {});
        captured
    }

    fn become_leader(
        &mut self,
        realm: RealmId,
        group: GroupId,
        last_entry: LogEntry,
    ) -> BecomeLeaderResponse {
        self.hsm.handle_become_leader(
            &mut self.metrics,
            BecomeLeaderRequest {
                realm,
                group,
                last_entry,
            },
        )
    }

    fn stepdown_as_leader(&mut self, realm: RealmId, group: GroupId) -> StepDownResponse {
        self.hsm.handle_stepdown_as_leader(
            &mut self.metrics,
            StepDownRequest {
                realm,
                group,
                force: false,
            },
        )
    }

    // Makes a CaptureNext request to the HSM if there are any new log
    // entries to capture. returns the role as returned by capture next. If
    // there were no new log entries to capture returns None.
    fn capture_next(
        &mut self,
        store: &TestStore,
        realm: RealmId,
        group: GroupId,
    ) -> Option<RoleStatus> {
        let log = store.group_log(&group);
        let next_capture = self
            .next_capture
            .entry((realm, group))
            .or_insert_with(|| LogIndex::FIRST);

        let offset = (next_capture.0 - log[0].index.0) as usize;
        if log[offset..].is_empty() {
            // nothing new to capture
            return None;
        }
        let r = self.hsm.handle_capture_next(
            &mut self.metrics,
            CaptureNextRequest {
                realm,
                group,
                entries: log[offset..].to_vec(),
            },
        );
        match r {
            CaptureNextResponse::Ok(role) => {
                *next_capture = log.last().unwrap().index.next();
                Some(role)
            }
            _ => panic!("capture_next failed: {r:?}"),
        }
    }

    fn commit(&mut self, realm: RealmId, group: GroupId, captures: Vec<Captured>) -> CommitState {
        let r = self.hsm.handle_commit(
            &mut self.metrics,
            CommitRequest {
                realm,
                group,
                captures,
            },
        );
        if let CommitResponse::Ok(state) = r {
            state
        } else {
            panic!("commit failed {r:?}");
        }
    }

    fn app_request(
        &mut self,
        store: &TestStore,
        realm: RealmId,
        group: GroupId,
        record_id: RecordId,
        req: SecretsRequest,
    ) -> (Handshake, AppResponse) {
        let req_bytes = marshalling::to_vec(&req).unwrap();
        let (handshake, req) = Handshake::start(&self.public_key, &req_bytes, &mut OsRng).unwrap();
        let (proof, index) = read_proof(store, group, &record_id);
        (
            handshake,
            self.hsm.handle_app(
                &mut self.metrics,
                AppRequest {
                    realm,
                    group,
                    record_id,
                    session_id: SessionId(OsRng.next_u32()),
                    encrypted: NoiseRequest::Handshake { handshake: req },
                    proof,
                    index,
                },
            ),
        )
    }
}

// OwnershipTransfer deals with some the things the agent & coordinator deal
// with in the full system. This can help reduce a lot of boilerplate steps in
// tests.
struct OwnershipTransfer<'a, 'b> {
    cluster: &'a mut TestCluster<'b>,
    realm: RealmId,
    source: GroupId,
    destination: GroupId,
    range: OwnedRange,
    prepared: Option<PreparedTransfer>,
    partition: Option<Partition>,
    stmt: Option<TransferStatement>,
    auto_commit: bool,
}

impl<'a, 'b> OwnershipTransfer<'a, 'b> {
    fn new(
        cluster: &'a mut TestCluster<'b>,
        source: GroupId,
        destination: GroupId,
        range: OwnedRange,
        auto_commit: bool,
    ) -> Self {
        let realm = cluster.realm;
        Self {
            cluster,
            realm,
            source,
            destination,
            range,
            prepared: None,
            partition: None,
            stmt: None,
            auto_commit,
        }
    }

    // Will run through the regular happy path and execute the transfer.
    fn do_transfer(&mut self) {
        self.auto_commit = true;
        assert!(matches!(self.prepare(), PrepareTransferResponse::Ok { .. }));
        assert!(matches!(
            self.transfer_out(),
            TransferOutResponse::Ok { .. }
        ));
        assert!(matches!(
            self.transfer_statement(),
            TransferStatementResponse::Ok(_)
        ));
        match self.transfer_in() {
            TransferInResponse::Ok { .. } => {}
            other => panic!("transfer in failed with {other:?}"),
        }
        assert!(matches!(
            self.complete_transfer(),
            CompleteTransferResponse::Ok { .. }
        ));
    }

    fn prepare(&mut self) -> PrepareTransferResponse {
        let hsm = self.cluster.leader(self.destination).unwrap();
        let result = hsm.hsm.handle_prepare_transfer(
            &mut hsm.metrics,
            PrepareTransferRequest {
                realm: self.realm,
                source: self.source,
                destination: self.destination,
                range: self.range.clone(),
            },
        );
        if let PrepareTransferResponse::Ok(prepared) = &result {
            self.prepared = Some(prepared.clone());
            if let Some(entry) = &prepared.entry {
                self.cluster
                    .store
                    .append(self.destination, entry.clone(), StoreDelta::default());
                if self.auto_commit {
                    self.cluster.capture_next_and_commit_group(self.destination);
                }
            }
        }
        result
    }

    fn transfer_out(&mut self) -> TransferOutResponse {
        let last = self.cluster.store.latest_log(&self.source);
        let partition = last.partition.unwrap().clone();
        let proof = if self.range == partition.range {
            None
        } else {
            // When a transfer_out is retried, the last log entry already
            // reflects that the transferring range has been moved out of what
            // the group owns and into the transferring_out section. So split_at
            // may indicate that the range can't be split at that point. In
            // which case we skip getting a proof, and let the HSM decide.
            partition.range.split_at(&self.range).and_then(|id| {
                self.cluster
                    .store
                    .tree
                    .read(&partition.range, &partition.root_hash, &id)
                    .ok()
            })
        };
        let hsm = self.cluster.leader(self.source).unwrap();
        let result = hsm.hsm.handle_transfer_out(
            &mut hsm.metrics,
            TransferOutRequest {
                realm: self.realm,
                source: self.source,
                destination: self.destination,
                range: self.range.clone(),
                nonce: self.prepared.as_ref().unwrap().nonce,
                statement: self.prepared.as_ref().unwrap().statement.clone(),
                proof,
            },
        );
        if let TransferOutResponse::Ok {
            entry,
            delta,
            partition,
            ..
        } = &result
        {
            self.partition = Some(partition.clone());
            if let Some(entry) = entry {
                self.cluster
                    .store
                    .append(self.source, entry.clone(), delta.clone());
                if self.auto_commit {
                    self.cluster.capture_next_and_commit_group(self.source);
                }
            }
        }
        result
    }

    fn transfer_statement(&mut self) -> TransferStatementResponse {
        let hsm = self.cluster.leader(self.source).unwrap();
        let result = hsm.hsm.handle_transfer_statement(
            &mut hsm.metrics,
            TransferStatementRequest {
                realm: self.realm,
                source: self.source,
                destination: self.destination,
                nonce: self.prepared.as_ref().unwrap().nonce,
            },
        );
        if let TransferStatementResponse::Ok(stmt) = &result {
            self.stmt = Some(stmt.clone());
        }
        result
    }

    fn transfer_in(&mut self) -> TransferInResponse {
        let last_entry = self.cluster.store.latest_log(&self.destination);
        let proofs = match last_entry.partition {
            None => None,
            Some(partition) => partition.range.join(&self.range).map(|jr| {
                let proof_dir = if jr.start == self.range.start {
                    Dir::Right
                } else {
                    Dir::Left
                };
                let transferring_in = self.partition.clone().unwrap();
                let tin_proof = self.cluster.store.tree.read_tree_side(
                    &transferring_in.range,
                    &transferring_in.root_hash,
                    proof_dir,
                );
                let owned_proof = self.cluster.store.tree.read_tree_side(
                    &partition.range,
                    &partition.root_hash,
                    proof_dir.opposite(),
                );
                TransferInProofs {
                    owned: owned_proof.unwrap(),
                    transferring: tin_proof.unwrap(),
                }
            }),
        };
        let hsm = self.cluster.leader(self.destination).unwrap();

        let result = hsm.hsm.handle_transfer_in(
            &mut hsm.metrics,
            TransferInRequest {
                realm: self.realm,
                source: self.source,
                destination: self.destination,
                transferring: self.partition.clone().unwrap(),
                proofs,
                nonce: self.prepared.as_ref().unwrap().nonce,
                statement: self.stmt.clone().unwrap(),
            },
        );
        if let TransferInResponse::Ok { entry, delta, .. } = &result {
            self.cluster
                .store
                .append(self.destination, entry.clone(), delta.clone());
            if self.auto_commit {
                self.cluster.capture_next_and_commit_group(self.destination);
            }
        }
        result
    }

    fn complete_transfer(&mut self) -> CompleteTransferResponse {
        let hsm = self.cluster.leader(self.source).unwrap();
        let result = hsm.hsm.handle_complete_transfer(
            &mut hsm.metrics,
            CompleteTransferRequest {
                realm: self.realm,
                source: self.source,
                destination: self.destination,
                range: self.range.clone(),
            },
        );
        if let CompleteTransferResponse::Ok { entry, clock: _ } = &result {
            self.cluster
                .store
                .append(self.source, entry.clone(), StoreDelta::default());
            if self.auto_commit {
                self.cluster.capture_next_and_commit_group(self.source);
            }
        }
        result
    }

    #[allow(unused)]
    fn cancel_prepare(&mut self) -> CancelPreparedTransferResponse {
        let hsm = self.cluster.leader(self.destination).unwrap();
        let result = hsm.hsm.handle_cancel_prepared_transfer(
            &mut hsm.metrics,
            CancelPreparedTransferRequest {
                realm: self.realm,
                source: self.source,
                destination: self.destination,
                range: self.range.clone(),
            },
        );
        if let CancelPreparedTransferResponse::Ok { entry, clock } = &result {
            self.cluster
                .store
                .append(self.destination, entry.clone(), StoreDelta::default());
            if self.auto_commit {
                self.cluster.capture_next_and_commit_group(self.source);
            }
        }
        result
    }
}

fn read_proof(
    store: &TestStore,
    group: GroupId,
    record: &RecordId,
) -> (ReadProof<DataHash>, LogIndex) {
    let last = store.latest_log(&group);
    let partition = last.partition.as_ref().unwrap();
    let proof = store
        .tree
        .read(&partition.range, &partition.root_hash, record)
        .unwrap();
    (proof, last.index)
}

#[derive(Default)]
struct TestStore {
    logs: HashMap<GroupId, Vec<LogEntry>>,
    tree: MemStore<DataHash>,
}

impl TestStore {
    fn append(&mut self, g: GroupId, e: LogEntry, d: StoreDelta<DataHash>) {
        if let Some(p) = &e.partition {
            self.tree.apply_store_delta(p.root_hash, d);
        }
        self.logs.entry(g).or_default().push(e);
    }

    fn group_log(&self, g: &GroupId) -> &[LogEntry] {
        match self.logs.get(g) {
            Some(log) => log.as_slice(),
            None => panic!("no log found for group {g:?}"),
        }
    }

    fn latest_log(&self, g: &GroupId) -> LogEntry {
        self.group_log(g).last().unwrap().clone()
    }
}

#[derive(Clone, Default)]
struct TestPlatform {
    nvram: Arc<Mutex<Vec<u8>>>,
}

impl RngCore for TestPlatform {
    fn next_u32(&mut self) -> u32 {
        OsRng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        OsRng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        OsRng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        OsRng.try_fill_bytes(dest)
    }
}
impl CryptoRng for TestPlatform {}

impl NVRam for TestPlatform {
    fn read(&self) -> Result<Vec<u8>, IOError> {
        Ok(self.nvram.lock().unwrap().clone())
    }

    fn write(&self, data: Vec<u8>) -> Result<(), IOError> {
        *self.nvram.lock().unwrap() = data;
        Ok(())
    }
}

impl Clock for TestPlatform {
    type Instant = StdInstant;

    fn now(&self) -> Option<Self::Instant> {
        Some(StdInstant(std::time::Instant::now()))
    }

    fn elapsed(&self, start: Self::Instant) -> Option<Nanos> {
        Some(Nanos(
            start.0.elapsed().as_nanos().try_into().unwrap_or(u32::MAX),
        ))
    }
}

struct StdInstant(std::time::Instant);
impl core::ops::Sub for StdInstant {
    type Output = Nanos;

    fn sub(self, rhs: Self) -> Self::Output {
        Nanos((self.0 - rhs.0).as_nanos().try_into().unwrap_or(u32::MAX))
    }
}
