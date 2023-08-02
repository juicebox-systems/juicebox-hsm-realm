extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use hashbrown::hash_map::Entry;
use tracing::{info, trace, warn};

use super::super::hal::Platform;
use super::mac::{CapturedStatementMessage, CtMac, EntryMacMessage};
use super::{Hsm, LeaderLogEntry, Metrics};
use election::HsmElection;
use hsm_api::{
    CaptureNextRequest, CaptureNextResponse, Captured, CommitRequest, CommitResponse, EntryMac,
    GroupMemberRole, LogEntry, LogIndex,
};

impl<P: Platform> Hsm<P> {
    pub(super) fn handle_capture_next(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: CaptureNextRequest,
    ) -> CaptureNextResponse {
        type Response = CaptureNextResponse;
        trace!(hsm = self.options.name, ?request);

        let response = (|| {
            if request.entries.is_empty() {
                return Response::MissingEntries;
            }

            match &self.persistent.realm {
                None => Response::InvalidRealm,

                Some(realm) => {
                    if realm.id != request.realm {
                        return Response::InvalidRealm;
                    }

                    if realm.groups.get(&request.group).is_none() {
                        return Response::InvalidGroup;
                    }

                    for entry in request.entries {
                        if self
                            .realm_keys
                            .mac
                            .log_entry_mac(&EntryMacMessage::new(
                                request.realm,
                                request.group,
                                &entry,
                            ))
                            .verify(&entry.entry_mac)
                            .is_err()
                        {
                            return Response::InvalidMac;
                        }

                        let e = self.volatile.captured.entry(request.group);
                        match &e {
                            Entry::Vacant(_) => {
                                if entry.index != LogIndex::FIRST {
                                    return Response::MissingPrev;
                                }
                                if entry.prev_mac != EntryMac::zero() {
                                    return Response::InvalidChain;
                                }
                            }
                            Entry::Occupied(v) => {
                                let (captured_index, captured_mac) = v.get();
                                if entry.index != captured_index.next() {
                                    return Response::MissingPrev;
                                }
                                if entry.prev_mac != *captured_mac {
                                    return Response::InvalidChain;
                                }
                            }
                        }
                        e.insert((entry.index, entry.entry_mac.clone()));

                        if let Some(ls) = self.volatile.leader.get_mut(&request.group) {
                            // If while leading another HSM becomes leader and
                            // writes a log entry the actual persisted log
                            // diverges from what our in memory copy of the log
                            // is.
                            let status = has_log_diverged(&ls.log, &entry);
                            match status {
                                LogEntryStatus::Ok => {}
                                LogEntryStatus::PriorIndex => {
                                    // The start of log gets truncated on
                                    // commit. The commit may of been based on
                                    // captures from just witnesses not the
                                    // leader. So its valid that the captured
                                    // index is earlier than anything in the in
                                    // memory log.
                                }
                                LogEntryStatus::FutureIndex => {
                                    // Some other HSM successfully wrote a log entry, we should stop leading
                                    let leader =
                                        self.volatile.leader.remove(&request.group).unwrap();
                                    let last_idx = leader.log.back().unwrap().entry.index;
                                    self.stepdown_at(request.group, leader, last_idx);
                                }
                                LogEntryStatus::EntryMacMismatch { offset: _ } => {
                                    // The logs have diverged, we'll stepdown.
                                    let leader =
                                        self.volatile.leader.remove(&request.group).unwrap();
                                    self.stepdown_at(
                                        request.group,
                                        leader,
                                        entry.index.prev().unwrap(),
                                    );
                                }
                            }
                        }

                        if let Some(sd) = self.volatile.stepping_down.get_mut(&request.group) {
                            let status = has_log_diverged(&sd.log, &entry);
                            match status {
                                LogEntryStatus::Ok | LogEntryStatus::PriorIndex => {}
                                LogEntryStatus::EntryMacMismatch { offset } => {
                                    // If the logs diverge while we're stepping down we
                                    // shorten the stepping down index to the index just
                                    // before it diverged.
                                    if let Some(prev) = entry.index.prev() {
                                        if prev < sd.stepdown_at {
                                            sd.stepdown_at = prev;
                                            // We also need to flag the future log entries
                                            // as abandoned.
                                            for e in sd.log.iter().skip(offset) {
                                                sd.abandoned.push(e.entry.entry_mac.clone());
                                            }
                                        }
                                    }
                                    // we truncate the in memory log so that it can
                                    // be rebuilt with the valid captured entries. This
                                    // allows the log to build back up and eventually
                                    // perform a commit. The commit is safe because
                                    // we've removed from the log any responses that
                                    // would be at or after the diverged index.
                                    sd.log.truncate(offset);
                                    sd.log.push_back(LeaderLogEntry {
                                        entry,
                                        response: None,
                                    });
                                }
                                LogEntryStatus::FutureIndex => {
                                    // If we're stepping down we need to get the commit
                                    // index up to the stepping down index. It's not
                                    // possible for the agent to create a commit request
                                    // with that exact index as the witnesses may have
                                    // already passed the index and they can't generate a
                                    // capture statement for an earlier index. So while
                                    // stepping down we collect the new log entries that
                                    // we're witnessing into the stepping down log. Commit
                                    // can then successfully process a commit request that
                                    // is after the stepdown index and complete the
                                    // stepdown.
                                    let last = &sd.log.back().unwrap().entry;
                                    if entry.index == last.index.next()
                                        && entry.prev_mac == last.entry_mac
                                    {
                                        sd.log.push_back(LeaderLogEntry {
                                            entry,
                                            response: None,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    Response::Ok(
                        self.current_role(&request.group)
                            .expect("We already validated that this HSM is a member of the group"),
                    )
                }
            }
        })();

        trace!(hsm = self.options.name, ?response);
        response
    }

    pub(super) fn handle_commit(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: CommitRequest,
    ) -> CommitResponse {
        type Response = CommitResponse;
        trace!(hsm = self.options.name, ?request);

        let response = (|| {
            let Some(realm) = &self.persistent.realm else {
                return Response::InvalidRealm;
            };
            if realm.id != request.realm {
                return Response::InvalidRealm;
            }

            let Some(group) = realm.groups.get(&request.group) else {
                return Response::InvalidGroup;
            };

            let (log, committed) = match self.volatile.leader.get_mut(&request.group) {
                Some(leader) => (&mut leader.log, &mut leader.committed),
                None => match self.volatile.stepping_down.get_mut(&request.group) {
                    Some(steppingdown) => (&mut steppingdown.log, &mut steppingdown.committed),
                    None => return Response::NotLeader(GroupMemberRole::Witness),
                },
            };

            let mut election = HsmElection::new(&group.configuration);
            let verify_capture = |captured: &Captured| -> bool {
                match self
                    .realm_keys
                    .mac
                    .captured_mac(&CapturedStatementMessage {
                        hsm: captured.hsm,
                        realm: captured.realm,
                        group: captured.group,
                        index: captured.index,
                        entry_mac: &captured.mac,
                    })
                    .verify(&captured.statement)
                {
                    Ok(_) => true,
                    Err(err) => {
                        warn!(?err, ?captured, "failed to verify capture statement");
                        false
                    }
                }
            };
            for captured in &request.captures {
                if captured.group == request.group
                    && captured.realm == request.realm
                    && verify_capture(captured)
                {
                    // Ensure the entry MAC is valid for this log by checking
                    // it against entries we have. For a new leader this won't
                    // be able to commit until the witnesses catch up to a log
                    // entry written by the new leader.
                    if let Some(offset) = captured.index.0.checked_sub(log[0].entry.index.0) {
                        if let Ok(offset) = usize::try_from(offset) {
                            if offset < log.len() {
                                if log[offset].entry.index != captured.index {
                                    panic!("in memory log seems corrupt, expecting index {} at offset {} but got {}", captured.index, offset, log[offset].entry.index);
                                }
                                if log[offset].entry.entry_mac == captured.mac {
                                    election.vote(captured.hsm, captured.index);
                                } else {
                                    warn!(index=?captured.index, hsm=?captured.hsm, "mac mismatch, skipping vote")
                                }
                            }
                        }
                    }
                }
            }

            let Ok(commit_index) = election.outcome() else {
                warn!(
                    hsm = self.options.name,
                    commit_request = ?request,
                    "no quorum. buggy caller or diverged logs"
                );
                return Response::NoQuorum;
            };

            if let Some(committed) = committed {
                if *committed >= commit_index {
                    return Response::AlreadyCommitted {
                        committed: *committed,
                    };
                }
            }

            trace!(
                hsm = self.options.name,
                group=?request.group,
                index = ?commit_index,
                prev_index=?committed,
                "leader committed entries",
            );

            // trim the prefix of leader.log and collect up the responses
            let mut responses = Vec::new();
            loop {
                match log.pop_front() {
                    None => panic!("We should never empty leader.log entirely"),
                    Some(e) if e.entry.index < commit_index => {
                        if let Some(r) = e.response {
                            responses.push((e.entry.entry_mac, r));
                        }
                    }
                    Some(mut e) => {
                        assert!(e.entry.index == commit_index);
                        if let Some(r) = e.response.take() {
                            responses.push((e.entry.entry_mac.clone(), r));
                        }
                        // If there's still something in the log then we
                        // don't need to put this one back. But it seems
                        // safer to be consistent and always have this
                        // one in the log.
                        log.push_front(e);
                        break;
                    }
                }
            }
            *committed = Some(commit_index);

            // See if we're finished stepping down.
            let mut abandoned = Vec::new();
            let role = if let Some(sd) = self.volatile.stepping_down.get_mut(&request.group) {
                core::mem::swap(&mut abandoned, &mut sd.abandoned);
                if commit_index >= sd.stepdown_at {
                    info!(group=?request.group, hsm=self.options.name, "Completed leader stepdown");
                    self.volatile.stepping_down.remove(&request.group);
                    GroupMemberRole::Witness
                } else {
                    GroupMemberRole::SteppingDown
                }
            } else {
                GroupMemberRole::Leader
            };

            Response::Ok {
                committed: commit_index,
                responses,
                abandoned,
                role,
            }
        })();

        trace!(hsm = self.options.name, ?response);
        response
    }
}

// Checks to see if the in memory log and the captured
// entry have diverged. If so, returns the offset into
// our_log where the diverged entry is located.
enum LogEntryStatus {
    // The captured entry matches our in memory log.
    Ok,
    // The captured entry is for an index before our in
    // memory log starts.
    PriorIndex,
    // The captured entry is for an index after the most
    // recent entry in our in memory log.
    FutureIndex,
    // The captured entry and the entry in our log have
    // different Entry MACs.
    EntryMacMismatch { offset: usize },
}

// Compares the supplied 'captured' log entry against the in memory log to see
// if its diverged. If it has that that would indicate that some other HSM
// became leader and successfully wrote a log entry.
fn has_log_diverged(our_log: &VecDeque<LeaderLogEntry>, captured: &LogEntry) -> LogEntryStatus {
    let our_first_idx = our_log.front().unwrap().entry.index;
    if captured.index < our_first_idx {
        return LogEntryStatus::PriorIndex;
    }
    let our_last_idx = our_log.back().unwrap().entry.index;
    if captured.index > our_last_idx {
        return LogEntryStatus::FutureIndex;
    }
    let offset = captured.index.0 - our_first_idx.0;
    if let Ok(offset) = usize::try_from(offset) {
        if let Some(our_entry) = our_log.get(offset) {
            assert_eq!(our_entry.entry.index, captured.index);
            if our_entry.entry.entry_mac != captured.entry_mac {
                warn!(index=?captured.index, "logs diverged");
                return LogEntryStatus::EntryMacMismatch { offset };
            }
        }
    } else {
        // I'd expect that we ran out of memory long before we hit this.
        panic!("in memory log too large");
    }
    LogEntryStatus::Ok
}
