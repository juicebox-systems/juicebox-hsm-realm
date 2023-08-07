extern crate alloc;

use alloc::vec::Vec;
use core::cmp::max;
use hashbrown::hash_map::Entry;
use tracing::{info, instrument, trace, warn};

use super::super::hal::Platform;
use super::mac::{CapturedStatementMessage, CtMac, EntryMacMessage};
use super::{Hsm, LeaderLog, Metrics, StepDownPoint};
use election::HsmElection;
use hsm_api::{
    CaptureNextRequest, CaptureNextResponse, Captured, CommitRequest, CommitResponse, CommitState,
    EntryMac, GroupMemberRole, LogEntry, LogIndex,
};

impl<P: Platform> Hsm<P> {
    #[instrument(level = "trace", skip(self, _metrics), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_capture_next(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: CaptureNextRequest,
    ) -> CaptureNextResponse {
        type Response = CaptureNextResponse;

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
                        .log_entry_mac(&EntryMacMessage::new(request.realm, request.group, &entry))
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
                                // commit. The commit may have been based on
                                // captures from just witnesses not the
                                // leader. So it's valid that the captured
                                // index is earlier than anything in the in
                                // memory log.
                            }
                            LogEntryStatus::FutureIndex => {
                                // Some other HSM successfully wrote a log entry, we should stop leading
                                self.stepdown_at(request.group, StepDownPoint::LastLogIndex);
                            }
                            LogEntryStatus::EntryMacMismatch => {
                                // The logs have diverged, we'll stepdown.
                                self.stepdown_at(
                                    request.group,
                                    StepDownPoint::LogIndex(entry.index.prev().unwrap()),
                                );
                            }
                        }
                    }

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
                    if let Some(sd) = self.volatile.stepping_down.get_mut(&request.group) {
                        let status = has_log_diverged(&sd.log, &entry);
                        match status {
                            LogEntryStatus::Ok | LogEntryStatus::PriorIndex => {}
                            LogEntryStatus::EntryMacMismatch => {
                                // If the logs diverge while we're stepping down we
                                // shorten the stepping down index to the index just
                                // before it diverged.
                                if let Some(prev) = entry.index.prev() {
                                    if prev < sd.stepdown_at {
                                        sd.stepdown_at = prev;
                                    }
                                }
                                // We need to flag the future log entries
                                // as abandoned. We remove them from the log as
                                // they're not going to get committed, and we need
                                // to rebuild the log with the persisted entries.
                                while sd.log.last_index() >= entry.index {
                                    let e = sd.log.pop_last();
                                    sd.abandoned.push(e.entry.entry_mac);
                                }
                                sd.log.append(entry, None);
                            }
                            LogEntryStatus::FutureIndex => {
                                // append will verify the index & mac chain.
                                sd.log.append(entry, None);
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
    }

    #[instrument(level = "trace", skip(self, _metrics), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_commit(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: CommitRequest,
    ) -> CommitResponse {
        type Response = CommitResponse;

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
                // Ensure the entry MAC is valid for this log by checking it
                // against entries we have. For a new leader this won't be
                // able to commit until the witnesses catch up to at least
                // the log entry that the new leader started from.
                if let Some(log_entry) = log.get_index(captured.index) {
                    if log_entry.entry.entry_mac == captured.mac {
                        election.vote(captured.hsm, captured.index);
                    } else {
                        warn!(index=?captured.index, hsm=?captured.hsm, "mac mismatch, skipping vote");
                    }
                }
            }
        }

        let Ok(mut commit_index) = election.outcome() else {
            warn!(
                hsm = self.options.name,
                commit_request = ?request,
                "no quorum. buggy caller or diverged logs"
            );
            return Response::NoQuorum;
        };

        if let Some(committed) = committed {
            // Don't let the commit_index go backwards from a prior commit.
            commit_index = max(commit_index, *committed);
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
        while log.first_index() < commit_index {
            let e = log.pop_first();
            if let Some(r) = e.response {
                responses.push((e.entry.entry_mac, r));
            }
        }
        assert_eq!(commit_index, log.first_index());
        // This ensures we don't try to empty the log entirely.
        if let Some((mac, res)) = log.take_first_response() {
            responses.push((mac, res));
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

        Response::Ok(CommitState {
            committed: commit_index,
            responses,
            abandoned,
            role,
        })
    }
}

// Describes the result of checking to see if the in memory log and the captured
// entry have diverged.
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
    EntryMacMismatch,
}

// Compares the supplied 'captured' log entry against the in memory log to see
// if its diverged. If it has that would indicate that some other HSM became
// leader and successfully wrote a log entry.
fn has_log_diverged(our_log: &LeaderLog, captured: &LogEntry) -> LogEntryStatus {
    if captured.index < our_log.first_index() {
        return LogEntryStatus::PriorIndex;
    }
    if captured.index > our_log.last_index() {
        return LogEntryStatus::FutureIndex;
    }
    let our_entry = our_log
        .get_index(captured.index)
        .expect("We already validated this is in range");

    if our_entry.entry.entry_mac != captured.entry_mac {
        warn!(index=?captured.index, "logs diverged");
        return LogEntryStatus::EntryMacMismatch;
    }
    LogEntryStatus::Ok
}
