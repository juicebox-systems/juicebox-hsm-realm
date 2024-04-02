extern crate alloc;

use alloc::vec::Vec;
use core::cmp::{max, min};
use core::mem;
use hashbrown::hash_map::Entry;
use tracing::{info, instrument, trace, warn};

use super::super::hal::Platform;
use super::mac::{CapturedStatementMessage, CtMac, EntryMacMessage};
use super::{
    is_group_member, GroupMemberError, Hsm, LeaderLog, Metrics, RoleState, RoleVolatileState,
    StepDownPoint,
};
use election::HsmElection;
use hsm_api::{
    CaptureJumpRequest, CaptureJumpResponse, CaptureNextRequest, CaptureNextResponse, Captured,
    CommitRequest, CommitResponse, CommitState, EntryMac, LogEntry, LogIndex,
};

impl<P: Platform> Hsm<P> {
    #[instrument(level = "trace", skip(self, _metrics, request), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_capture_jump(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: CaptureJumpRequest,
    ) -> CaptureJumpResponse {
        type Response = CaptureJumpResponse;

        match is_group_member(&self.persistent, request.jump.realm, request.jump.group) {
            Err(GroupMemberError::InvalidRealm) => return Response::InvalidRealm,
            Err(GroupMemberError::InvalidGroup) => return Response::InvalidGroup,
            Ok(_) => {}
        }

        let role = self
            .volatile
            .groups
            .get(&request.jump.group)
            .expect("group member must have role");
        if !matches!(role.state, RoleVolatileState::Witness) {
            // Agents try to avoid compacting log entries needed for leaders
            // and stepping down, so we don't expect to get here. It's easier
            // to bail than to deal with the jump entry not agreeing with the
            // leader/stepdown log (which would sometimes require log entries
            // that have already been compacted).
            return Response::NotWitness(role.status());
        }

        if self
            .realm_keys
            .mac
            .captured_mac(&CapturedStatementMessage {
                hsm: request.jump.hsm,
                realm: request.jump.realm,
                group: request.jump.group,
                index: request.jump.index,
                entry_mac: &request.jump.mac,
            })
            .verify(&request.jump.statement)
            .is_err()
        {
            return Response::InvalidStatement;
        }

        let v = self.volatile.captured.entry(request.jump.group);
        if let Entry::Occupied(v) = &v {
            if v.get().0 >= request.jump.index {
                return Response::StaleIndex;
            }
        }
        v.insert((request.jump.index, request.jump.mac));
        Response::Ok
    }

    #[instrument(level = "trace", skip(self, _metrics, request), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_capture_next(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: CaptureNextRequest,
    ) -> CaptureNextResponse {
        type Response = CaptureNextResponse;

        if request.entries.is_empty() {
            return Response::MissingEntries;
        }

        match is_group_member(&self.persistent, request.realm, request.group) {
            Err(GroupMemberError::InvalidRealm) => return Response::InvalidRealm,
            Err(GroupMemberError::InvalidGroup) => return Response::InvalidGroup,
            Ok(_) => {}
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

            let v = self.volatile.captured.entry(request.group);
            match &v {
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
            v.insert((entry.index, entry.entry_mac.clone()));

            if let Some(RoleState {
                state: RoleVolatileState::Leader(ls),
                ..
            }) = self.volatile.groups.get_mut(&request.group)
            {
                // If while leading another HSM becomes leader and writes a log
                // entry, the actual persisted log diverges from our in-memory
                // copy of the log.
                let status = has_log_diverged(&ls.log, &entry);
                match status {
                    LogEntryStatus::Ok => {}
                    LogEntryStatus::PriorIndex => {
                        // The start of log gets truncated on commit. The
                        // commit may have been based on captures from just
                        // witnesses, not the leader. So, it's valid that the
                        // captured index is earlier than anything in the in
                        // memory log.
                    }
                    LogEntryStatus::FutureIndex => {
                        // Some other HSM successfully wrote a log entry, so we
                        // should stop leading.
                        self.stepdown_at(request.group, StepDownPoint::LastLogIndex);
                    }
                    LogEntryStatus::EntryMacMismatch => {
                        // The logs have diverged, so we'll stepdown.
                        self.stepdown_at(
                            request.group,
                            StepDownPoint::LogIndex(entry.index.prev().unwrap()),
                        );
                    }
                }
            }

            // If we're stepping down, we need to get the commit index up to
            // the stepping down index. It's not possible for the agent to
            // create a commit request with that exact index, as the witnesses
            // may have already passed the index and they can't generate a
            // capture statement for an earlier index. So, while stepping down,
            // we collect the new log entries that we're witnessing into the
            // stepping down log. The commit handler can then successfully
            // process a request that is after the stepdown index and complete
            // the stepdown.
            if let Some(RoleState {
                state: RoleVolatileState::SteppingDown(sd),
                ..
            }) = self.volatile.groups.get_mut(&request.group)
            {
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
                        // We need to flag the future log entries as abandoned.
                        // We remove them from the log as they're not going to
                        // get committed, and we need to rebuild the log with
                        // the persisted entries.
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
            self.volatile
                .groups
                .get(&request.group)
                .expect("We already validated that this HSM is a member of the group")
                .status(),
        )
    }

    #[instrument(level = "trace", skip(self, _metrics, request), fields(hsm=self.options.name), ret)]
    pub(super) fn handle_commit(
        &mut self,
        _metrics: &mut Metrics<P>,
        request: CommitRequest,
    ) -> CommitResponse {
        type Response = CommitResponse;

        let group_config = match is_group_member(&self.persistent, request.realm, request.group) {
            Ok(group) => &group.configuration,
            Err(GroupMemberError::InvalidRealm) => return Response::InvalidRealm,
            Err(GroupMemberError::InvalidGroup) => return Response::InvalidGroup,
        };

        let role = self
            .volatile
            .groups
            .get_mut(&request.group)
            .expect("already validated that this HSM is a member of the group");

        let (log, committed, stepdown_at) = match &mut role.state {
            RoleVolatileState::Leader(leader) => (&mut leader.log, &mut leader.committed, None),
            RoleVolatileState::SteppingDown(steppingdown) => (
                &mut steppingdown.log,
                &mut steppingdown.committed,
                Some(steppingdown.stepdown_at),
            ),
            RoleVolatileState::Witness => return Response::NotLeader(role.status()),
        };

        let mut election = HsmElection::new(group_config);
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
                // against entries we have. For a new leader this won't be able
                // to commit until the witnesses catch up to at least the log
                // entry that the new leader started from.
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

        // Don't let the commit_index go past the stepdown point. This allows
        // the agent to use the combination of the commit_index and the role
        // clock to determine if a previously generated entry from this HSM has
        // committed. Entries in the log past the stepdown point were written by
        // a different leader.
        if let Some(stepdown_at) = stepdown_at {
            commit_index = min(commit_index, stepdown_at);
        }

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
            if let Some((r, g)) = e.response {
                responses.push((e.entry.entry_mac, r, g));
            }
        }
        assert_eq!(commit_index, log.first_index());
        // This ensures we don't try to empty the log entirely.
        if let Some(res) = log.take_first_response() {
            responses.push(res);
        }
        *committed = Some(commit_index);

        // See if we're finished stepping down.
        let mut abandoned = Vec::new();
        if let RoleVolatileState::SteppingDown(sd) = &mut role.state {
            abandoned = mem::take(&mut sd.abandoned);
            if commit_index >= sd.stepdown_at {
                info!(group=?request.group, hsm=self.options.name, "Completed leader stepdown");
                role.make_witness();
            }
        }

        Response::Ok(CommitState {
            committed: commit_index,
            responses,
            abandoned,
            role: role.status(),
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
