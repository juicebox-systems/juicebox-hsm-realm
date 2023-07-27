extern crate alloc;

use alloc::vec::Vec;
use hashbrown::hash_map::Entry;
use tracing::{info, trace, warn};

use super::super::hal::Platform;
use super::mac::{CapturedStatementMessage, CtMac, EntryMacMessage};
use super::{Hsm, LeaderLogEntry, Metrics};
use election::HsmElection;
use hsm_api::{
    CaptureNextRequest, CaptureNextResponse, Captured, CommitRequest, CommitResponse, EntryMac,
    GroupMemberRole, LogIndex,
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
                            let last = &sd.log.back().unwrap().entry;
                            if entry.index == last.index.next() {
                                if entry.prev_mac == last.entry_mac {
                                    sd.log.push_back(LeaderLogEntry {
                                        entry: entry.clone(),
                                        response: None,
                                    });
                                } else {
                                    // If there's dueling leaders then our in
                                    // memory log may not be the one that
                                    // actually got persisted to the store. In
                                    // that event our responses are never valid,
                                    // and we should give up trying to step
                                    // down.

                                    // TODO: what do we want to do about
                                    // signaling to the caller that the request
                                    // is done. Can we return a NoLeader for all
                                    // the pending responses? If so we'll need
                                    // to do that from commit somehow.
                                    // Annoyingly there's no common error
                                    // responses, so we'd need to know what
                                    // request type each pending response is for
                                    // so that we can generate the right type of
                                    // NoLeader response.
                                }
                            }
                        }
                        e.insert((entry.index, entry.entry_mac));
                    }
                    Response::Ok
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
                    None => return Response::NotLeader,
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
                            if offset < log.len() && log[offset].entry.entry_mac == captured.mac {
                                election.vote(captured.hsm, captured.index);
                            }
                        }
                    }
                }
            }

            let Ok(commit_index) = election.outcome() else {
                warn!(
                    hsm = self.options.name,
                    commit_request = ?request,
                    "no quorum. buggy caller?"
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
            let role = if let Some(sd) = self.volatile.stepping_down.get(&request.group) {
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
                role,
            }
        })();

        trace!(hsm = self.options.name, ?response);
        response
    }
}
