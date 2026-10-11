// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Caller-owned, revision-guarded traversal of all published lock obstacles.
use super::{Actor, Command, Error, Request};
use crate::locks::{Lock, Owner, groups::Capture, groups::Id, records};
use crate::storage::Token;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadSnapshot {
    inode: Token,
    revision: u64,
}
impl ReadSnapshot {
    pub const fn inode(self) -> Token {
        self.inode
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadState {
    More,
    Done,
    Invalidated,
}
#[derive(Debug)]
pub struct ReadProgress {
    pub visited: usize,
    pub blockers: [Option<Lock>; records::PORTION],
    pub state: ReadState,
}
pub struct Reader {
    request: Request,
    snapshot: ReadSnapshot,
    group: Option<Id>,
    next: Option<Id>,
    capture: Option<Capture>,
    entered: bool,
    record: Option<records::Id>,
    state: ReadState,
}
impl Reader {
    pub const fn snapshot(&self) -> ReadSnapshot {
        self.snapshot
    }
}
impl<const G: usize, const I: usize, const P: usize, const D: usize, const R: usize, const S: usize>
    Actor<G, I, P, D, R, S>
{
    pub fn reader_snapshot(&self, inode: Token) -> Option<ReadSnapshot> {
        self.groups
            .inode_revision(inode)
            .map(|revision| ReadSnapshot { inode, revision })
    }
    pub fn reader_snapshot_valid(&self, snapshot: ReadSnapshot) -> bool {
        self.reader_snapshot(snapshot.inode) == Some(snapshot)
    }
    pub fn pid_visible(&self, pid: u32) -> bool {
        self.groups.pid_visible(pid)
    }
    /// None disables optional detection after revision exhaustion, not POSIX I/O.
    pub fn reader(&self, request: Request) -> Result<Option<Reader>, Error> {
        self.validate_request(request)?;
        if !matches!(request.command, Command::Get(_) | Command::Set(Some(_))) {
            return Err(Error::Invalid);
        }
        let Some(snapshot) = self.reader_snapshot(request.inode) else {
            return Ok(None);
        };
        Ok(Some(Reader {
            request,
            snapshot,
            group: self.groups.inode_head(request.inode)?,
            next: None,
            capture: None,
            entered: false,
            record: None,
            state: ReadState::More,
        }))
    }
    pub fn reader_part(
        &self,
        reader: &mut Reader,
        mut pid_live: impl FnMut(u32) -> bool,
        mut ofd_live: impl FnMut(Token) -> bool,
    ) -> ReadProgress {
        let mut result = ReadProgress {
            visited: 0,
            blockers: [None; records::PORTION],
            state: reader.state,
        };
        // This barrier MUST precede every carried group/record dereference.
        if !self.reader_snapshot_valid(reader.snapshot) {
            reader.state = ReadState::Invalidated;
        }
        if reader.state != ReadState::More {
            result.state = reader.state;
            return result;
        }
        let kind = match reader.request.command {
            Command::Get(kind) | Command::Set(Some(kind)) => kind,
            Command::Set(None) => unreachable!("validated reader kind"),
        };
        let request = Lock {
            owner: reader.request.owner,
            kind,
            range: reader.request.range,
        };
        let mut count = 0;
        while result.visited < records::PORTION {
            if reader.entered && reader.record.is_none() {
                reader.group = reader.next;
                reader.entered = false;
                reader.capture = None;
            }
            let Some(id) = reader.group else {
                reader.state = ReadState::Done;
                break;
            };
            result.visited += 1;
            if !reader.entered {
                reader.next = self.groups.inode_next(id).expect("revision guarded group");
                reader.capture = self.groups.capture(id).expect("revision guarded capture");
                reader.entered = true;
                if reader.capture.is_some() {
                    reader.record = self.view(id).expect("revision guarded view").head;
                }
            } else {
                // PID logical revocation may precede structural detach. Its
                // retained records remain safe but must no longer be visible.
                if reader
                    .capture
                    .is_none_or(|capture| !self.groups.valid(capture))
                {
                    reader.record = None;
                    continue;
                }
                let record = self
                    .pool
                    .read(reader.record.expect("entered record"))
                    .expect("revision guarded published record");
                reader.record = record.next;
                let live = match record.lock.owner {
                    Owner::Process(pid) => self.groups.pid_visible(pid) && pid_live(pid),
                    Owner::Description { slot, generation } => ofd_live(Token { slot, generation }),
                };
                if live && record.lock.conflicts(request) {
                    result.blockers[count] = Some(record.lock);
                    count += 1;
                }
            }
        }
        result.state = reader.state;
        result
    }
}

#[cfg(test)]
#[path = "reader_tests.rs"]
mod tests;
