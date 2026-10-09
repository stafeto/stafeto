// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Absolute paths are counted and built in paid bounded steps.
//! Ready bytes retain their exact original result through chunk retries.

use super::*;
use crate::storage::{NODES, NONE, PAGE, ROOT};
use proto_fs::{INVALID_ARGUMENT, MAX_PATH, MAX_READ, NO_ENTRY, RESOLVING};
const INLINE: usize = MAX_PATH + 1;
const MAX_LENGTH: usize = (NODES - 1) * 256 + 1;
pub(crate) const MAX_PAGES: usize = MAX_LENGTH.div_ceil(PAGE);
pub(crate) const NO_MEMORY: u32 = proto_wire::Status::Kernel(abi::Error::NoMemory).code();

pub(crate) struct ResultPages {
    pub(crate) head: u16,
    pub(crate) first: u16,
    pub(crate) root: u16,
    pub(crate) count: u16,
    pub(crate) length: u32,
}
impl ResultPages {
    fn empty(root: u16) -> Self {
        Self {
            head: NONE,
            first: 0,
            root,
            count: 0,
            length: 0,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GetcwdOutcome {
    Ready { length: u32 },
    BufferTooSmall { required: u32 },
    Failed(u32),
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Scan,
    Move,
    BeginPage,
    Copy,
    Ready,
    Restart,
    Cancel,
    Canceled,
}
/// The service owns the authentic key, admission and recovery of this record.
pub struct GetcwdJournal {
    root: Root,
    charge: u16,
    identity: Identity,
    epoch: u64,
    base: Token,
    current: Token,
    parent: Token,
    base_pinned: bool,
    current_pinned: bool,
    scan: u16,
    depth: u16,
    phase: Phase,
    building: bool,
    name: [u8; 256],
    name_len: u16,
    remaining: u16,
    inline: [u8; INLINE],
    length: u32,
    expected: u32,
    caller_size: u64,
    pages: ResultPages,
    read_offset: Option<u32>,
    read_page: u16,
    read_start: u32,
    outcome: Option<GetcwdOutcome>,
    /// The result of a path operation fits the inline buffer or fails with
    /// ENAMETOOLONG; it never grows pages.
    inline_only: bool,
    /// What the walk needs of each parent: read and search for getcwd, search alone otherwise.
    parent_bits: u32,
    /// The length of the final name a path operation puts after the directory's path.
    initial: u32,
}
impl Ram<'_> {
    /// This capture is the paid server-admission linearization point for CWD.
    pub fn prepare_getcwd(
        &mut self,
        fds: &Fds,
        charge: u16,
        identity: Identity,
        caller_size: u64,
    ) -> Result<GetcwdJournal, u32> {
        if caller_size == 0 {
            return Err(INVALID_ARGUMENT);
        }
        self.storage.namespace_charge(fds.root, charge)?;
        let base = fds.cwd.unwrap_or(ROOT);
        if self.storage.node(base)?.kind != crate::DIR {
            return Err(NOT_DIRECTORY);
        }
        self.storage.pin(base, Pin::Pending)?;
        Ok(GetcwdJournal {
            root: fds.root,
            charge,
            identity,
            epoch: self.storage.state.epoch,
            base,
            current: base,
            parent: ROOT,
            base_pinned: true,
            current_pinned: false,
            scan: 0,
            depth: 0,
            phase: Phase::Scan,
            building: false,
            name: [0; 256],
            name_len: 0,
            remaining: 0,
            inline: [0; INLINE],
            length: 1,
            expected: 0,
            caller_size,
            pages: ResultPages::empty(charge),
            read_offset: None,
            read_page: NONE,
            read_start: 0,
            outcome: None,
            inline_only: false,
            parent_bits: 5,
            initial: 1,
        })
    }
    /// The canonical path of the directory `base`, followed by `/tail` when a
    /// name is given. The result is at most 511 bytes. `search` demands the
    /// search permission of the directory itself.
    pub fn prepare_path(
        &mut self,
        root: Root,
        charge: u16,
        identity: Identity,
        base: Token,
        tail: Option<&[u8]>,
        search: bool,
    ) -> Result<GetcwdJournal, u32> {
        self.storage.namespace_charge(root, charge)?;
        let node = self.storage.node(base)?;
        if node.kind != crate::DIR {
            return Err(NOT_DIRECTORY);
        }
        if search && !identity.permits(node, 1) {
            return Err(ACCESS_DENIED);
        }
        let tail = tail.unwrap_or(b"");
        if tail.len() > 255 {
            return Err(proto_fs::NAME_TOO_LONG);
        }
        self.storage.pin(base, Pin::Pending)?;
        let mut journal = GetcwdJournal {
            root,
            charge,
            identity,
            epoch: self.storage.state.epoch,
            base,
            current: base,
            parent: ROOT,
            base_pinned: true,
            current_pinned: false,
            scan: 0,
            depth: 0,
            phase: Phase::Scan,
            building: false,
            name: [0; 256],
            name_len: 0,
            remaining: 0,
            inline: [0; INLINE],
            length: 1,
            expected: 0,
            caller_size: u64::MAX,
            pages: ResultPages::empty(charge),
            read_offset: None,
            read_page: NONE,
            read_start: 0,
            outcome: None,
            inline_only: true,
            parent_bits: 1,
            initial: 1,
        };
        if !tail.is_empty() {
            let length = tail.len() + 2;
            journal.inline[INLINE - length] = b'/';
            journal.inline[INLINE - length + 1..INLINE - 1].copy_from_slice(tail);
            journal.length = length as u32;
            journal.initial = length as u32;
        }
        Ok(journal)
    }
}
impl GetcwdJournal {
    pub fn outcome(&self) -> Option<GetcwdOutcome> {
        self.outcome
    }
    fn fail(&mut self, status: u32) -> bool {
        self.outcome = Some(GetcwdOutcome::Failed(status));
        self.phase = Phase::Ready;
        true
    }
    /// Scan eight naming rows, copy one component, or initialize one result page.
    /// Every error keeps existing pins and pages attached until cancellation.
    pub fn step(&mut self, storage: &mut Storage<'_>, identity: Identity) -> Result<bool, u32> {
        if self.outcome.is_some() {
            return Ok(true);
        }
        if matches!(self.phase, Phase::Cancel | Phase::Canceled) {
            return Err(STALE_PROOF);
        }
        storage.namespace_charge(self.root, self.charge)?;
        if identity != self.identity {
            return Err(STALE_PROOF);
        }
        if storage.state.epoch != self.epoch && self.phase != Phase::Restart {
            self.phase = Phase::Restart;
        }
        match self.phase {
            Phase::Restart => {
                if !self.cleanup_step(storage, false)? {
                    return Ok(false);
                }
                self.epoch = storage.state.epoch;
                self.current = self.base;
                self.parent = ROOT;
                self.scan = 0;
                self.depth = 0;
                self.length = self.initial;
                self.expected = 0;
                self.building = false;
                self.phase = Phase::Scan;
                if self.initial == 1 {
                    self.inline.fill(0);
                }
                self.read_offset = None;
                Ok(false)
            }
            Phase::BeginPage => {
                storage.cwd_result_allocate(&mut self.pages)?;
                storage.cwd_result_prepend(&mut self.pages, &[0]);
                self.phase = Phase::Scan;
                Ok(false)
            }
            Phase::Copy => {
                if self.pages.first == 0 {
                    storage.cwd_result_allocate(&mut self.pages)?;
                    return Ok(false);
                }
                let amount = (self.pages.first as usize).min(self.remaining as usize);
                let start = self.remaining as usize - amount;
                storage.cwd_result_prepend(
                    &mut self.pages,
                    &self.name[start..self.remaining as usize],
                );
                self.remaining -= amount as u16;
                if self.remaining == 0 {
                    self.phase = Phase::Move;
                }
                Ok(false)
            }
            Phase::Move => {
                storage.pin(self.parent, Pin::Pending)?;
                if self.current_pinned {
                    storage.unpin(self.current, Pin::Pending)?;
                }
                self.current = self.parent;
                self.current_pinned = true;
                self.scan = 0;
                self.depth += 1;
                self.phase = Phase::Scan;
                Ok(false)
            }
            Phase::Scan => {
                if self.current == ROOT {
                    return self.finish_walk(storage);
                }
                if self.depth as usize >= NODES - 1 {
                    return Ok(self.fail(NO_ENTRY));
                }
                let node = storage.node(self.current)?;
                if node.links == 0 {
                    return Ok(self.fail(NO_ENTRY));
                }
                let parent = node.parent;
                let parent_node = storage.node(parent)?;
                if !identity.permits(parent_node, self.parent_bits) {
                    return Ok(self.fail(ACCESS_DENIED));
                }
                let end = (self.scan as usize + 8).min(storage.entries());
                while (self.scan as usize) < end {
                    let row = self.scan as usize;
                    self.scan += 1;
                    if let Some((name, target)) = storage.entry(parent, row)
                        && target == self.current
                    {
                        self.name[0] = b'/';
                        self.name[1..name.len() + 1].copy_from_slice(name);
                        self.name_len = (name.len() + 1) as u16;
                        self.parent = parent;
                        if self.building {
                            self.remaining = self.name_len;
                            self.phase = Phase::Copy;
                        } else {
                            self.length += u32::from(self.name_len);
                            if self.inline_only && self.length as usize > INLINE {
                                return Ok(self.fail(proto_fs::NAME_TOO_LONG));
                            }
                            if self.length as usize <= INLINE {
                                let first = INLINE - self.length as usize;
                                self.inline[first..first + self.name_len as usize]
                                    .copy_from_slice(&self.name[..self.name_len as usize]);
                            }
                            self.phase = Phase::Move;
                        }
                        return Ok(false);
                    }
                }
                if self.scan as usize == storage.entries() {
                    Ok(self.fail(NO_ENTRY))
                } else {
                    Ok(false)
                }
            }
            _ => Err(STALE_PROOF),
        }
    }
    fn finish_walk(&mut self, storage: &mut Storage<'_>) -> Result<bool, u32> {
        if self.building {
            if self.pages.length != self.expected {
                return Err(STALE_PROOF);
            }
            self.outcome = Some(GetcwdOutcome::Ready {
                length: self.expected,
            });
            self.phase = Phase::Ready;
            return Ok(true);
        }
        if self.length == 1 {
            self.length = 2;
            self.inline[INLINE - 2] = b'/';
        }
        if self.inline_only && self.length as usize > INLINE {
            return Ok(self.fail(proto_fs::NAME_TOO_LONG));
        }
        if self.length as usize > MAX_LENGTH {
            return Ok(self.fail(NO_ENTRY));
        }
        if u64::from(self.length) > self.caller_size {
            self.outcome = Some(GetcwdOutcome::BufferTooSmall {
                required: self.length,
            });
            self.phase = Phase::Ready;
            return Ok(true);
        }
        self.expected = self.length;
        if self.length as usize <= INLINE {
            self.outcome = Some(GetcwdOutcome::Ready {
                length: self.length,
            });
            self.phase = Phase::Ready;
            return Ok(true);
        }
        storage.cwd_result_preflight(self.charge, (self.length as usize).div_ceil(PAGE))?;
        if self.current_pinned {
            storage.unpin(self.current, Pin::Pending)?;
            self.current_pinned = false;
        }
        self.current = self.base;
        self.scan = 0;
        self.depth = 0;
        self.building = true;
        self.phase = Phase::BeginPage;
        Ok(false)
    }
    /// The bytes of a ready result that fits the inline buffer, without the terminator.
    pub fn inline_bytes(&self) -> Option<&[u8]> {
        let Some(GetcwdOutcome::Ready { length }) = self.outcome else {
            return None;
        };
        (self.pages.head == NONE).then(|| &self.inline[INLINE - length as usize..INLINE - 1])
    }
    /// Locate at most eight page links, then copy at most MAX_READ immutable bytes.
    /// A chunk result leaves this record paid until the original full-result ACK.
    pub fn read_step(
        &mut self,
        storage: &Storage<'_>,
        offset: u32,
        out: &mut [u8],
    ) -> Result<Option<usize>, u32> {
        let Some(GetcwdOutcome::Ready { length }) = self.outcome else {
            return Err(RESOLVING);
        };
        if self.phase != Phase::Ready {
            return Err(STALE_PROOF);
        }
        if out.len() > MAX_READ || offset > length {
            return Err(INVALID_ARGUMENT);
        }
        let count = out.len().min((length - offset) as usize);
        if self.pages.head == NONE {
            let first = INLINE - length as usize + offset as usize;
            out[..count].copy_from_slice(&self.inline[first..first + count]);
            return Ok(Some(count));
        }
        if count == 0 {
            return Ok(Some(0));
        }
        if self.read_offset != Some(offset) {
            self.read_offset = Some(offset);
            self.read_page = self.pages.head;
            self.read_start = 0;
        }
        for _ in 0..8 {
            let first = if self.read_page == self.pages.head {
                self.pages.first as usize
            } else {
                0
            };
            let capacity = PAGE - first;
            if ((offset - self.read_start) as usize) < capacity {
                storage.cwd_result_read(
                    self.read_page,
                    first + (offset - self.read_start) as usize,
                    &mut out[..count],
                );
                return Ok(Some(count));
            }
            self.read_start += capacity as u32;
            self.read_page = storage.cwd_result_next(self.read_page);
        }
        Ok(None)
    }
    fn cleanup_step(&mut self, storage: &mut Storage<'_>, base: bool) -> Result<bool, u32> {
        if self.pages.head != NONE {
            storage.cwd_result_free(&mut self.pages);
            return Ok(false);
        }
        if self.current_pinned {
            storage.unpin(self.current, Pin::Pending)?;
            self.current_pinned = false;
            return Ok(false);
        }
        if base && self.base_pinned {
            storage.unpin(self.base, Pin::Pending)?;
            self.base_pinned = false;
            return Ok(false);
        }
        Ok(true)
    }
    /// Release one page or pin. The original root charge remains owned by the job.
    pub fn cancel_step(&mut self, storage: &mut Storage<'_>) -> Result<bool, u32> {
        self.phase = Phase::Cancel;
        let done = self.cleanup_step(storage, true)?;
        if done {
            self.phase = Phase::Canceled;
        }
        Ok(done)
    }
}
