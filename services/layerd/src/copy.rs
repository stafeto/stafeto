// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The copy up of lower files (the layered file system, step C4 part A): the table of the copies
//! the loop keeps, and the copier the worker thread runs. A change that has to write a file of the
//! lower set copies it into the layer first. The bytes move outside the loop, so no step of the loop
//! holds a copy (the bound of its step is 0.9 B). The loop does wait for the data file service, as
//! it always did: that service has one worker thread of synchronous calls, so a call of the loop
//! waits for at most one job of the copy that is ahead of it (a part of 64 KiB, an FSYNC or one
//! attribute call) and one tail step of the data file service (docs/data.md), besides the jobs of
//! other clients ahead of it and its own job; the wait is no work of the step:
//!
//! - `Table` (the loop): the places of the copies with their tickets (the place and the
//!   generation), the queue of the files that wait for one of the `ACTIVE` copies in work, and the
//!   outcome of a copy that is done until its place is taken again. A second request for a file
//!   whose copy is in the table gets the same ticket. `Waiters` holds the notifications of the
//!   programs that wait (WAIT with a handle).
//! - `Copier` (the worker): the copies in work, each of its turns one unit of one copy in turn.
//!   The unit that moves bytes is one cell of `CELL` bytes: up to six reads of the lower file into
//!   the cell (`proto_fs::READ_PORTION` each, the step of the RAM file service) and one write of
//!   the cell to the file in `work/`, so a small file waits behind a large one for at most
//!   `ACTIVE - 1` cells.
//!
//! The file in `work/` is named `c<place>-<generation>`; its number is that of the lower file, and
//! its owner, mode and times are the lower file's, made before the rename into the layer, which
//! the loop does (`changejob`, the stage `CopyIn`) in one visible step.

use crate::volume::{Bulk, CELL, LowerStat};
use proto_data as d;
use proto_wire::Status;

/// The copies in work at once, the files that wait for a place, and the places of the table.
pub const ACTIVE: usize = 4;
pub const QUEUE: usize = 8;
pub const PLACES: usize = ACTIVE + QUEUE;
/// The WAIT requests the service holds at once.
pub const WAITERS: usize = 16;
/// The bytes of one read of the lower file.
pub const PIECE: usize = proto_fs::READ_PORTION;
/// The first bytes of a program of the lower set.
pub const ELF: [u8; 4] = *b"\x7fELF";
/// The longest path of a lower file (a path of `proto_fs`).
pub const PATH: usize = proto_fs::MAX_PATH;

/// What a copy copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// The whole file.
    Whole,
    /// No bytes: a file with the attributes of the lower one (the open with a cut).
    Empty,
}

/// What the table says of a ticket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// The copy is not over: the reply waits.
    Pending,
    /// The copy is over: 0, or the code that is its failure.
    Over(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Free,
    /// Waits for one of the copies in work.
    Queued,
    /// Handed to the worker.
    Active,
    /// The worker is done; the loop has not yet made it visible or dropped it.
    Finished,
    /// Over; the outcome stays until the place is taken again.
    Over,
}

#[derive(Clone, Copy)]
struct Place {
    state: State,
    generation: u32,
    kind: Kind,
    path: [u8; PATH],
    len: u16,
    stat: LowerStat,
    /// The order of the queue.
    seq: u64,
    /// 0, or the code of the failure.
    code: u32,
    /// The worker made the file in `work/`.
    made: bool,
}

const NO_STAT: LowerStat = LowerStat {
    kind: 2,
    mode: 0,
    uid: 0,
    gid: 0,
    ino: 0,
    atime: 0,
    mtime: 0,
};

const FREE_PLACE: Place = Place {
    state: State::Free,
    generation: 0,
    kind: Kind::Whole,
    path: [0; PATH],
    len: 0,
    stat: NO_STAT,
    seq: 0,
    code: 0,
    made: false,
};

/// What the worker needs to copy one file.
#[derive(Clone, Copy)]
pub struct Order {
    pub place: u8,
    pub generation: u32,
    pub kind: Kind,
    path: [u8; PATH],
    len: u16,
    pub stat: LowerStat,
}

impl Order {
    /// The canonical path of the lower file.
    pub fn path(&self) -> &[u8] {
        &self.path[..usize::from(self.len)]
    }

    /// The path of the copy in `work/`.
    pub fn work(&self) -> ([u8; WORK_MAX], usize) {
        work_path(self.place, self.generation)
    }
}

/// The longest name of `work_path`.
pub const WORK_MAX: usize = 40;

/// `/.layers/work/c<place>-<generation>`.
pub fn work_path(place: u8, generation: u32) -> ([u8; WORK_MAX], usize) {
    let head = b"/.layers/work/c";
    let mut out = [0u8; WORK_MAX];
    out[..head.len()].copy_from_slice(head);
    let mut at = head.len();
    for (n, dash) in [(u64::from(place), true), (u64::from(generation), false)] {
        let mut digits = [0u8; 20];
        let (mut v, mut k) = (n, 0);
        loop {
            digits[k] = b'0' + (v % 10) as u8;
            v /= 10;
            k += 1;
            if v == 0 {
                break;
            }
        }
        for i in 0..k {
            out[at + i] = digits[k - 1 - i];
        }
        at += k;
        if dash {
            out[at] = b'-';
            at += 1;
        }
    }
    (out, at)
}

/// The ticket of a place and its generation: the generation above the place.
pub const fn ticket_of(place: u8, generation: u32) -> u64 {
    (generation as u64) << 8 | place as u64
}

/// The place and the generation a ticket names.
pub const fn ticket_parts(ticket: u64) -> (u8, u32) {
    (ticket as u8, (ticket >> 8) as u32)
}

/// The ticket of a copy that is over before it is asked for (the link a rename copies is made in
/// the job): WAIT answers 0 at once and the program asks again. Place 0 with the generation
/// `u32::MAX`, which the table reaches after four billion copies of one place.
pub const DONE_TICKET: u64 = ticket_of(0, u32::MAX);

/// Whether `ticket` is one the table gave: a place and a generation of at most 32 bits, and nothing
/// above them. A WAIT with another value is INVALID_ARGUMENT (the bits above would be dropped by
/// `ticket_parts`, and the notification kept under a value no copy ever ends).
pub const fn ticket_valid(ticket: u64) -> bool {
    let (place, generation) = ticket_parts(ticket);
    (place as usize) < PLACES && generation != 0 && ticket_of(place, generation) == ticket
}

/// What a worker says of a copy that ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ended {
    pub place: u8,
    pub generation: u32,
    /// 0, or the code of the failure.
    pub code: u32,
    /// The file in `work/` was made (a failed copy leaves it for the reaper).
    pub made: bool,
}

/// The table of the copies the loop keeps.
pub struct Table {
    places: [Place; PLACES],
    seq: u64,
    /// The copies ever reserved, made visible, dropped, and failed (the lines of the service).
    pub reserved: u32,
    pub committed: u32,
    pub dropped: u32,
    pub failed: u32,
}

impl Default for Table {
    fn default() -> Self {
        Table::new()
    }
}

impl Table {
    pub const fn new() -> Table {
        Table {
            places: [FREE_PLACE; PLACES],
            seq: 0,
            reserved: 0,
            committed: 0,
            dropped: 0,
            failed: 0,
        }
    }

    fn count(&self, state: State) -> usize {
        self.places.iter().filter(|p| p.state == state).count()
    }

    /// The ticket of the copy of `path` that is in work (queued, handed to the worker, or ended
    /// and not yet made visible); a copy that is over is none.
    pub fn find(&self, path: &[u8]) -> Option<u64> {
        self.places.iter().enumerate().find_map(|(i, p)| {
            let live = matches!(p.state, State::Queued | State::Active | State::Finished);
            (live && &p.path[..usize::from(p.len)] == path)
                .then(|| ticket_of(i as u8, p.generation))
        })
    }

    /// A place is free for a copy, and the queue has room.
    pub fn room(&self) -> bool {
        self.count(State::Queued) < QUEUE && self.take_place().is_some()
    }

    /// A place a new copy takes: a free one, else the one that has been over the longest.
    fn take_place(&self) -> Option<usize> {
        self.places
            .iter()
            .position(|p| p.state == State::Free)
            .or_else(|| {
                self.places
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| p.state == State::Over)
                    .min_by_key(|(_, p)| p.seq)
                    .map(|(i, _)| i)
            })
    }

    /// Queues the copy of the lower file at `path`: its ticket, or None when no place or no room
    /// in the queue is left.
    pub fn reserve(&mut self, path: &[u8], kind: Kind, stat: LowerStat) -> Option<u64> {
        if path.len() > PATH || !self.room() {
            return None;
        }
        let at = self.take_place()?;
        self.seq += 1;
        let p = &mut self.places[at];
        // The generation `u32::MAX` is the one of `DONE_TICKET`: no copy has it.
        p.generation = match p.generation.wrapping_add(1) {
            0 | u32::MAX => 1,
            g => g,
        };
        p.state = State::Queued;
        p.kind = kind;
        p.path[..path.len()].copy_from_slice(path);
        p.len = path.len() as u16;
        p.stat = stat;
        p.seq = self.seq;
        p.code = 0;
        p.made = false;
        self.reserved += 1;
        Some(ticket_of(at as u8, p.generation))
    }

    /// The next copy for the worker: the oldest queued one, when fewer than `ACTIVE` are in work.
    pub fn next_order(&mut self) -> Option<Order> {
        if self.count(State::Active) >= ACTIVE {
            return None;
        }
        let at = self
            .places
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state == State::Queued)
            .min_by_key(|(_, p)| p.seq)
            .map(|(i, _)| i)?;
        let p = &mut self.places[at];
        p.state = State::Active;
        Some(Order {
            place: at as u8,
            generation: p.generation,
            kind: p.kind,
            path: p.path,
            len: p.len,
            stat: p.stat,
        })
    }

    /// The worker ended a copy. False for a copy the table does not hold as handed out.
    pub fn ended(&mut self, e: Ended) -> bool {
        let Some(p) = self.places.get_mut(usize::from(e.place)) else {
            return false;
        };
        if p.state != State::Active || p.generation != e.generation {
            return false;
        }
        p.state = State::Finished;
        p.code = e.code;
        p.made = e.made;
        true
    }

    /// The oldest copy the worker has ended: its place and generation.
    pub fn finished(&self) -> Option<(u8, u32)> {
        self.places
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state == State::Finished)
            .min_by_key(|(_, p)| p.seq)
            .map(|(i, p)| (i as u8, p.generation))
    }

    /// The facts of a copy that ended, for the stage that makes it visible or drops it: the path
    /// of the lower file, its stat, the code of the worker and whether `work/` holds the file.
    pub fn facts(&self, place: u8, generation: u32) -> Option<(&[u8], LowerStat, u32, bool)> {
        let p = self.places.get(usize::from(place))?;
        (p.state == State::Finished && p.generation == generation)
            .then(|| (&p.path[..usize::from(p.len)], p.stat, p.code, p.made))
    }

    /// The copy is over (made visible, dropped or failed): its outcome stays for WAIT, and the
    /// waiters are answered with it. `code` is 0 or the failure.
    pub fn over(&mut self, place: u8, generation: u32, code: u32, dropped: bool) {
        let Some(p) = self.places.get_mut(usize::from(place)) else {
            return;
        };
        if p.state != State::Finished || p.generation != generation {
            return;
        }
        p.state = State::Over;
        p.code = code;
        if code != 0 {
            self.failed += 1;
        } else if dropped {
            self.dropped += 1;
        } else {
            self.committed += 1;
        }
    }

    /// What WAIT with `ticket` finds: a copy in work is pending; one that is over has its outcome;
    /// a ticket whose place was taken again by another copy is over with no failure (the copy it
    /// named ended long ago, and the request sent again sees the present state).
    pub fn wait(&self, ticket: u64) -> Wait {
        let (place, generation) = ticket_parts(ticket);
        match self.places.get(usize::from(place)) {
            Some(p) if p.generation == generation => match p.state {
                State::Queued | State::Active | State::Finished => Wait::Pending,
                State::Over => Wait::Over(p.code),
                State::Free => Wait::Over(0),
            },
            _ => Wait::Over(0),
        }
    }

    /// The copies in work, queued ones included.
    pub fn in_work(&self) -> usize {
        self.count(State::Queued) + self.count(State::Active) + self.count(State::Finished)
    }

    /// The copies the worker holds.
    pub fn active(&self) -> usize {
        self.count(State::Active)
    }
}

/// The waiters of the copies: `N` places for what the service gives each when its copy ends (the
/// notification a program's WAIT brought), each kept under the session that asked (`owner`) and the
/// ticket. A session has at most `PER_OWNER` places, for one ticket or for several (two threads of a
/// program, or one thread after a signal, wait for one copy); a waiter is never replaced, and none is
/// told before its copy ends, so no notification bounces between threads.
pub struct Waiters<P, const N: usize> {
    held: [Option<(u64, u64, P)>; N],
}

/// The places of one session.
pub const PER_OWNER: usize = 4;

/// What `Waiters::add` did.
#[derive(Debug, PartialEq, Eq)]
pub enum Added<P> {
    /// A place was taken.
    New,
    /// No place: the table is full or the session holds `PER_OWNER`; the waiter comes back and the
    /// program is told to ask again later (STARTING).
    Full(P),
}

impl<P, const N: usize> Default for Waiters<P, N> {
    fn default() -> Self {
        Waiters::new()
    }
}

impl<P, const N: usize> Waiters<P, N> {
    pub const fn new() -> Self {
        Waiters {
            held: [const { None }; N],
        }
    }

    /// Holds `waiter` of the session `owner` for `ticket`.
    pub fn add(&mut self, owner: u64, ticket: u64, waiter: P) -> Added<P> {
        let mine = self
            .held
            .iter()
            .flatten()
            .filter(|(o, _, _)| *o == owner)
            .count();
        if mine >= PER_OWNER {
            return Added::Full(waiter);
        }
        match self.held.iter_mut().find(|h| h.is_none()) {
            Some(place) => {
                *place = Some((owner, ticket, waiter));
                Added::New
            }
            None => Added::Full(waiter),
        }
    }

    /// One waiter held for `ticket`.
    pub fn take(&mut self, ticket: u64) -> Option<P> {
        let place = self
            .held
            .iter_mut()
            .find(|h| h.as_ref().is_some_and(|(_, t, _)| *t == ticket))?;
        place.take().map(|(_, _, p)| p)
    }

    /// The waiters of the session `owner` go (it ended): they are of no use.
    pub fn drop_owner(&mut self, owner: u64) {
        for place in &mut self.held {
            if place.as_ref().is_some_and(|(o, _, _)| *o == owner) {
                *place = None;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.held.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The code of a status of a call of a copy, for the table: the codes the client turns into
/// ENOSPC and EROFS keep their own, any other failure is an I/O error.
pub fn code_of(status: Status) -> u32 {
    match status {
        Status::Unknown(c) if c == d::NO_SPACE || c == proto_fs::NO_SPACE => proto_fs::NO_SPACE,
        Status::Unknown(c) if c == d::READ_ONLY || c == proto_fs::READ_ONLY_FILESYSTEM => {
            proto_fs::READ_ONLY_FILESYSTEM
        }
        _ => proto_layer::IO,
    }
}

/// Where the worker makes the copy: the file in `work/`. The break `break-layerd-copy-rename-open`
/// makes it at its final name in the live layer 00, so the name is visible before the bytes are
/// there (a cut leaves a partial file under the name: `cargo xtask layer-cut copy`).
fn target(order: &Order) -> ([u8; PATH + 16], usize) {
    let mut out = [0u8; PATH + 16];
    let head: &[u8] = if cfg!(feature = "break-layerd-copy-rename-open") {
        b"/.layers/00"
    } else {
        let (work, wl) = order.work();
        out[..wl].copy_from_slice(&work[..wl]);
        return (out, wl);
    };
    let path = order.path();
    out[..head.len()].copy_from_slice(head);
    out[head.len()..head.len() + path.len()].copy_from_slice(path);
    (out, head.len() + path.len())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Open the lower file, check its first bytes, make the file in `work/`.
    Head,
    /// Cells: read, write.
    Cells,
    /// Sync, owner, mode, times, close.
    Finish,
}

#[derive(Clone, Copy)]
struct Run {
    order: Order,
    phase: Phase,
    lower: Option<u32>,
    work: Option<u32>,
    made: bool,
    offset: u64,
}

/// The copies the worker has in work.
pub struct Copier {
    runs: [Option<Run>; ACTIVE],
    next: usize,
}

impl Default for Copier {
    fn default() -> Self {
        Copier::new()
    }
}

impl Copier {
    pub const fn new() -> Copier {
        Copier {
            runs: [None; ACTIVE],
            next: 0,
        }
    }

    /// Takes a copy in; false when `ACTIVE` copies are in work.
    pub fn add(&mut self, order: Order) -> bool {
        match self.runs.iter_mut().find(|r| r.is_none()) {
            Some(place) => {
                *place = Some(Run {
                    order,
                    phase: Phase::Head,
                    lower: None,
                    work: None,
                    made: false,
                    offset: 0,
                });
                true
            }
            None => false,
        }
    }

    /// Copies in work.
    pub fn busy(&self) -> usize {
        self.runs.iter().flatten().count()
    }

    /// One unit of the next copy in turn; the copy's end when it was this one.
    pub fn turn<B: Bulk>(&mut self, bulk: &mut B) -> Option<Ended> {
        for k in 0..ACTIVE {
            let at = (self.next + k) % ACTIVE;
            let Some(mut run) = self.runs[at] else {
                continue;
            };
            self.next = (at + 1) % ACTIVE;
            match Self::unit(&mut run, bulk) {
                Ok(true) => {
                    self.runs[at] = None;
                    return Some(Ended {
                        place: run.order.place,
                        generation: run.order.generation,
                        code: 0,
                        made: run.made,
                    });
                }
                Ok(false) => self.runs[at] = Some(run),
                Err(code) => {
                    Self::drop_handles(&mut run, bulk);
                    self.runs[at] = None;
                    return Some(Ended {
                        place: run.order.place,
                        generation: run.order.generation,
                        code,
                        made: run.made,
                    });
                }
            }
            return None;
        }
        None
    }

    fn drop_handles<B: Bulk>(run: &mut Run, bulk: &mut B) {
        if let Some(fd) = run.lower.take() {
            bulk.close_lower(fd);
        }
        if let Some(h) = run.work.take() {
            let _ = bulk.close(h);
        }
    }

    /// One cell: the reads of the lower file into it (the first `have` bytes are there already, and
    /// `eof` says the file ended inside them) and one write of it.
    fn cells<B: Bulk>(run: &mut Run, bulk: &mut B, have: usize, eof: bool) -> Result<(), u32> {
        let (Some(fd), Some(h)) = (run.lower, run.work) else {
            return Err(proto_layer::IO);
        };
        let mut filled = have;
        let mut ended = eof;
        while filled < CELL && !ended {
            let want = PIECE.min(CELL - filled);
            let got = bulk
                .read_lower(fd, run.offset + filled as u64, filled, want)
                .map_err(code_of)?;
            filled += got;
            // A read that is short is the end of the file (the service reads what one state of the
            // file holds), and the next place would be no whole page.
            ended = got < want;
        }
        if filled > 0 {
            let wrote = bulk.write_cell(h, run.offset, filled).map_err(code_of)?;
            if wrote != filled {
                return Err(proto_fs::NO_SPACE);
            }
            run.offset += filled as u64;
            if filled == CELL
                && run.offset == CELL as u64
                && crate::cut::armed(crate::cut::MID_COPY)
            {
                bulk.cut(crate::cut::MID_COPY);
            }
        }
        if filled < CELL {
            run.phase = Phase::Finish;
        }
        Ok(())
    }

    /// One unit; true when the copy is done.
    fn unit<B: Bulk>(run: &mut Run, bulk: &mut B) -> Result<bool, u32> {
        let fail = |s: Status| code_of(s);
        match run.phase {
            Phase::Head => {
                let fd = bulk.open_lower(run.order.path()).map_err(fail)?;
                run.lower = Some(fd);
                // A program is never copied up: its first bytes are the check (an empty copy reads
                // four, a whole one the first read of the copy).
                let len = if run.order.kind == Kind::Empty {
                    ELF.len()
                } else {
                    PIECE
                };
                let got = bulk.read_lower(fd, 0, 0, len).map_err(fail)?;
                if !cfg!(feature = "break-layerd-copy-elf")
                    && got >= ELF.len()
                    && bulk.cell()[..ELF.len()] == ELF
                {
                    return Err(proto_fs::READ_ONLY_FILESYSTEM);
                }
                let (work, wl) = target(&run.order);
                // The number of the copy is the lower file's (the break: one of the counter).
                let ino = if cfg!(feature = "break-layerd-copy-counter-ino") {
                    run.order.stat.ino | proto_fs::names::UPPER_INO_TAG
                } else {
                    run.order.stat.ino
                };
                let h = bulk.open_work(&work[..wl], 0o600, ino).map_err(fail)?;
                run.work = Some(h);
                run.made = true;
                if crate::cut::armed(crate::cut::WORK_MADE) {
                    bulk.cut(crate::cut::WORK_MADE);
                }
                if run.order.kind == Kind::Empty {
                    run.phase = Phase::Finish;
                    return Ok(false);
                }
                // The first cell goes on from the piece the check read, which is in the cell
                // still: no second read of it.
                run.phase = Phase::Cells;
                Self::cells(run, bulk, got, got < PIECE).map(|()| false)
            }
            Phase::Cells => Self::cells(run, bulk, 0, false).map(|()| false),
            Phase::Finish => {
                let (Some(fd), Some(h)) = (run.lower, run.work) else {
                    return Err(proto_layer::IO);
                };
                let (work, wl) = target(&run.order);
                let work = &work[..wl];
                let s = run.order.stat;
                bulk.fsync(h).map_err(fail)?;
                // The deliberate break `break-layerd-copy-attrs`: the copy keeps the attributes the
                // volume gave it.
                if !cfg!(feature = "break-layerd-copy-attrs") {
                    // The owner first, so the set-ID bits of the mode that follows stay.
                    bulk.chown(work, s.uid, s.gid).map_err(fail)?;
                    bulk.chmod(work, s.mode & 0o7777).map_err(fail)?;
                    bulk.utimens(work, s.atime, s.mtime).map_err(fail)?;
                }
                run.work = None;
                bulk.close(h).map_err(fail)?;
                if crate::cut::armed(crate::cut::WORK_CLOSED) {
                    bulk.cut(crate::cut::WORK_CLOSED);
                }
                run.lower = None;
                bulk.close_lower(fd);
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(ino: u64) -> LowerStat {
        LowerStat {
            ino,
            mode: 0o644,
            ..NO_STAT
        }
    }

    #[test]
    fn a_ticket_is_the_place_and_its_generation_and_the_work_name_says_both() {
        for (place, generation) in [(0u8, 1u32), (11, 7), (255, u32::MAX)] {
            let t = ticket_of(place, generation);
            assert_eq!(ticket_parts(t), (place, generation));
        }
        let (name, n) = work_path(3, 12);
        assert_eq!(&name[..n], b"/.layers/work/c3-12");
        let (name, n) = work_path(0, 1);
        assert_eq!(&name[..n], b"/.layers/work/c0-1");
    }

    #[test]
    fn no_copy_has_the_generation_of_the_ticket_that_is_over() {
        let mut t = Table::new();
        for place in &mut t.places {
            place.generation = u32::MAX - 1;
        }
        let ticket = t.reserve(b"/etc/motd", Kind::Whole, stat(1)).unwrap();
        assert_ne!(ticket_parts(ticket).1, u32::MAX);
        assert_ne!(ticket, DONE_TICKET);
        assert_eq!(t.wait(DONE_TICKET), Wait::Over(0));
    }

    #[test]
    fn a_second_request_for_a_file_in_work_gets_the_same_ticket() {
        let mut t = Table::new();
        let a = t.reserve(b"/etc/motd", Kind::Whole, stat(1)).unwrap();
        let b = t.reserve(b"/etc/passwd", Kind::Whole, stat(2)).unwrap();
        assert_ne!(a, b);
        assert_eq!(t.find(b"/etc/motd"), Some(a));
        assert_eq!(t.find(b"/etc/passwd"), Some(b));
        assert_eq!(t.find(b"/etc/other"), None);
        // Handed out and ended, it is still the same copy until it is over.
        let order = t.next_order().unwrap();
        assert_eq!(t.find(b"/etc/motd"), Some(a));
        assert!(t.ended(Ended {
            place: order.place,
            generation: order.generation,
            code: 0,
            made: true,
        }));
        assert_eq!(t.find(b"/etc/motd"), Some(a));
        t.over(order.place, order.generation, 0, false);
        assert_eq!(t.find(b"/etc/motd"), None);
    }

    #[test]
    fn four_copies_are_in_work_eight_wait_and_the_next_file_is_refused() {
        let mut t = Table::new();
        let mut paths = std::vec::Vec::new();
        let mut orders = std::vec::Vec::new();
        for k in 0..PLACES {
            let p = std::format!("/f{k}");
            assert!(t.room(), "{k}");
            t.reserve(p.as_bytes(), Kind::Whole, stat(k as u64 + 1))
                .unwrap();
            paths.push(p);
            // The loop hands a copy to the worker as soon as one of its four places is free.
            if let Some(o) = t.next_order() {
                orders.push(o);
            }
        }
        // Four are in work, eight wait, and the next file is refused.
        assert_eq!(
            (orders.len(), t.active(), t.in_work()),
            (ACTIVE, ACTIVE, PLACES)
        );
        assert!(!t.room());
        assert!(t.reserve(b"/more", Kind::Whole, stat(99)).is_none());
        assert_eq!(
            orders
                .iter()
                .map(|o| o.path().to_vec())
                .collect::<std::vec::Vec<_>>(),
            paths[..ACTIVE]
                .iter()
                .map(|p| p.as_bytes().to_vec())
                .collect::<std::vec::Vec<_>>()
        );
        assert!(t.next_order().is_none());
        let first = orders[0];
        t.ended(Ended {
            place: first.place,
            generation: first.generation,
            code: 0,
            made: true,
        });
        // An ended copy is no longer in the worker's hands, and the oldest one that waits goes in.
        assert_eq!(t.active(), ACTIVE - 1);
        let fifth = t.next_order().unwrap();
        assert_eq!(fifth.path(), paths[ACTIVE].as_bytes());
        assert_eq!(t.finished(), Some((first.place, first.generation)));
        t.over(first.place, first.generation, 0, false);
        // The place of the file that is over takes a new copy, and the old ticket is over with 0.
        assert!(t.room());
        let old = ticket_of(first.place, first.generation);
        assert_eq!(t.wait(old), Wait::Over(0));
        let again = t.reserve(b"/new", Kind::Empty, stat(100)).unwrap();
        assert_ne!(again, old);
        assert_eq!(ticket_parts(again).0, first.place);
        assert_eq!(t.wait(old), Wait::Over(0));
        assert_eq!(t.wait(again), Wait::Pending);
    }

    #[test]
    fn a_failed_copy_keeps_its_code_for_the_wait_that_comes_late() {
        let mut t = Table::new();
        let ticket = t.reserve(b"/big", Kind::Whole, stat(5)).unwrap();
        assert_eq!(t.wait(ticket), Wait::Pending);
        let o = t.next_order().unwrap();
        assert_eq!(t.wait(ticket), Wait::Pending);
        t.ended(Ended {
            place: o.place,
            generation: o.generation,
            code: proto_fs::NO_SPACE,
            made: true,
        });
        let (path, s, code, made) = t.facts(o.place, o.generation).unwrap();
        assert_eq!(
            (path, s.ino, code, made),
            (&b"/big"[..], 5, proto_fs::NO_SPACE, true)
        );
        assert_eq!(t.wait(ticket), Wait::Pending);
        t.over(o.place, o.generation, proto_fs::NO_SPACE, false);
        assert_eq!(t.wait(ticket), Wait::Over(proto_fs::NO_SPACE));
        assert_eq!(t.wait(ticket), Wait::Over(proto_fs::NO_SPACE));
        assert_eq!((t.failed, t.committed, t.dropped), (1, 0, 0));
        // The same file asked again is a new copy with a new ticket.
        let next = t.reserve(b"/big", Kind::Whole, stat(5)).unwrap();
        assert_ne!(next, ticket);
        // The old ticket keeps its outcome until its place is taken by another copy.
        assert_eq!(t.wait(ticket), Wait::Over(proto_fs::NO_SPACE));
    }

    #[test]
    fn a_stale_end_or_a_ticket_never_given_changes_nothing() {
        let mut t = Table::new();
        let ticket = t.reserve(b"/a", Kind::Whole, stat(1)).unwrap();
        let o = t.next_order().unwrap();
        assert!(!t.ended(Ended {
            place: o.place,
            generation: o.generation + 1,
            code: 0,
            made: false,
        }));
        assert!(!t.ended(Ended {
            place: 200,
            generation: 1,
            code: 0,
            made: false,
        }));
        assert_eq!(t.wait(ticket), Wait::Pending);
        assert_eq!(t.wait(ticket_of(9, 4)), Wait::Over(0));
        assert_eq!(t.wait(ticket_of(250, 4)), Wait::Over(0));
    }

    #[test]
    fn two_waits_of_one_session_for_one_ticket_are_both_kept_and_told_when_the_copy_ends() {
        let mut w: Waiters<u32, WAITERS> = Waiters::new();
        // Two threads of one session wait for one copy: both are kept, none replaces the other.
        assert_eq!(w.add(1, 7, 10), Added::New);
        assert_eq!(w.add(1, 7, 11), Added::New);
        assert_eq!(w.len(), 2);
        // Nothing is told while the copy goes on (the service tells by `take` when it ends).
        assert_eq!(w.len(), 2);
        let mut told = std::vec::Vec::new();
        while let Some(x) = w.take(7) {
            told.push(x);
        }
        told.sort_unstable();
        assert_eq!(told, [10, 11]);
        assert!(w.is_empty());
        // A session holds `PER_OWNER` and no more, for one ticket or several; others are not held back.
        for k in 0..PER_OWNER as u32 {
            assert_eq!(w.add(1, u64::from(k % 2), k), Added::New);
        }
        assert_eq!(w.add(1, 0, 99), Added::Full(99));
        assert_eq!(w.add(2, 0, 5), Added::New);
        // Four sessions of four fill the table.
        let mut full: Waiters<u32, WAITERS> = Waiters::new();
        for k in 0..WAITERS as u32 {
            assert_eq!(full.add(u64::from(k / PER_OWNER as u32), 1, k), Added::New);
        }
        assert_eq!(full.add(9, 1, 0), Added::Full(0));
        // A session that ended takes its own away.
        w.drop_owner(1);
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn a_ticket_with_a_bit_above_its_place_and_generation_is_no_ticket() {
        let t = ticket_of(3, 12);
        assert!(ticket_valid(t));
        assert!(!ticket_valid(t | 1 << 40));
        assert!(!ticket_valid(t | 1 << 63));
        assert!(!ticket_valid(0));
        assert!(!ticket_valid(3));
        assert!(ticket_valid(ticket_of(PLACES as u8 - 1, u32::MAX)));
        // A place the table does not have is no ticket either.
        assert!(!ticket_valid(ticket_of(PLACES as u8, 1)) && !ticket_valid(ticket_of(255, 1)));
        // The table would find the forged value Pending, the reason the service refuses it first.
        let mut table = Table::new();
        let real = table.reserve(b"/a", Kind::Whole, stat(1)).unwrap();
        assert_eq!(table.wait(real | 1 << 40), Wait::Pending);
        assert!(!ticket_valid(real | 1 << 40) && ticket_valid(real));
    }

    #[test]
    fn the_codes_the_client_maps_stay_and_the_rest_are_an_io_error() {
        assert_eq!(code_of(Status::Unknown(d::NO_SPACE)), proto_fs::NO_SPACE);
        assert_eq!(
            code_of(Status::Unknown(d::READ_ONLY)),
            proto_fs::READ_ONLY_FILESYSTEM
        );
        assert_eq!(code_of(Status::Unknown(d::IO)), proto_layer::IO);
        assert_eq!(code_of(Status::BadSize), proto_layer::IO);
    }

    // ------------------------------------------------------------------ the copier

    use crate::testkit::{FakeBulk, FakeLower, FakeVolume};

    fn st(code: u32) -> Status {
        Status::Unknown(code)
    }

    fn bytes(n: usize, salt: u8) -> std::vec::Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt) | 1)
            .collect()
    }

    fn world() -> (FakeVolume, FakeLower) {
        let mut v = FakeVolume::new();
        v.dir("/.layers", 0o755, 0).dir("/.layers/work", 0o700, 0);
        let mut l = FakeLower::new();
        l.dir("/etc", 10);
        (v, l)
    }

    fn order(t: &mut Table, l: &FakeLower, path: &str, kind: Kind) -> Order {
        let stat = {
            let mut probe = crate::testkit::FakeLower::new();
            probe.nodes = l.nodes.clone();
            probe.attrs = l.attrs.clone();
            probe.times = l.times.clone();
            use crate::volume::Lower;
            let mut p = probe.stat_start(path.as_bytes(), false).unwrap();
            probe.stat_poll(&mut p).unwrap().unwrap()
        };
        t.reserve(path.as_bytes(), kind, stat).unwrap();
        t.next_order().unwrap()
    }

    /// Turns until `n` copies have ended; the ends, in order, and the turns taken.
    fn run(c: &mut Copier, b: &mut FakeBulk<'_>, n: usize) -> (std::vec::Vec<Ended>, usize) {
        let (mut ends, mut turns) = (std::vec::Vec::new(), 0);
        while ends.len() < n {
            turns += 1;
            assert!(turns < 1000, "a copy that never ends");
            if let Some(e) = c.turn(b) {
                ends.push(e);
            }
        }
        (ends, turns)
    }

    #[test]
    fn a_file_is_copied_a_cell_at_a_time_with_its_number_owner_mode_and_times() {
        let (mut v, mut l) = world();
        let data = bytes(150_000, 3);
        l.file("/etc/motd", 4_000_000_000_011)
            .bytes("/etc/motd", &data)
            .attr("/etc/motd", 0o4755, 7, 8)
            .times_of("/etc/motd", 111, 222);
        let mut t = Table::new();
        let o = order(&mut t, &l, "/etc/motd", Kind::Whole);
        let mut b = FakeBulk::new(&mut v, &mut l);
        let mut c = Copier::new();
        assert!(c.add(o));
        let (ends, turns) = run(&mut c, &mut b, 1);
        assert_eq!(
            ends[0],
            Ended {
                place: o.place,
                generation: o.generation,
                code: 0,
                made: true
            }
        );
        // The head with the first cell (the check read its first piece, which stays), two more cells
        // (the last is the short one: the end), the finish.
        assert_eq!(turns, 1 + 2 + 1);
        assert_eq!(
            b.writes,
            [(0, 65_536), (65_536, 65_536), (131_072, 150_000 - 131_072)]
        );
        // Every read is a piece of the step of the RAM file service, six to a cell (five of 12
        // KiB and one of 4 KiB); the head read the first piece once more.
        assert!(b.reads.iter().all(|&(_, n)| n <= PIECE));
        assert_eq!(b.reads[0], (0, PIECE));
        // The first cell is that piece and five reads more (no second read of the piece).
        assert_eq!(b.reads[..6].iter().map(|r| r.1).sum::<usize>(), CELL);
        assert_eq!(b.reads[1].0, PIECE as u64);
        let (work, wl) = o.work();
        let node = &b.volume.nodes[&work[..wl]];
        assert_eq!(node.data, data);
        assert_eq!(
            (node.ino, node.uid, node.gid, node.mode, node.times),
            (4_000_000_000_011, 7, 8, 0o4755, (111, 222))
        );
        // Nothing is left open on either side, and the order of the finish is the plan's.
        assert_eq!(b.open_fds(), 0);
        let tail: std::vec::Vec<&str> = b
            .calls
            .iter()
            .rev()
            .take(6)
            .rev()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(
            tail,
            ["fsync", "chown", "chmod", "utimens", "close", "close_lower"]
        );
    }

    #[test]
    fn a_file_of_whole_cells_and_an_empty_one_end_with_a_read_of_nothing() {
        let (mut v, mut l) = world();
        l.file("/etc/a", 21).bytes("/etc/a", &bytes(CELL, 1));
        l.file("/etc/e", 22);
        let mut t = Table::new();
        let a = order(&mut t, &l, "/etc/a", Kind::Whole);
        let e = order(&mut t, &l, "/etc/e", Kind::Whole);
        let mut b = FakeBulk::new(&mut v, &mut l);
        let mut c = Copier::new();
        c.add(a);
        c.add(e);
        let (ends, _) = run(&mut c, &mut b, 2);
        assert!(ends.iter().all(|e| e.code == 0 && e.made));
        assert_eq!(b.writes, [(0, CELL)]);
        let (wa, la) = a.work();
        let (we, le) = e.work();
        assert_eq!(b.volume.nodes[&wa[..la]].data, bytes(CELL, 1));
        assert!(b.volume.nodes[&we[..le]].data.is_empty());
    }

    #[test]
    fn copies_take_turns_a_cell_each_so_a_small_file_waits_for_four_cells_at_most() {
        let (mut v, mut l) = world();
        l.file("/etc/big", 31)
            .bytes("/etc/big", &bytes(5 * CELL + 10, 5));
        l.file("/etc/small", 32).bytes("/etc/small", &bytes(100, 6));
        let mut t = Table::new();
        let big = order(&mut t, &l, "/etc/big", Kind::Whole);
        let small = order(&mut t, &l, "/etc/small", Kind::Whole);
        let mut b = FakeBulk::new(&mut v, &mut l);
        let mut c = Copier::new();
        c.add(big);
        c.add(small);
        let mut ends = std::vec::Vec::new();
        for _ in 0..40 {
            if let Some(e) = c.turn(&mut b) {
                ends.push((e.place, b.writes.len()));
            }
            if ends.len() == 2 {
                break;
            }
        }
        // The small file ended long before the big one: after its head, its one cell and its
        // finish, while the big file had written two cells.
        assert_eq!(ends[0].0, small.place);
        assert_eq!(ends[1].0, big.place);
        assert!(ends[0].1 <= 3, "{ends:?}");
        assert_eq!(b.writes.len(), 5 + 1 + 1);
        let (wb, lb) = big.work();
        assert_eq!(b.volume.nodes[&wb[..lb]].data, bytes(5 * CELL + 10, 5));
    }

    #[test]
    fn a_program_is_never_copied_and_leaves_nothing_in_work() {
        let (mut v, mut l) = world();
        let mut elf = b"\x7fELF".to_vec();
        elf.extend(bytes(30_000, 9));
        l.file("/etc/prog", 41).bytes("/etc/prog", &elf);
        l.file("/etc/short", 42).bytes("/etc/short", b"\x7fEL");
        let mut t = Table::new();
        for kind in [Kind::Whole, Kind::Empty] {
            let o = order(&mut t, &l, "/etc/prog", kind);
            let mut b = FakeBulk::new(&mut v, &mut l);
            let mut c = Copier::new();
            c.add(o);
            let (ends, _) = run(&mut c, &mut b, 1);
            assert_eq!(
                (ends[0].code, ends[0].made),
                (proto_fs::READ_ONLY_FILESYSTEM, false),
                "{kind:?}"
            );
            assert_eq!(b.open_fds(), 0);
            assert_eq!(b.volume.calls_of("open_numbered"), 0);
            // The empty copy reads four bytes, the whole one the first piece.
            assert_eq!(b.reads, [(0, if kind == Kind::Empty { 4 } else { PIECE })]);
            let (w, n) = o.work();
            assert!(!b.volume.nodes.contains_key(&w[..n]));
            t.ended(ends[0]);
            t.over(o.place, o.generation, ends[0].code, false);
        }
        // Three bytes of a program are no program, and a file that starts with other bytes is data.
        let o = order(&mut t, &l, "/etc/short", Kind::Whole);
        let mut b = FakeBulk::new(&mut v, &mut l);
        let mut c = Copier::new();
        c.add(o);
        let (ends, _) = run(&mut c, &mut b, 1);
        assert_eq!(ends[0].code, 0);
    }

    #[test]
    fn a_cut_copy_is_an_empty_file_with_the_attributes_of_the_lower_one() {
        let (mut v, mut l) = world();
        l.file("/etc/log", 51)
            .bytes("/etc/log", &bytes(100_000, 2))
            .attr("/etc/log", 0o640, 3, 4)
            .times_of("/etc/log", 9, 10);
        let mut t = Table::new();
        let o = order(&mut t, &l, "/etc/log", Kind::Empty);
        let mut b = FakeBulk::new(&mut v, &mut l);
        let mut c = Copier::new();
        c.add(o);
        let (ends, turns) = run(&mut c, &mut b, 1);
        assert_eq!((ends[0].code, turns), (0, 2));
        assert!(b.writes.is_empty());
        let (w, n) = o.work();
        let node = &b.volume.nodes[&w[..n]];
        assert!(node.data.is_empty());
        assert_eq!(
            (node.ino, node.uid, node.gid, node.mode, node.times),
            (51, 3, 4, 0o640, (9, 10))
        );
    }

    #[test]
    fn a_failure_in_any_call_ends_the_copy_with_its_code_and_closes_what_it_holds() {
        for (call, status, code, made) in [
            ("open_lower", st(proto_fs::NO_ENTRY), proto_layer::IO, false),
            (
                "read_lower",
                st(proto_fs::INVALID_ARGUMENT),
                proto_layer::IO,
                false,
            ),
            ("open_work", st(d::NO_SPACE), proto_fs::NO_SPACE, false),
            ("write_cell", st(d::NO_SPACE), proto_fs::NO_SPACE, true),
            (
                "write_cell",
                st(d::READ_ONLY),
                proto_fs::READ_ONLY_FILESYSTEM,
                true,
            ),
            ("fsync", st(d::IO), proto_layer::IO, true),
            ("chown", st(d::IO), proto_layer::IO, true),
            ("chmod", st(d::IO), proto_layer::IO, true),
            ("utimens", st(d::NO_SPACE), proto_fs::NO_SPACE, true),
        ] {
            let (mut v, mut l) = world();
            l.file("/etc/f", 61).bytes("/etc/f", &bytes(70_000, 4));
            let mut t = Table::new();
            let o = order(&mut t, &l, "/etc/f", Kind::Whole);
            let mut b = FakeBulk::new(&mut v, &mut l);
            b.fail = Some((call, status));
            let mut c = Copier::new();
            c.add(o);
            let (ends, _) = run(&mut c, &mut b, 1);
            assert_eq!((ends[0].code, ends[0].made), (code, made), "{call}");
            assert_eq!(b.open_fds(), 0, "{call}");
            assert_eq!(c.busy(), 0);
        }
    }

    #[test]
    fn a_write_that_stops_short_is_no_space() {
        let (mut v, mut l) = world();
        l.file("/etc/f", 71).bytes("/etc/f", &bytes(70_000, 4));
        let mut t = Table::new();
        let o = order(&mut t, &l, "/etc/f", Kind::Whole);
        let mut b = FakeBulk::new(&mut v, &mut l);
        b.short = Some(100);
        let mut c = Copier::new();
        c.add(o);
        let (ends, _) = run(&mut c, &mut b, 1);
        assert_eq!((ends[0].code, ends[0].made), (proto_fs::NO_SPACE, true));
        assert_eq!(b.open_fds(), 0);
    }

    #[test]
    fn the_copier_holds_four_copies_and_gives_the_fifth_back() {
        let (mut v, mut l) = world();
        let mut c = Copier::new();
        let mut orders = std::vec::Vec::new();
        for k in 0..ACTIVE + 1 {
            let p = std::format!("/etc/f{k}");
            l.file(&p, 100 + k as u64).bytes(&p, &bytes(10, k as u8));
            // A table of its own for each: the copier takes any order it is given.
            orders.push(order(&mut Table::new(), &l, &p, Kind::Whole));
        }
        for o in &orders[..ACTIVE] {
            assert!(c.add(*o));
        }
        assert_eq!(c.busy(), ACTIVE);
        assert!(!c.add(orders[ACTIVE]));
        let mut b = FakeBulk::new(&mut v, &mut l);
        let mut seen = 0;
        while seen < ACTIVE {
            seen += usize::from(c.turn(&mut b).is_some());
        }
        assert!(c.add(orders[ACTIVE]));
    }
}
