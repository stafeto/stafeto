// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Numbered inode FIFO, retained notifications and portioned PID reachability.
//! Receipts retain the exact source, inode pin and expenditure root independently.

use super::{
    Kind, Lock, Owner,
    request::{Captured, reply},
    simple::{Command, Error, Request, SimpleLocks},
    wait_receipts::{Id, PLACES, Phase, Queue, SHARE},
};
use crate::storage::{self, Storage, Token};
use proto_fs::{WaitPhase, WaitReply};

// A service BSS window bounds registrations independently of paid receipt custody.
// Exhaustion reports ENOLCK; each inode separately admits 64 numbered waiters.
const CAPACITY: usize = 256;
const NONE: u16 = u16::MAX;
const CHAIN: usize = 16;

struct Registration<H> {
    id: Id,
    captured: Captured,
    number: u64,
    next: u16,
    linked: bool,
    checking: bool,
    waited: bool,
    checked: bool,
    invalidated: bool,
    dirty: bool,
    handle: Option<H>,
}
#[derive(Clone, Copy)]
struct Vertex {
    pid: u32,
    depth: u8,
    parent: u16,
    edge: Option<Edge>,
}
impl Vertex {
    const EMPTY: Self = Self {
        pid: 0,
        depth: 0,
        parent: NONE,
        edge: None,
    };
}
#[derive(Clone, Copy)]
struct Edge {
    number: u64,
    revision: u64,
    blocker: u32,
    waiter: u16,
}

struct Check {
    target: Id,
    origin: u32,
    vertices: [Vertex; CAPACITY],
    len: usize,
    vertex: usize,
    registration: usize,
    blockers: [Option<u32>; 64],
    blocker: usize,
    blockers_len: usize,
    edge: Option<Edge>,
    path: [Option<Edge>; CHAIN],
    path_len: usize,
    validation: usize,
    candidate: Option<Edge>,
    candidate_cursor: usize,
}
impl Check {
    /// # Safety
    /// Destination is exclusive aligned uninitialized Check storage.
    unsafe fn initialize_at(destination: *mut Self) {
        unsafe {
            let vertices = core::ptr::addr_of_mut!((*destination).vertices).cast::<Vertex>();
            for i in 0..CAPACITY {
                vertices.add(i).write(Vertex::EMPTY);
            }
            let blockers = core::ptr::addr_of_mut!((*destination).blockers).cast::<Option<u32>>();
            for i in 0..64 {
                blockers.add(i).write(None);
            }
            let path = core::ptr::addr_of_mut!((*destination).path).cast::<Option<Edge>>();
            for i in 0..CHAIN {
                path.add(i).write(None);
            }
            core::ptr::addr_of_mut!((*destination).target).write(
                Id::new(
                    0,
                    1,
                    proto_fs::WaitKey {
                        slot: 0,
                        generation: 1,
                    },
                )
                .unwrap(),
            );
            core::ptr::addr_of_mut!((*destination).origin).write(0);
            core::ptr::addr_of_mut!((*destination).len).write(0);
            core::ptr::addr_of_mut!((*destination).vertex).write(0);
            core::ptr::addr_of_mut!((*destination).registration).write(0);
            core::ptr::addr_of_mut!((*destination).blocker).write(0);
            core::ptr::addr_of_mut!((*destination).blockers_len).write(0);
            core::ptr::addr_of_mut!((*destination).edge).write(None);
            core::ptr::addr_of_mut!((*destination).path_len).write(0);
            core::ptr::addr_of_mut!((*destination).validation).write(0);
            core::ptr::addr_of_mut!((*destination).candidate).write(None);
            core::ptr::addr_of_mut!((*destination).candidate_cursor).write(0);
        }
    }
    fn start(&mut self, target: Id, pid: u32) {
        self.target = target;
        self.origin = pid;
        self.vertices[0] = Vertex::EMPTY;
        self.len = 1;
        self.vertex = 0;
        self.registration = 0;
        self.blocker = 0;
        self.blockers_len = 0;
        self.edge = None;
        self.path_len = 0;
        self.validation = 0;
        self.candidate = None;
        self.candidate_cursor = 0;
    }
}

pub struct Waits<H> {
    registrations: [Option<Registration<H>>; CAPACITY],
    receipt: [u16; PLACES],
    heads: [u16; storage::NODES],
    free: [u64; CAPACITY / 64],
    pid_waiters: [u16; CAPACITY],
    pid_owner: [u32; CAPACITY],
    number: u64,
    count: usize,
    cursor: usize,
    remaining: usize,
    check: Check,
    active: bool,
    graph_turn: bool,
}
impl<H> Waits<H> {
    /// # Safety
    /// The destination exclusively owns aligned uninitialized writable storage.
    pub unsafe fn initialize_at(destination: *mut Self) {
        unsafe {
            let registrations = core::ptr::addr_of_mut!((*destination).registrations)
                .cast::<Option<Registration<H>>>();
            for i in 0..CAPACITY {
                registrations.add(i).write(None);
            }
            let receipt = core::ptr::addr_of_mut!((*destination).receipt).cast::<u16>();
            for i in 0..PLACES {
                receipt.add(i).write(NONE);
            }
            let heads = core::ptr::addr_of_mut!((*destination).heads).cast::<u16>();
            for i in 0..storage::NODES {
                heads.add(i).write(NONE);
            }
            core::ptr::addr_of_mut!((*destination).pid_waiters).write([0; CAPACITY]);
            core::ptr::addr_of_mut!((*destination).pid_owner).write([0; CAPACITY]);
            core::ptr::addr_of_mut!((*destination).free).write([u64::MAX; CAPACITY / 64]);
            core::ptr::addr_of_mut!((*destination).number).write(0);
            core::ptr::addr_of_mut!((*destination).count).write(0);
            core::ptr::addr_of_mut!((*destination).cursor).write(0);
            core::ptr::addr_of_mut!((*destination).remaining).write(0);
            Check::initialize_at(core::ptr::addr_of_mut!((*destination).check));
            core::ptr::addr_of_mut!((*destination).active).write(false);
            core::ptr::addr_of_mut!((*destination).graph_turn).write(true);
        }
    }
    /// Read-only test observer. A probe cannot alter custody or grant a lock.
    #[cfg(feature = "lifetime-probe")]
    pub fn inspect(
        &self,
        first: usize,
        limit: usize,
        mut visit: impl FnMut(usize, Id, Captured, bool),
    ) -> usize {
        let end = first.saturating_add(limit.min(8)).min(CAPACITY);
        for slot in first.min(CAPACITY)..end {
            if let Some(r) = self.registrations[slot].as_ref() {
                visit(slot, r.id, r.captured, r.linked);
            }
        }
        end.saturating_sub(first)
    }
    #[cfg(test)]
    fn check_ref(&self) -> Option<&Check> {
        self.active.then_some(&self.check)
    }
    #[cfg(test)]
    fn check_mut(&mut self) -> Option<&mut Check> {
        if self.active {
            Some(&mut self.check)
        } else {
            None
        }
    }
    pub fn count(&self) -> usize {
        self.count
    }
    pub fn pending(&self) -> bool {
        self.count != 0
    }
    /// Retained custody keeps the timer alive, but never an endless own notice.
    pub fn needs_work(&self) -> bool {
        self.active || self.remaining != 0
    }
    fn schedule(&mut self) {
        self.remaining = if self.count == 0 { 0 } else { CAPACITY };
    }
    /// Schedule one finite bounded sweep; polling itself visits no registrations.
    pub fn poll(&mut self) {
        // A timer cannot replenish an in-flight sweep forever. Changed custody
        // and graph completion separately schedule a fresh notification sweep.
        if self.remaining == 0 {
            self.schedule();
        }
    }
    fn slot(&self, id: Id) -> Result<usize, u32> {
        let slot = self.receipt[id.slot() as usize];
        if slot == NONE
            || self.registrations[slot as usize]
                .as_ref()
                .is_none_or(|r| r.id != id)
        {
            return Err(proto_fs::OPEN_RETIRED);
        }
        Ok(slot as usize)
    }
    pub fn register(&mut self, queue: &mut Queue, id: Id) -> Result<(), u32> {
        if self.slot(id).is_ok() {
            return Ok(());
        }
        let (captured, phase, _) = queue.snapshot(id)?;
        if phase == Phase::Complete {
            return Ok(());
        }
        let inode = captured.request.inode;
        let mut at = self.heads[inode.slot as usize];
        let mut count = 0;
        let mut tail = NONE;
        while at != NONE {
            let registration = self.registrations[at as usize].as_ref().unwrap();
            if registration.captured.request.inode != inode {
                return Err(proto_fs::INVALID_ARGUMENT);
            }
            count += 1;
            tail = at;
            at = registration.next;
        }
        if count == 64 {
            return Err(proto_fs::NO_LOCKS);
        }
        let word = self
            .free
            .iter()
            .position(|word| *word != 0)
            .ok_or(proto_fs::NO_LOCKS)?;
        let bit = self.free[word].trailing_zeros() as usize;
        let slot = word * 64 + bit;
        let number = self.number.checked_add(1).ok_or(proto_fs::NO_LOCKS)?;
        self.number = number;
        self.free[word] &= !(1u64 << bit);
        self.registrations[slot] = Some(Registration {
            id,
            captured,
            number,
            next: NONE,
            linked: true,
            checking: false,
            waited: false,
            checked: false,
            invalidated: true,
            dirty: false,
            handle: None,
        });
        self.receipt[id.slot() as usize] = slot as u16;
        if tail == NONE {
            self.heads[inode.slot as usize] = slot as u16;
        } else {
            self.registrations[tail as usize].as_mut().unwrap().next = slot as u16;
        }
        self.count += 1;
        self.schedule();
        if let Owner::Process(pid) = captured.request.owner {
            let bucket = pid as usize % CAPACITY;
            if self.pid_waiters[bucket] == 0 {
                self.pid_owner[bucket] = pid;
            } else if self.pid_owner[bucket] != pid {
                self.pid_owner[bucket] = 0;
            }
            self.pid_waiters[bucket] += 1;
        }
        Ok(())
    }
    fn unlink(&mut self, slot: usize) {
        let r = self.registrations[slot].as_ref().unwrap();
        if !r.linked {
            return;
        }
        let inode = r.captured.request.inode;
        let next = r.next;
        let owner = r.captured.request.owner;
        let mut at = self.heads[inode.slot as usize];
        let mut previous = NONE;
        while at != slot as u16 {
            assert_ne!(at, NONE);
            previous = at;
            at = self.registrations[at as usize].as_ref().unwrap().next;
        }
        if previous == NONE {
            self.heads[inode.slot as usize] = next;
        } else {
            self.registrations[previous as usize].as_mut().unwrap().next = next;
        }
        let r = self.registrations[slot].as_mut().unwrap();
        r.linked = false;
        if let Owner::Process(pid) = owner {
            self.pid_waiters[pid as usize % CAPACITY] -= 1;
        }
        r.checking = false;
        self.changed(inode);
    }
    pub fn release_registration(&mut self, id: Id) {
        let Ok(slot) = self.slot(id) else {
            return;
        };
        self.unlink(slot);
        self.registrations[slot] = None;
        self.receipt[id.slot() as usize] = NONE;
        self.free[slot / 64] |= 1u64 << (slot % 64);
        self.count -= 1;
        if self.active && self.check.target == id {
            self.active = false;
            self.schedule();
        }
    }
    pub fn changed(&mut self, inode: Token) {
        self.schedule();
        let mut at = self.heads[inode.slot as usize];
        while at != NONE {
            let r = self.registrations[at as usize].as_mut().unwrap();
            if r.captured.request.inode == inode {
                r.dirty = true;
                r.invalidated = true;
            }
            at = r.next;
        }
    }
    #[inline(always)]
    fn incompatible(a: &Request, b: &Request) -> bool {
        matches!((a.command, b.command), (Command::Set(Some(ak)), Command::Set(Some(bk)))
            if a.owner != b.owner && (ak == Kind::Write || bk == Kind::Write) && a.range.overlaps(b.range))
    }
    pub fn older_conflict(
        &self,
        request: Request,
        id: Option<Id>,
        mut live: impl FnMut(Owner) -> bool,
    ) -> Option<Lock> {
        let number = id
            .and_then(|id| self.slot(id).ok())
            .map_or(u64::MAX, |slot| {
                self.registrations[slot].as_ref().unwrap().number
            });
        let mut at = self.heads[request.inode.slot as usize];
        while at != NONE {
            let r = self.registrations[at as usize].as_ref().unwrap();
            if r.number >= number {
                break;
            }
            let older = &r.captured.request;
            if older.inode == request.inode
                && Self::incompatible(older, &request)
                && live(older.owner)
            {
                let Command::Set(Some(kind)) = older.command else {
                    unreachable!()
                };
                return Some(Lock {
                    owner: older.owner,
                    kind,
                    range: older.range,
                });
            }
            at = r.next;
        }
        None
    }
    fn finish(&mut self, queue: &mut Queue, id: Id, result: u32) -> Result<WaitReply, u32> {
        let saved = WaitReply {
            phase: WaitPhase::Complete,
            result,
        };
        queue.complete(id, saved)?;
        if let Ok(slot) = self.slot(id) {
            self.unlink(slot);
            self.registrations[slot].as_mut().unwrap().dirty = true;
        }
        if self.active && self.check.target == id {
            self.active = false;
            self.schedule();
        }
        queue.query(id)
    }
    #[inline(never)]
    pub fn query(
        &mut self,
        queue: &mut Queue,
        locks: &mut SimpleLocks,
        storage: &mut Storage<'_>,
        id: Id,
        source_live: bool,
        mut live: impl FnMut(Owner) -> bool,
    ) -> Result<WaitReply, u32> {
        let (captured, phase, cancelled) = queue.snapshot(id)?;
        if phase == Phase::Complete {
            return queue.query(id);
        }
        if !source_live {
            return self.finish(queue, id, proto_fs::BAD_FD);
        }
        if cancelled || !live(captured.request.owner) {
            return self.finish(queue, id, proto_fs::LOCK_CANCELLED);
        }
        self.register(queue, id)?;
        let slot = self.slot(id)?;
        let request = captured.request;
        let held = match locks.query_details(storage, request, &mut live) {
            Ok(held) => held,
            Err(error) => return self.finish(queue, id, reply(Err(error)).result),
        };
        let older = self.registrations[slot].as_ref().unwrap().waited
            && !held.owns_overlap
            && self.older_conflict(request, Some(id), &mut live).is_some();
        let blocked = held.blocker.is_some() || older;
        if held.blocker.is_some() {
            self.registrations[slot].as_mut().unwrap().waited = true;
        }
        if !blocked {
            match locks.set(storage, captured.root, request, &mut live) {
                Ok(()) => {
                    self.changed(request.inode);
                    return self.finish(queue, id, 0);
                }
                Err(Error::Conflict(_)) => {}
                Err(error) => return self.finish(queue, id, reply(Err(error)).result),
            }
        }
        if phase != Phase::Sleeping {
            queue.sleep(id, false)?;
        }
        let r = self.registrations[slot].as_mut().unwrap();
        if matches!(request.owner, Owner::Process(_)) && r.invalidated {
            r.checked = false;
        }
        if matches!(request.owner, Owner::Process(_)) && !r.checking && !r.checked {
            r.checking = true;
            r.invalidated = false;
            if !self.active {
                let Owner::Process(pid) = request.owner else {
                    unreachable!()
                };
                self.check.start(id, pid);
                self.active = true;
            }
        }
        r.dirty = false;
        if r.checking {
            return Ok(WaitReply {
                phase: WaitPhase::Queued,
                result: 0,
            });
        }
        queue.query(id)
    }
    pub fn arm(&mut self, queue: &mut Queue, id: Id, handle: H) -> Result<WaitReply, u32> {
        if queue.query(id)?.phase == WaitPhase::Complete {
            return queue.query(id);
        }
        let slot = self.slot(id)?;
        let r = self.registrations[slot].as_mut().unwrap();
        if r.handle.is_none() {
            r.handle = Some(handle);
        }
        queue.arm_registration(id)?;
        let checking = r.checking;
        self.schedule();
        if checking {
            Ok(WaitReply {
                phase: WaitPhase::Queued,
                result: 0,
            })
        } else {
            queue.query(id)
        }
    }
    pub fn cancel(&mut self, queue: &mut Queue, id: Id) -> Result<WaitReply, u32> {
        if queue.query(id)?.phase == WaitPhase::Complete {
            return queue.query(id);
        }
        self.finish(queue, id, proto_fs::LOCK_CANCELLED)
    }
    pub fn departure(
        &mut self,
        queue: &mut Queue,
        storage: &mut Storage<'_>,
        place: usize,
        owner: u64,
        offset: usize,
        limit: usize,
    ) -> usize {
        let end = offset.saturating_add(limit).min(SHARE);
        for key in offset..end {
            if let Ok(Some(id)) = queue.occupied(place, owner, key as u32) {
                let _ = self.cancel(queue, id);
                self.release_registration(id);
                let _ = queue.release(id, storage);
            }
        }
        end
    }
    /// Alternate one graph portion with one receipt inspection. Each turn reads
    /// at most one inode lock snapshot. Notification is only a hint;
    /// a later authenticated Query alone may publish SET and terminal success.
    #[inline(never)]
    pub fn maintenance(
        &mut self,
        queue: &mut Queue,
        locks: &mut SimpleLocks,
        storage: &mut Storage<'_>,
        mut source_live: impl FnMut(Captured, u64) -> bool,
        mut live: impl FnMut(Owner) -> bool,
        mut notify: impl FnMut(&H),
    ) -> usize {
        if self.active && self.graph_turn {
            self.graph_turn = false;
            self.advance(queue, locks, storage, &mut source_live, &mut live);
            return 1;
        }
        self.graph_turn = true;
        if self.remaining == 0 {
            return 0;
        }
        self.remaining -= 1;
        let slot = self.cursor;
        self.cursor = (self.cursor + 1) % CAPACITY;
        if let Some(r) = self.registrations[slot].as_ref() {
            let id = r.id;
            let captured = r.captured;
            if r.linked
                && r.handle.is_some()
                && locks
                    .query_details(storage, captured.request, &mut live)
                    .is_ok_and(|held| {
                        held.blocker.is_none()
                            && (!r.waited
                                || held.owns_overlap
                                || self
                                    .older_conflict(captured.request, Some(id), &mut live)
                                    .is_none())
                    })
            {
                self.registrations[slot].as_mut().unwrap().dirty = true;
            }
            if queue
                .snapshot(id)
                .is_ok_and(|(_, phase, _)| phase != Phase::Complete)
                && !source_live(captured, id.owner())
            {
                let _ = self.finish(queue, id, proto_fs::BAD_FD);
            } else if queue
                .query(id)
                .is_ok_and(|reply| reply.phase != WaitPhase::Complete)
                && !live(captured.request.owner)
            {
                let _ = self.finish(queue, id, proto_fs::LOCK_CANCELLED);
            }
            let r = self.registrations[slot].as_mut().unwrap();
            if r.checking
                && !self.active
                && let Owner::Process(pid) = r.captured.request.owner
            {
                self.check.start(id, pid);
                self.active = true;
            }
            if r.dirty
                && let Some(handle) = r.handle.as_ref()
            {
                notify(handle);
                r.dirty = false;
            }
        }
        1
    }
    #[inline(never)]
    fn advance(
        &mut self,
        queue: &mut Queue,
        locks: &SimpleLocks,
        storage: &Storage<'_>,
        source_live: &mut impl FnMut(Captured, u64) -> bool,
        live: &mut impl FnMut(Owner) -> bool,
    ) {
        if self.slot(self.check.target).is_err()
            || queue
                .query(self.check.target)
                .is_ok_and(|r| r.phase == WaitPhase::Complete)
        {
            self.active = false;
            self.schedule();
            return;
        }
        if let Some(edge) = self.check.candidate {
            for _ in 0..8 {
                if self.check.candidate_cursor == CAPACITY {
                    self.check.candidate = None;
                    break;
                }
                let slot = self.check.candidate_cursor;
                self.check.candidate_cursor += 1;
                if self.registrations[slot].as_ref().is_some_and(|r| {
                    r.linked && r.captured.request.owner == Owner::Process(edge.blocker)
                }) {
                    self.check.candidate = None;
                    if !self.add_vertex(edge, queue) {
                        return;
                    }
                    break;
                }
            }
            return;
        }
        if self.check.path_len != 0 {
            if self.check.validation < self.check.path_len {
                let edge = self.check.path[self.check.validation].unwrap();
                let valid = self.edge_registration(edge).is_some_and(|r| {
                    let request = r.captured.request;
                    queue
                        .snapshot(r.id)
                        .is_ok_and(|(_, phase, _)| phase != Phase::Complete)
                        && source_live(r.captured, r.id.owner())
                        && locks
                            .conflicts(storage, request, &mut *live)
                            .is_ok_and(|conflicts| {
                                conflicts
                                    .iter()
                                    .any(|lock| lock.owner == Owner::Process(edge.blocker))
                            })
                });
                if !valid {
                    self.restart(self.check.target);
                    return;
                }
                let inode = self.edge_registration(edge).unwrap().captured.request.inode;
                self.check.path[self.check.validation]
                    .as_mut()
                    .unwrap()
                    .revision = locks.revision(inode);
                self.check.validation += 1;
            } else {
                if self.check.path[..self.check.path_len]
                    .iter()
                    .flatten()
                    .all(|edge| {
                        self.edge_registration(*edge).is_some_and(|r| {
                            locks.revision(r.captured.request.inode) == edge.revision
                                && source_live(r.captured, r.id.owner())
                        }) && live(Owner::Process(edge.blocker))
                    })
                {
                    let _ = self.finish(queue, self.check.target, proto_fs::LOCK_DEADLOCK);
                } else {
                    self.restart(self.check.target);
                }
                return;
            }
            return;
        }
        if self.check.blocker < self.check.blockers_len {
            let pid = self.check.blockers[self.check.blocker].unwrap();
            self.check.blocker += 1;
            if !live(Owner::Process(pid)) {
                return;
            }
            let mut edge = self.check.edge.unwrap();
            edge.blocker = pid;
            if pid == self.check.origin {
                self.check.path[0] = Some(edge);
                self.check.path_len = 1;
                let mut vertex = self.check.vertex;
                while self.check.vertices[vertex].parent != NONE {
                    if self.check.path_len == CHAIN {
                        self.check.path_len = 0;
                        break;
                    }
                    self.check.path[self.check.path_len] = self.check.vertices[vertex].edge;
                    self.check.path_len += 1;
                    vertex = self.check.vertices[vertex].parent as usize;
                }
            } else if !self.check.vertices[..self.check.len]
                .iter()
                .any(|v| v.pid == pid)
            {
                let bucket = pid as usize % CAPACITY;
                if self.pid_waiters[bucket] != 0 && self.pid_owner[bucket] == pid {
                    if !self.add_vertex(edge, queue) {
                        return;
                    }
                } else if self.pid_waiters[bucket] != 0 && self.pid_owner[bucket] == 0 {
                    // A recycled slot with both generations needs an exact portioned lookup.
                    self.check.candidate = Some(edge);
                    self.check.candidate_cursor = 0;
                }
            }
            return;
        }
        self.check.blocker = 0;
        self.check.blockers_len = 0;
        if self.check.vertex >= self.check.len {
            if let Ok(slot) = self.slot(self.check.target) {
                let r = self.registrations[slot].as_mut().unwrap();
                r.checking = false;
                r.checked = !r.invalidated;
                r.dirty = true;
            }
            self.active = false;
            self.schedule();
            return;
        }
        let pid = if self.check.vertex == 0 {
            self.check.origin
        } else {
            self.check.vertices[self.check.vertex].pid
        };
        for _ in 0..8 {
            if self.check.registration == CAPACITY {
                self.check.registration = 0;
                self.check.vertex += 1;
                break;
            }
            let slot = self.check.registration;
            self.check.registration += 1;
            let Some(r) = self.registrations[slot].as_ref() else {
                continue;
            };
            if !r.linked || r.captured.request.owner != Owner::Process(pid) {
                continue;
            }
            if self.check.vertex == 0 && r.id != self.check.target {
                continue;
            }
            let request = r.captured.request;
            if !source_live(r.captured, r.id.owner()) {
                continue;
            }
            if let Ok(conflicts) = locks.conflicts(storage, request, &mut *live) {
                for lock in conflicts.iter() {
                    if let Owner::Process(blocker) = lock.owner {
                        self.check.blockers[self.check.blockers_len] = Some(blocker);
                        self.check.blockers_len += 1;
                    }
                }
            }
            self.check.edge = Some(Edge {
                waiter: slot as u16,
                number: r.number,
                blocker: 0,
                revision: locks.revision(request.inode),
            });
            break;
        }
    }
    fn edge_registration(&self, edge: Edge) -> Option<&Registration<H>> {
        self.registrations[edge.waiter as usize]
            .as_ref()
            .filter(|r| r.linked && r.number == edge.number)
    }
    fn add_vertex(&mut self, edge: Edge, queue: &mut Queue) -> bool {
        if self.check.vertices[self.check.vertex].depth as usize + 1 >= CHAIN {
            return true;
        }
        if self.check.len == CAPACITY {
            let _ = self.finish(queue, self.check.target, proto_fs::NO_LOCKS);
            return false;
        }
        self.check.vertices[self.check.len] = Vertex {
            pid: edge.blocker,
            depth: self.check.vertices[self.check.vertex].depth + 1,
            parent: self.check.vertex as u16,
            edge: Some(edge),
        };
        self.check.len += 1;
        true
    }
    fn restart(&mut self, id: Id) {
        if let Ok(slot) = self.slot(id) {
            let r = self.registrations[slot].as_mut().unwrap();
            r.checking = true;
            r.checked = false;
            r.invalidated = false;
            // Yield the single checker after invalidation. The receipt cursor
            // selects the next pending check, so one changing inode cannot own it.
            self.active = false;
            self.schedule();
        }
    }
}

#[cfg(test)]
#[path = "simple_wait_tests.rs"]
mod tests;
