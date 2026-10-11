// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A single service-driven worker owns scans, preparation and paid cleanup.

#[path = "reader.rs"]
mod reader;
pub use reader::{ReadProgress, ReadSnapshot, ReadState, Reader};

use super::{Kind, Lock, Owner, Range, budget, groups, preparation, records};
use crate::storage::Token;
use groups::{Capture, Groups, Id};
use preparation::{Prepare, Retirement};
use records::{Pool, Reclaim};
const NONE: u16 = u16::MAX;
const RECORDS: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    NoLocks,
    Busy,
    Cancelled,
    Conflict(Lock),
}
impl From<groups::Error> for Error {
    fn from(error: groups::Error) -> Self {
        match error {
            groups::Error::Invalid => Self::Invalid,
            groups::Error::NoLocks => Self::NoLocks,
        }
    }
}
impl From<preparation::Error> for Error {
    fn from(error: preparation::Error) -> Self {
        match error {
            preparation::Error::Invalid => Self::Invalid,
            preparation::Error::NoLocks => Self::NoLocks,
            preparation::Error::Busy => Self::Busy,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Get(Kind),
    Set(Option<Kind>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub inode: Token,
    pub owner: Owner,
    pub root: u16,
    pub range: Range,
    pub command: Command,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Response {
    Blocker(Option<Lock>),
    Changed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupEvent {
    Created { id: Id, root: u16 },
    Released { id: Id, root: u16 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub visited: usize,
    pub group_event: Option<GroupEvent>,
    pub completed: Option<Result<Response, Error>>,
}
impl Progress {
    fn with_event(mut self, event: Option<GroupEvent>) -> Self {
        self.group_event = event;
        self
    }
    fn pending(visited: usize) -> Self {
        Self {
            visited,
            group_event: None,
            completed: None,
        }
    }
    fn complete(visited: usize, result: Result<Response, Error>) -> Self {
        Self {
            visited,
            group_event: None,
            completed: Some(result),
        }
    }
}
#[derive(Clone, Copy)]
struct View {
    id: Option<Id>,
    head: Option<records::Id>,
    count: usize,
    revoked: bool,
    next: Option<Id>,
}
impl View {
    const EMPTY: Self = Self {
        id: None,
        head: None,
        count: 0,
        revoked: false,
        next: None,
    };
}
struct Cleanup {
    root: u16,
    expected: usize,
    released: usize,
    cursor: Reclaim,
}
impl Cleanup {
    fn new(retirement: Retirement) -> Self {
        Self {
            root: retirement.root,
            expected: retirement.count,
            released: 0,
            cursor: Reclaim::new(retirement.head),
        }
    }
}
struct Departure {
    cursor: groups::Departure,
    next: u16,
}
struct Scan {
    group: Option<Id>,
    entered: bool,
    next: Option<Id>,
    record: Option<records::Id>,
    blocker: Option<Lock>,
}
// One fixed worker resides in the permanent actor allocation.
#[allow(clippy::large_enum_variant)]
enum Phase {
    Scan(Scan),
    Admit,
    Prepare { capture: Capture, work: Prepare },
}
struct Worker {
    request: Request,
    cancelled: bool,
    phase: Phase,
}

pub struct Actor<
    const G: usize,
    const I: usize,
    const P: usize,
    const D: usize,
    const R: usize,
    const S: usize,
> {
    groups: Groups<G, I, P, D, R, S>,
    pool: Pool<RECORDS, R, 256>,
    budget: budget::Budget<R>,
    views: [View; G],
    worker: Option<Worker>,
    previous: Option<Cleanup>,
    revoked: Option<Id>,
    empty: Option<Capture>,
    group_cleanup: Option<Cleanup>,
    departures: [Option<Departure>; P],
    departure_head: u16,
    departure_tail: u16,
}
impl<const G: usize, const I: usize, const P: usize, const D: usize, const R: usize, const S: usize>
    Actor<G, I, P, D, R, S>
{
    /// Initialize tables in their permanent allocation without large stack copies.
    ///
    /// # Safety
    /// The destination is exclusive aligned writable uninitialized Self storage.
    pub unsafe fn initialize_at(destination: *mut Self) {
        // SAFETY: every field lies in the complete exclusive destination.
        unsafe {
            Groups::initialize_at(core::ptr::addr_of_mut!((*destination).groups));
            Pool::initialize_at(core::ptr::addr_of_mut!((*destination).pool));
            core::ptr::addr_of_mut!((*destination).budget).write(budget::Budget::new());
            let views = core::ptr::addr_of_mut!((*destination).views).cast::<View>();
            for index in 0..G {
                views.add(index).write(View::EMPTY);
            }
            let departures =
                core::ptr::addr_of_mut!((*destination).departures).cast::<Option<Departure>>();
            for index in 0..P {
                departures.add(index).write(None);
            }
            core::ptr::addr_of_mut!((*destination).worker).write(None);
            core::ptr::addr_of_mut!((*destination).previous).write(None);
            core::ptr::addr_of_mut!((*destination).revoked).write(None);
            core::ptr::addr_of_mut!((*destination).empty).write(None);
            core::ptr::addr_of_mut!((*destination).group_cleanup).write(None);
            core::ptr::addr_of_mut!((*destination).departure_head).write(NONE);
            core::ptr::addr_of_mut!((*destination).departure_tail).write(NONE);
        }
    }
    fn view(&self, id: Id) -> Result<View, Error> {
        self.views
            .get(id.slot())
            .copied()
            .filter(|view| view.id == Some(id))
            .ok_or(Error::Invalid)
    }
    fn debt(&self) -> bool {
        self.previous.is_some()
            || self.revoked.is_some()
            || self.empty.is_some()
            || self.departure_head != NONE
    }
    pub fn busy(&self) -> bool {
        self.worker.is_some() || self.debt()
    }
    pub fn counts(&self) -> budget::Counts {
        self.budget.totals()
    }
    pub fn record_charge(&self, root: u16) -> Option<usize> {
        self.pool.used(root)
    }
    pub fn group_charge(&self, root: u16) -> Option<usize> {
        self.groups.used(root)
    }
    /// Read-only admission key validation precedes any new expenditure account.
    pub fn validate_request(&self, request: Request) -> Result<(), Error> {
        self.groups.lookup(request.inode, request.owner)?;
        self.budget.root(request.root).ok_or(Error::Invalid)?;
        Ok(())
    }
    /// Busy is internal admission; the service keeps the paid request waiting.
    pub fn start(&mut self, request: Request) -> Result<(), Error> {
        if self.busy() {
            return Err(Error::Busy);
        }
        self.validate_request(request)?;
        let phase = if request.command == Command::Set(None) {
            Phase::Admit
        } else {
            Phase::Scan(Scan {
                group: self.groups.inode_head(request.inode)?,
                entered: false,
                next: None,
                record: None,
                blocker: None,
            })
        };
        self.worker = Some(Worker {
            request,
            cancelled: false,
            phase,
        });
        Ok(())
    }
    pub fn cancel(&mut self) -> bool {
        if let Some(worker) = &mut self.worker {
            worker.cancelled = true;
            true
        } else {
            false
        }
    }
    /// Numeric close reaches this event independently of physical I/O references.
    pub fn close(&mut self, inode: Token, owner: Owner) -> Result<(), Error> {
        let capture = self.groups.lookup(inode, owner)?;
        if let Some(worker) = &mut self.worker
            && worker.request.inode == inode
            && worker.request.owner == owner
        {
            worker.cancelled = true;
        }
        if let Some(capture) = capture {
            let snapshot = self.groups.revoke(capture)?;
            self.retire_view(capture.id(), snapshot.root)?;
        }
        Ok(())
    }
    fn retire_view(&mut self, id: Id, root: u16) -> Result<(), Error> {
        let view = self.view(id)?;
        if view.revoked {
            return Err(Error::Invalid);
        }
        self.budget
            .retire(root, view.count)
            .expect("paid published head");
        if let Some(worker) = &mut self.worker
            && let Phase::Scan(scan) = &mut worker.phase
            && scan.group == Some(id)
            && scan.entered
        {
            scan.record = None;
        }
        let view = &mut self.views[id.slot()];
        view.revoked = true;
        view.next = self.revoked;
        self.revoked = Some(id);
        Ok(())
    }
    /// The adapter confirms PID death against the process lifetime page first.
    pub fn depart_pid(&mut self, pid: u32) -> Result<(), Error> {
        let cursor = self.groups.depart_pid(pid)?;
        if let Some(worker) = &mut self.worker
            && worker.request.owner == Owner::Process(pid)
        {
            worker.cancelled = true;
        }
        if let Some(worker) = &mut self.worker
            && let Phase::Scan(scan) = &mut worker.phase
            && let Some(id) = scan.group
            && scan.entered
            && self.groups.capture(id)?.is_none()
        {
            scan.record = None;
        }
        if cursor.done() {
            return Ok(());
        }
        let index = (pid % 256) as usize;
        assert!(
            self.departures[index].is_none(),
            "one unpaid publication barrier per PID place"
        );
        self.departures[index] = Some(Departure { cursor, next: NONE });
        if self.departure_tail == NONE {
            self.departure_head = index as u16;
        } else {
            self.departures[self.departure_tail as usize]
                .as_mut()
                .expect("departure tail")
                .next = index as u16;
        }
        self.departure_tail = index as u16;
        Ok(())
    }
    fn retire_private(&mut self, retirement: Retirement) {
        assert!(self.previous.is_none(), "exclusive preparation cleanup");
        self.previous = Some(Cleanup::new(retirement));
    }
    fn defer_empty(&mut self, capture: Capture) {
        let view = self.view(capture.id()).expect("retained candidate view");
        if !view.revoked && view.count == 0 {
            assert!(self.empty.is_none(), "exclusive empty candidate");
            self.empty = Some(capture);
        }
    }

    fn cleanup_step(&mut self) -> Progress {
        if let Some(cleanup) = &mut self.previous {
            let progress = cleanup
                .cursor
                .step(&mut self.pool)
                .unwrap_or_else(|failure| {
                    self.budget
                        .release_retired(cleanup.root, failure.released)
                        .expect("partial reclaim charge");
                    panic!("invalid previous lock chain: {failure:?}");
                });
            self.budget
                .release_retired(cleanup.root, progress.released)
                .expect("previous reclaim charge");
            cleanup.released += progress.released;
            if progress.complete {
                assert_eq!(cleanup.released, cleanup.expected);
                self.previous = None;
            }
            return Progress::pending(progress.released);
        }
        if let Some(capture) = self.empty.take() {
            if self.groups.valid(capture) {
                let snapshot = self.groups.revoke(capture).expect("empty candidate");
                self.retire_view(capture.id(), snapshot.root)
                    .expect("empty candidate debt");
            }
            return Progress::pending(records::PORTION);
        }
        if self.departure_head != NONE {
            let index = self.departure_head as usize;
            let departure = self.departures[index]
                .as_mut()
                .expect("paid departure head");
            let (id, snapshot) = departure
                .cursor
                .step(&mut self.groups)
                .expect("exact departed group")
                .expect("nonempty departure");
            let done = departure.cursor.done();
            let next = departure.next;
            self.retire_view(id, snapshot.root)
                .expect("departed paid view");
            if done {
                self.departures[index] = None;
                self.departure_head = next;
                if next == NONE {
                    self.departure_tail = NONE;
                }
            }
            return Progress::pending(records::PORTION);
        }
        if let Some(id) = self.revoked {
            let view = self.view(id).expect("paid revoked view");
            if self.group_cleanup.is_none() {
                let root = self.groups.capture(id).expect("paid revoked group");
                assert!(root.is_none());
                // Root provenance remains in the paid records or the retained snapshot.
                let root = self.revoked_root(id);
                self.group_cleanup = Some(Cleanup::new(Retirement {
                    root,
                    head: view.head,
                    count: view.count,
                }));
            }
            let cleanup = self.group_cleanup.as_mut().expect("group cleanup custody");
            let progress = cleanup
                .cursor
                .step_limit(&mut self.pool, 6)
                .unwrap_or_else(|failure| {
                    self.budget
                        .release_retired(cleanup.root, failure.released)
                        .expect("partial group charge");
                    panic!("invalid revoked lock chain: {failure:?}");
                });
            self.budget
                .release_retired(cleanup.root, progress.released)
                .expect("group reclaim charge");
            cleanup.released += progress.released;
            if progress.complete {
                assert_eq!(cleanup.released, cleanup.expected);
                let root = cleanup.root;
                self.group_cleanup = None;
                self.groups.release(id).expect("paid empty group");
                self.views[id.slot()] = View::EMPTY;
                self.revoked = view.next;
                return Progress::pending(progress.released + 2)
                    .with_event(Some(GroupEvent::Released { id, root }));
            }
            return Progress::pending(progress.released + 2);
        }
        Progress::pending(0)
    }
    fn revoked_root(&self, id: Id) -> u16 {
        self.groups
            .retained_snapshot(id)
            .expect("paid revoked root")
            .root
    }
    /// Audit one PID place even while no client asks for a lock.
    pub fn audit_pid(
        &mut self,
        index: usize,
        mut live: impl FnMut(u32) -> bool,
    ) -> Result<bool, Error> {
        let Some(pid) = self.groups.tracked_pid(index)? else {
            return Ok(false);
        };
        if live(pid) {
            return Ok(false);
        }
        self.depart_pid(pid)?;
        Ok(true)
    }
    /// Audit the full description generation through RAM's real fd count.
    pub fn audit_description(
        &mut self,
        index: usize,
        mut live: impl FnMut(Token) -> bool,
    ) -> Result<bool, Error> {
        let Some(snapshot) = self.groups.tracked_description(index)? else {
            return Ok(false);
        };
        let Owner::Description { slot, generation } = snapshot.owner else {
            unreachable!("OFD index");
        };
        if live(Token { slot, generation }) {
            return Ok(false);
        }
        self.close(snapshot.inode, snapshot.owner)?;
        Ok(true)
    }
    fn retire_owner(&mut self, inode: Token, owner: Owner) {
        match owner {
            Owner::Process(pid) => self.depart_pid(pid).expect("validated dead PID"),
            Owner::Description { .. } => self.close(inode, owner).expect("validated dead OFD"),
        }
    }
    fn scan_step(
        &mut self,
        request: Request,
        scan: &mut Scan,
        live: &mut impl FnMut(Owner) -> bool,
    ) -> (usize, bool) {
        let mut visited = 0;
        loop {
            if scan.entered && scan.record.is_none() {
                scan.group = scan.next;
                scan.entered = false;
            }
            let Some(id) = scan.group else {
                return (visited, true);
            };
            if visited == records::PORTION {
                return (visited, false);
            }
            if !scan.entered {
                visited += 1;
                scan.next = self.groups.inode_next(id).expect("retained scan group");
                scan.entered = true;
                if let Some(capture) = self.groups.capture(id).expect("retained exact scan group") {
                    let snapshot = self.groups.snapshot(capture).expect("live scan group");
                    if !live(snapshot.owner) {
                        self.retire_owner(snapshot.inode, snapshot.owner);
                    } else {
                        let view = self.view(id).expect("retained scan view");
                        scan.record = view.head;
                    }
                }
            } else if let Some(record) = scan.record {
                visited += 1;
                let record = self.pool.read(record).expect("retained scan record");
                scan.record = record.next;
                if !live(record.lock.owner) {
                    self.retire_owner(request.inode, record.lock.owner);
                    scan.record = None;
                    continue;
                }
                let kind = match request.command {
                    Command::Get(kind) | Command::Set(Some(kind)) => kind,
                    Command::Set(None) => unreachable!(),
                };
                if record.lock.conflicts(Lock {
                    owner: request.owner,
                    kind,
                    range: request.range,
                }) && scan
                    .blocker
                    .is_none_or(|old| record.lock.range.first() < old.range.first())
                {
                    scan.blocker = Some(record.lock);
                }
            }
        }
    }
    #[cfg(test)]
    pub fn step(&mut self) -> Progress {
        self.step_with_life(|_| true)
    }
    #[cfg(test)]
    pub fn step_with_life(&mut self, live: impl FnMut(u32) -> bool) -> Progress {
        self.step_with_owners(live, |_| true)
    }
    /// Every production slice confirms full PID and actual open-description lives.
    pub fn step_with_owners(
        &mut self,
        mut live: impl FnMut(u32) -> bool,
        mut ofd_live: impl FnMut(Token) -> bool,
    ) -> Progress {
        let Some(mut worker) = self.worker.take() else {
            return self.cleanup_step();
        };
        if let Owner::Process(pid) = worker.request.owner {
            if let Some(old) = self
                .groups
                .tracked_pid((pid % 256) as usize)
                .expect("validated PID place")
                && old != pid
                && !live(old)
            {
                self.depart_pid(old)
                    .expect("retire previous PID before admission");
            }
            if !live(pid) {
                self.depart_pid(pid).expect("validated dead worker PID");
                worker.cancelled = true;
            }
        }
        if let Owner::Description { slot, generation } = worker.request.owner {
            if let Some(old) = self
                .groups
                .tracked_description(slot as usize)
                .expect("validated OFD place")
                && old.owner != worker.request.owner
            {
                let Owner::Description { slot, generation } = old.owner else {
                    unreachable!("OFD index");
                };
                if !ofd_live(Token { slot, generation }) {
                    self.close(old.inode, old.owner)
                        .expect("retire previous OFD before admission");
                }
            }
            if !ofd_live(Token { slot, generation }) {
                self.close(worker.request.inode, worker.request.owner)
                    .expect("validated dead worker OFD");
                worker.cancelled = true;
            }
        }
        if worker.cancelled {
            if let Phase::Prepare { work, capture } = &mut worker.phase {
                let retirement = work
                    .cancel(&mut self.budget)
                    .expect("cancel private custody");
                self.retire_private(retirement);
                self.defer_empty(*capture);
            }
            return Progress::complete(1, Err(Error::Cancelled));
        }
        if matches!(worker.phase, Phase::Admit) && self.debt() {
            self.worker = Some(worker);
            return self.cleanup_step();
        }
        let progress = match &mut worker.phase {
            Phase::Scan(scan) => {
                let mut owners = |owner| match owner {
                    Owner::Process(pid) => live(pid),
                    Owner::Description { slot, generation } => ofd_live(Token { slot, generation }),
                };
                let (visited, done) = self.scan_step(worker.request, scan, &mut owners);
                if done {
                    if matches!(worker.request.command, Command::Get(_)) {
                        return Progress::complete(visited, Ok(Response::Blocker(scan.blocker)));
                    }
                    if let Some(blocker) = scan.blocker {
                        return Progress::complete(visited, Err(Error::Conflict(blocker)));
                    }
                    worker.phase = Phase::Admit;
                }
                Progress::pending(visited)
            }
            Phase::Admit => {
                let request = worker.request;
                let old = self
                    .groups
                    .lookup(request.inode, request.owner)
                    .expect("validated admission key");
                if old.is_none() && request.command == Command::Set(None) {
                    return Progress::complete(1, Ok(Response::Changed));
                }
                let capture = match old.map(Ok).unwrap_or_else(|| {
                    self.groups
                        .allocate(request.inode, request.owner, request.root)
                }) {
                    Ok(capture) => capture,
                    Err(error) => return Progress::complete(2, Err(error.into())),
                };
                if old.is_none() {
                    self.views[capture.id().slot()] = View {
                        id: Some(capture.id()),
                        ..View::EMPTY
                    };
                }
                let snapshot = self.groups.snapshot(capture).expect("admitted group");
                let event = old.is_none().then_some(GroupEvent::Created {
                    id: capture.id(),
                    root: snapshot.root,
                });
                let view = self.view(capture.id()).expect("admitted view");
                let Command::Set(kind) = request.command else {
                    unreachable!()
                };
                match Prepare::begin(
                    &mut self.budget,
                    snapshot.root,
                    request.owner,
                    view.head,
                    view.count,
                    kind,
                    request.range,
                ) {
                    Ok(work) => worker.phase = Phase::Prepare { capture, work },
                    Err(error) => {
                        if old.is_none() {
                            self.groups.revoke(capture).expect("new empty group");
                            self.retire_view(capture.id(), snapshot.root)
                                .expect("new empty debt");
                        }
                        return Progress::complete(3, Err(error.into())).with_event(event);
                    }
                }
                Progress::pending(3).with_event(event)
            }
            Phase::Prepare { capture, work } => {
                if !self.groups.valid(*capture) {
                    let retirement = work
                        .cancel(&mut self.budget)
                        .expect("revoked private custody");
                    self.retire_private(retirement);
                    self.defer_empty(*capture);
                    return Progress::complete(1, Err(Error::Cancelled));
                }
                if work.ready() {
                    if let Err(error) = self
                        .budget
                        .can_publish(self.view(capture.id()).expect("ready view").count)
                    {
                        let retirement =
                            work.cancel(&mut self.budget).expect("quota abort custody");
                        self.retire_private(retirement);
                        self.defer_empty(*capture);
                        return Progress::complete(1, Err(preparation::Error::from(error).into()));
                    }
                    let advanced = match self.groups.advance(*capture) {
                        Ok(advanced) => advanced,
                        Err(error) => {
                            let retirement =
                                work.cancel(&mut self.budget).expect("epoch abort custody");
                            self.retire_private(retirement);
                            self.defer_empty(*capture);
                            return Progress::complete(2, Err(error.into()));
                        }
                    };
                    let commit = work
                        .commit(&mut self.budget)
                        .expect("preflighted exact exchange");
                    self.views[capture.id().slot()].head = commit.head;
                    self.views[capture.id().slot()].count = commit.count;
                    self.retire_private(commit.retired);
                    if commit.count == 0 {
                        self.defer_empty(advanced);
                    }
                    return Progress::complete(4, Ok(Response::Changed));
                }
                match work.step(&mut self.pool, &mut self.budget, records::PORTION - 1) {
                    Ok(progress) => Progress::pending(progress.visited + 1),
                    Err(failure) => {
                        let retirement = work
                            .cancel(&mut self.budget)
                            .expect("failed preparation custody");
                        self.retire_private(retirement);
                        self.defer_empty(*capture);
                        return Progress::complete(failure.visited + 1, Err(failure.error.into()));
                    }
                }
            }
        };
        self.worker = Some(worker);
        progress
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;
    type Small = Actor<32, 8, 4, 8, 9, 32>;
    fn fresh<
        const G: usize,
        const I: usize,
        const P: usize,
        const D: usize,
        const R: usize,
        const S: usize,
    >() -> Box<Actor<G, I, P, D, R, S>> {
        let mut allocation = Box::<Actor<G, I, P, D, R, S>>::new_uninit();
        // SAFETY: the Box exclusively supplies the aligned complete allocation.
        unsafe {
            Actor::initialize_at(allocation.as_mut_ptr());
            allocation.assume_init()
        }
    }
    fn inode(slot: u16) -> Token {
        Token {
            slot,
            generation: 1,
        }
    }
    fn request(
        node: u16,
        owner: Owner,
        kind: Option<Kind>,
        start: i64,
        len: i64,
        root: u16,
    ) -> Request {
        Request {
            inode: inode(node),
            owner,
            root,
            range: Range::relative(0, start, len).unwrap(),
            command: Command::Set(kind),
        }
    }
    fn check<
        const G: usize,
        const I: usize,
        const P: usize,
        const D: usize,
        const R: usize,
        const S: usize,
    >(
        a: &Actor<G, I, P, D, R, S>,
    ) {
        let mut paid = 0;
        for root in 0..R as u16 {
            let pool = a.record_charge(root).unwrap();
            assert_eq!(pool, a.budget.root(root).unwrap().paid());
            paid += pool;
        }
        assert_eq!(paid, a.counts().paid());
        assert!(paid <= 384);
        assert!(a.counts().published <= 256);
    }
    fn drain<
        const G: usize,
        const I: usize,
        const P: usize,
        const D: usize,
        const R: usize,
        const S: usize,
    >(
        a: &mut Actor<G, I, P, D, R, S>,
    ) {
        for _ in 0..2000 {
            if !a.busy() {
                return;
            }
            let p = a.step();
            assert!(p.visited <= 8);
            assert!(p.completed.is_none());
            check(a);
        }
        panic!("cleanup did not finish");
    }
    fn run<
        const G: usize,
        const I: usize,
        const P: usize,
        const D: usize,
        const R: usize,
        const S: usize,
    >(
        a: &mut Actor<G, I, P, D, R, S>,
        r: Request,
    ) -> Result<Response, Error> {
        a.start(r)?;
        for _ in 0..2000 {
            let p = a.step();
            assert!(p.visited <= 8);
            check(a);
            if let Some(result) = p.completed {
                drain(a);
                return result;
            }
        }
        panic!("worker did not finish");
    }
    fn query<
        const G: usize,
        const I: usize,
        const P: usize,
        const D: usize,
        const R: usize,
        const S: usize,
    >(
        a: &mut Actor<G, I, P, D, R, S>,
        mut r: Request,
        kind: Kind,
    ) -> Option<Lock> {
        r.command = Command::Get(kind);
        let Ok(Response::Blocker(blocker)) = run(a, r) else {
            panic!("query failed")
        };
        blocker
    }
    #[test]
    fn conflict_scan_keeps_process_and_description_owners_independent() {
        let mut a: Box<Small> = fresh();
        let p = Owner::Process(256);
        let q = Owner::Process(257);
        let ofd = Owner::Description {
            slot: 0,
            generation: 1,
        };
        assert_eq!(
            run(&mut a, request(0, p, Some(Kind::Read), 0, 10, 0)),
            Ok(Response::Changed)
        );
        assert!(matches!(
            run(&mut a, request(0, ofd, Some(Kind::Write), 0, 10, 2)),
            Err(Error::Conflict(_))
        ));
        assert_eq!(
            run(&mut a, request(0, q, Some(Kind::Read), 0, 10, 1)),
            Ok(Response::Changed)
        );
        assert!(query(&mut a, request(0, p, None, 0, 10, 0), Kind::Read).is_none());
        let blocker = query(&mut a, request(0, p, None, 0, 10, 0), Kind::Write).unwrap();
        assert_eq!(blocker.owner, q);
        assert!(matches!(
            run(&mut a, request(0, p, Some(Kind::Write), 0, 10, 0)),
            Err(Error::Conflict(_))
        ));
        assert!(matches!(
            run(&mut a, request(0, ofd, Some(Kind::Write), 0, 10, 2)),
            Err(Error::Conflict(_))
        ));
        assert_eq!(
            run(&mut a, request(0, p, None, 0, 0, 0)),
            Ok(Response::Changed)
        );
        assert_eq!(
            run(&mut a, request(0, q, None, 0, 0, 1)),
            Ok(Response::Changed)
        );
        assert_eq!(
            run(&mut a, request(0, ofd, Some(Kind::Write), 0, 10, 2)),
            Ok(Response::Changed)
        );
        assert_eq!(
            query(&mut a, request(0, p, None, 0, 10, 0), Kind::Read)
                .unwrap()
                .owner,
            ofd
        );
        assert_eq!(a.group_charge(0), Some(0));
        assert_eq!(a.group_charge(1), Some(0));
        assert_eq!(a.group_charge(2), Some(1));
    }
    #[test]
    fn close_one_inode_keeps_other_inode_and_defers_physical_payment_return() {
        let mut a: Box<Small> = fresh();
        let p = Owner::Process(256);
        let q = Owner::Process(257);
        for node in [0, 1] {
            run(&mut a, request(node, p, Some(Kind::Write), 0, 10, 0)).unwrap();
        }
        let old = a.groups.lookup(inode(0), p).unwrap().unwrap();
        a.close(inode(0), p).unwrap();
        assert!(a.groups.lookup(inode(0), p).unwrap().is_none());
        assert!(a.groups.lookup(inode(1), p).unwrap().is_some());
        assert_eq!(a.counts().published, 1);
        assert_eq!(a.counts().retired, 1);
        assert_eq!(a.record_charge(0), Some(2));
        assert_eq!(a.group_charge(0), Some(2));
        assert_eq!(
            a.start(request(0, q, Some(Kind::Write), 0, 10, 1)),
            Err(Error::Busy)
        );
        drain(&mut a);
        assert_eq!(a.group_charge(0), Some(1));
        assert_eq!(a.record_charge(0), Some(1));
        assert!(!a.groups.valid(old));
        assert!(query(&mut a, request(0, q, None, 0, 10, 1), Kind::Read).is_none());
        assert_eq!(
            query(&mut a, request(1, q, None, 0, 10, 1), Kind::Read)
                .unwrap()
                .owner,
            p
        );
        run(&mut a, request(0, p, Some(Kind::Write), 0, 10, 0)).unwrap();
        let new = a.groups.lookup(inode(0), p).unwrap().unwrap();
        assert!(!a.groups.valid(old));
        assert_ne!(new.id(), old.id());
        a.close(inode(0), p).unwrap();
        a.close(inode(0), p).unwrap();
        drain(&mut a);
        assert!(a.groups.lookup(inode(1), p).unwrap().is_some());
    }
    #[test]
    fn close_cancels_every_worker_position_including_before_group_creation() {
        let owner = Owner::Process(256);
        let mut positions = 0;
        for stop in 0..200 {
            let mut a: Box<Small> = fresh();
            for byte in (0..40).step_by(2) {
                run(&mut a, request(0, owner, Some(Kind::Write), byte, 1, 0)).unwrap();
            }
            a.start(request(0, owner, Some(Kind::Read), 5, 10, 0))
                .unwrap();
            let mut completed = false;
            for _ in 0..stop {
                let p = a.step();
                assert!(p.visited <= 8);
                check(&a);
                if p.completed.is_some() {
                    completed = true;
                    break;
                }
            }
            if completed {
                break;
            }
            a.close(inode(0), owner).unwrap();
            assert!(a.groups.lookup(inode(0), owner).unwrap().is_none());
            let p = a.step();
            assert!(p.visited <= 8);
            assert_eq!(p.completed, Some(Err(Error::Cancelled)));
            check(&a);
            drain(&mut a);
            assert_eq!(a.record_charge(0), Some(0));
            assert_eq!(a.group_charge(0), Some(0));
            assert!(
                query(
                    &mut a,
                    request(0, Owner::Process(257), None, 0, 0, 1),
                    Kind::Read
                )
                .is_none()
            );
            positions += 1;
        }
        assert!(positions > 10);
        let mut a: Box<Small> = fresh();
        a.start(request(0, owner, Some(Kind::Write), 0, 10, 0))
            .unwrap();
        assert_eq!(a.group_charge(0), Some(0));
        a.close(inode(0), owner).unwrap();
        assert_eq!(a.step().completed, Some(Err(Error::Cancelled)));
        drain(&mut a);
        assert_eq!(a.group_charge(0), Some(0));
    }
    #[test]
    fn cancel_new_preparation_cleans_empty_identity_and_preserves_old_publication() {
        for existing in [false, true] {
            let mut a: Box<Small> = fresh();
            let owner = Owner::Process(256);
            if existing {
                run(&mut a, request(0, owner, Some(Kind::Write), 0, 10, 0)).unwrap();
            }
            a.start(request(0, owner, Some(Kind::Read), 4, 3, 0))
                .unwrap();
            for _ in 0..20 {
                let p = a.step();
                assert!(p.visited <= 8);
                if matches!(
                    a.worker.as_ref().map(|w| &w.phase),
                    Some(Phase::Prepare { .. })
                ) {
                    break;
                }
            }
            assert!(a.cancel());
            assert_eq!(a.step().completed, Some(Err(Error::Cancelled)));
            drain(&mut a);
            assert_eq!(a.group_charge(0), Some(usize::from(existing)));
            assert_eq!(a.record_charge(0), Some(usize::from(existing)));
            let blocker = query(
                &mut a,
                request(0, Owner::Process(257), None, 0, 10, 1),
                Kind::Read,
            );
            assert_eq!(blocker.is_some(), existing);
            if let Some(blocker) = blocker {
                assert_eq!(blocker.kind, Kind::Write);
                assert_eq!(blocker.range, Range::relative(0, 0, 10).unwrap());
            }
        }
    }
    #[test]
    fn departed_pid_disappears_before_cleanup_and_preserves_other_owners() {
        let mut a: Box<Small> = fresh();
        let p = Owner::Process(256);
        let q = Owner::Process(257);
        let ofd = Owner::Description {
            slot: 0,
            generation: 1,
        };
        for node in [0, 1] {
            run(&mut a, request(node, p, Some(Kind::Read), 0, 10, 0)).unwrap();
        }
        run(&mut a, request(0, q, Some(Kind::Read), 0, 10, 1)).unwrap();
        run(&mut a, request(0, ofd, Some(Kind::Read), 0, 10, 2)).unwrap();
        a.depart_pid(256).unwrap();
        a.depart_pid(256).unwrap();
        assert!(a.groups.lookup(inode(0), p).unwrap().is_none());
        assert!(a.groups.lookup(inode(1), p).unwrap().is_none());
        assert!(a.groups.lookup(inode(0), q).unwrap().is_some());
        assert!(a.groups.lookup(inode(0), ofd).unwrap().is_some());
        assert_eq!(a.record_charge(0), Some(2));
        assert_eq!(a.group_charge(0), Some(2));
        drain(&mut a);
        assert_eq!(a.record_charge(0), Some(0));
        assert_eq!(a.group_charge(0), Some(0));
        assert_eq!(a.record_charge(1), Some(1));
        assert_eq!(a.record_charge(2), Some(1));
        run(
            &mut a,
            request(1, Owner::Process(512), Some(Kind::Write), 0, 10, 0),
        )
        .unwrap();
        assert_eq!(
            query(&mut a, request(1, q, None, 0, 10, 1), Kind::Read)
                .unwrap()
                .owner,
            Owner::Process(512)
        );
    }
    #[test]
    fn complete_root_reserve_and_copy_budget_remain_available_under_publication_load() {
        type Full = Actor<512, 1285, 256, 128, 320, 256>;
        let mut a: Box<Full> = fresh();
        for root in 0..8 {
            let count = match root {
                0 => 127,
                1 => 33,
                _ => 16,
            };
            for byte in 0..count {
                run(
                    &mut a,
                    request(
                        root,
                        Owner::Process(256 + root as u32),
                        Some(Kind::Write),
                        byte * 2,
                        1,
                        root,
                    ),
                )
                .unwrap();
            }
        }
        assert_eq!(a.counts().published, 256);
        assert_eq!(a.budget.common(), 128);
        assert_eq!(
            run(
                &mut a,
                request(8, Owner::Process(264), Some(Kind::Write), 0, 1, 8)
            ),
            Err(Error::NoLocks)
        );
        assert_eq!(a.group_charge(8), Some(0));
        assert_eq!(
            run(&mut a, request(0, Owner::Process(256), None, 126, 1, 0)),
            Ok(Response::Changed)
        );
        assert_eq!(a.record_charge(0), Some(126));
        assert_eq!(a.counts().published, 255);
        for root in 0..8 {
            a.close(inode(root), Owner::Process(256 + root as u32))
                .unwrap();
        }
        assert_eq!(a.counts().retired, 255);
        assert_eq!(a.counts().published, 0);
        drain(&mut a);
        assert_eq!(a.counts().paid(), 0);
        run(
            &mut a,
            request(8, Owner::Process(264), Some(Kind::Write), 0, 1, 8),
        )
        .unwrap();
    }
    #[test]
    fn fullest_getlk_scan_visits_512_objects_in_64_service_steps() {
        type Full = Actor<512, 1285, 256, 128, 320, 256>;
        let mut a: Box<Full> = fresh();
        let page = proto_process::lifetimes::Page::new();
        for index in 0..256 {
            page.publish(256 + index).unwrap();
            run(
                &mut a,
                request(
                    0,
                    Owner::Process(256 + index),
                    Some(Kind::Read),
                    0,
                    1,
                    (index / 32) as u16,
                ),
            )
            .unwrap();
        }
        assert_eq!(a.counts().published, 256);
        let mut r = request(
            0,
            Owner::Description {
                slot: 127,
                generation: 1,
            },
            None,
            0,
            1,
            0,
        );
        r.command = Command::Get(Kind::Read);
        a.start(r).unwrap();
        let mut visited = 0;
        let mut steps = 0;
        loop {
            let mut checks = 0;
            let p = a.step_with_life(|pid| {
                checks += 1;
                page.live(pid)
            });
            assert_eq!(checks, p.visited);
            assert!(p.visited <= 8);
            visited += p.visited;
            steps += 1;
            if let Some(result) = p.completed {
                assert_eq!(result, Ok(Response::Blocker(None)));
                break;
            }
            assert!(steps <= 64);
        }
        assert_eq!(visited, 512);
        assert_eq!(steps, 64);
        assert!(!a.busy());
        check(&a);
    }
    #[test]
    fn fragmentation_beyond_the_live_limit_preserves_every_old_region() {
        type Full = Actor<512, 1285, 256, 128, 320, 256>;
        let mut a: Box<Full> = fresh();
        let p = Owner::Process(256);
        run(&mut a, request(0, p, Some(Kind::Write), 0, 3, 0)).unwrap();
        for index in 0..126 {
            run(
                &mut a,
                request(0, p, Some(Kind::Write), 4 + index * 2, 1, 0),
            )
            .unwrap();
        }
        assert_eq!(a.record_charge(0), Some(127));
        assert_eq!(
            run(&mut a, request(0, p, None, 1, 1, 0)),
            Err(Error::NoLocks)
        );
        assert_eq!(a.record_charge(0), Some(127));
        assert_eq!(a.counts().published, 127);
        let blocker = query(
            &mut a,
            request(0, Owner::Process(257), None, 1, 1, 1),
            Kind::Read,
        )
        .unwrap();
        assert_eq!(blocker.range, Range::relative(0, 0, 3).unwrap());
        assert_eq!(
            run(&mut a, request(0, p, None, 0, 3, 0)),
            Ok(Response::Changed)
        );
        assert_eq!(a.record_charge(0), Some(126));
    }
    #[test]
    fn terminal_group_epoch_aborts_copy_and_close_still_reclaims_the_old_head() {
        let mut a: Box<Small> = fresh();
        let p = Owner::Process(256);
        run(&mut a, request(0, p, Some(Kind::Write), 0, 10, 0)).unwrap();
        let capture = a.groups.lookup(inode(0), p).unwrap().unwrap();
        a.groups.set_test_epoch(capture.id(), u64::MAX);
        assert_eq!(
            run(&mut a, request(0, p, Some(Kind::Read), 4, 3, 0)),
            Err(Error::NoLocks)
        );
        assert_eq!(a.record_charge(0), Some(1));
        assert_eq!(a.group_charge(0), Some(1));
        let blocker = query(
            &mut a,
            request(0, Owner::Process(257), None, 4, 3, 1),
            Kind::Read,
        )
        .unwrap();
        assert_eq!(blocker.kind, Kind::Write);
        assert_eq!(blocker.range, Range::relative(0, 0, 10).unwrap());
        a.close(inode(0), p).unwrap();
        drain(&mut a);
        assert_eq!(a.record_charge(0), Some(0));
        assert_eq!(a.group_charge(0), Some(0));
    }
    #[test]
    fn multiple_departure_cursors_keep_queue_custody_and_other_pid_heads() {
        let mut a: Box<Small> = fresh();
        for pid in 256..259 {
            run(
                &mut a,
                request(
                    0,
                    Owner::Process(pid),
                    Some(Kind::Read),
                    0,
                    10,
                    (pid - 256) as u16,
                ),
            )
            .unwrap();
        }
        a.depart_pid(256).unwrap();
        a.depart_pid(257).unwrap();
        a.depart_pid(256).unwrap();
        assert_eq!(a.departure_head, 0);
        assert_eq!(a.departure_tail, 1);
        drain(&mut a);
        assert_eq!(a.departure_head, NONE);
        assert_eq!(a.departure_tail, NONE);
        assert!(a.departures.iter().all(Option::is_none));
        assert_eq!(a.record_charge(0), Some(0));
        assert_eq!(a.record_charge(1), Some(0));
        assert_eq!(a.record_charge(2), Some(1));
        assert!(
            a.groups
                .lookup(inode(0), Owner::Process(258))
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn changed_preparation_epoch_aborts_without_altering_the_published_head() {
        let mut a: Box<Small> = fresh();
        let owner = Owner::Process(256);
        run(&mut a, request(0, owner, Some(Kind::Write), 0, 10, 0)).unwrap();
        a.start(request(0, owner, Some(Kind::Read), 4, 3, 0))
            .unwrap();
        for _ in 0..20 {
            let p = a.step();
            assert!(p.visited <= 8);
            if matches!(
                a.worker.as_ref().map(|w| &w.phase),
                Some(Phase::Prepare { .. })
            ) {
                break;
            }
        }
        let capture = a.groups.lookup(inode(0), owner).unwrap().unwrap();
        a.groups.advance(capture).unwrap();
        let mut result = None;
        for _ in 0..100 {
            let p = a.step();
            assert!(p.visited <= 8);
            check(&a);
            if p.completed.is_some() {
                result = p.completed;
                break;
            }
        }
        assert_eq!(result, Some(Err(Error::Cancelled)));
        drain(&mut a);
        assert_eq!(a.record_charge(0), Some(1));
        let blocker = query(
            &mut a,
            request(0, Owner::Process(257), None, 4, 3, 1),
            Kind::Read,
        )
        .unwrap();
        assert_eq!(blocker.kind, Kind::Write);
        assert_eq!(blocker.range, Range::relative(0, 0, 10).unwrap());
    }
    fn event_run(a: &mut Small, request: Request) -> std::vec::Vec<GroupEvent> {
        a.start(request).unwrap();
        let mut events = std::vec::Vec::new();
        let mut completed = false;
        for _ in 0..2000 {
            let progress = a.step();
            assert!(progress.visited <= 8);
            check(a);
            if let Some(event) = progress.group_event {
                events.push(event);
            }
            if let Some(result) = progress.completed {
                assert_eq!(result, Ok(Response::Changed));
                assert!(!completed);
                completed = true;
            }
            if !a.busy() {
                assert!(completed);
                return events;
            }
        }
        panic!("event worker did not finish");
    }
    fn event_cleanup(a: &mut Small) -> std::vec::Vec<GroupEvent> {
        let mut events = std::vec::Vec::new();
        for _ in 0..2000 {
            if !a.busy() {
                return events;
            }
            let progress = a.step();
            assert!(progress.visited <= 8);
            assert!(progress.completed.is_none());
            check(a);
            if let Some(event) = progress.group_event {
                let GroupEvent::Released { root, .. } = event else {
                    panic!("cleanup created a group")
                };
                assert_eq!(a.record_charge(root), Some(0));
                assert_eq!(a.group_charge(root), Some(0));
                events.push(event);
            }
        }
        panic!("event cleanup did not finish");
    }
    #[test]
    fn group_events_keep_original_payer_until_final_close_cleanup() {
        let mut a: Box<Small> = fresh();
        let owner = Owner::Process(256);
        let first = event_run(&mut a, request(0, owner, Some(Kind::Write), 0, 10, 0));
        let [GroupEvent::Created { id, root: 0 }] = first.as_slice() else {
            panic!("exact created event missing")
        };
        let id = *id;
        assert!(event_run(&mut a, request(0, owner, Some(Kind::Write), 10, 10, 1)).is_empty());
        assert_eq!(a.group_charge(0), Some(1));
        assert_eq!(a.group_charge(1), Some(0));
        a.close(inode(0), owner).unwrap();
        assert_eq!(a.record_charge(0), Some(1));
        assert_eq!(
            event_cleanup(&mut a),
            [GroupEvent::Released { id, root: 0 }]
        );
        let second = event_run(&mut a, request(0, owner, Some(Kind::Write), 0, 10, 1));
        let [GroupEvent::Created { id: new, root: 1 }] = second.as_slice() else {
            panic!("new payer event missing")
        };
        assert_ne!(*new, id);
        assert_eq!(
            event_run(&mut a, request(0, owner, None, 0, 0, 0)),
            [GroupEvent::Released { id: *new, root: 1 }]
        );
    }
    #[test]
    fn cancelled_private_copy_releases_group_event_after_last_record() {
        let mut a: Box<Small> = fresh();
        a.start(request(0, Owner::Process(256), Some(Kind::Write), 0, 10, 1))
            .unwrap();
        let mut created = None;
        for _ in 0..100 {
            let progress = a.step();
            assert!(progress.completed.is_none());
            if let Some(GroupEvent::Created { id, root: 1 }) = progress.group_event {
                assert!(created.replace(id).is_none());
            } else {
                assert!(progress.group_event.is_none());
            }
            if a.counts().private != 0 {
                break;
            }
        }
        let id = created.expect("private group created event");
        assert_eq!(a.counts().private, 1);
        assert!(a.cancel());
        let terminal = a.step();
        assert_eq!(terminal.completed, Some(Err(Error::Cancelled)));
        assert!(terminal.group_event.is_none());
        assert_eq!(a.record_charge(1), Some(1));
        assert_eq!(a.group_charge(1), Some(1));
        assert_eq!(
            event_cleanup(&mut a),
            [GroupEvent::Released { id, root: 1 }]
        );
    }
    #[test]
    fn refused_ninth_root_still_delivers_created_and_released_empty_group() {
        let mut a: Box<Small> = fresh();
        for root in 0..8 {
            let owner = Owner::Description {
                slot: root,
                generation: 1,
            };
            assert_eq!(
                event_run(&mut a, request(root, owner, Some(Kind::Read), 0, 10, root)).len(),
                1
            );
        }
        a.start(request(0, Owner::Process(256), Some(Kind::Read), 0, 10, 8))
            .unwrap();
        let mut created = None;
        for _ in 0..100 {
            let progress = a.step();
            if let Some(GroupEvent::Created { id, root: 8 }) = progress.group_event {
                assert!(created.replace(id).is_none());
            } else {
                assert!(progress.group_event.is_none());
            }
            if let Some(result) = progress.completed {
                assert_eq!(result, Err(Error::NoLocks));
                break;
            }
        }
        let id = created.expect("failed preparation retains new group");
        assert_eq!(a.group_charge(8), Some(1));
        assert_eq!(a.record_charge(8), Some(0));
        assert_eq!(
            event_cleanup(&mut a),
            [GroupEvent::Released { id, root: 8 }]
        );
        for root in 0..8 {
            assert_eq!(a.group_charge(root), Some(1));
            assert_eq!(a.record_charge(root), Some(1));
        }
    }
    #[test]
    fn departed_groups_each_return_their_exact_original_root_event() {
        let mut a: Box<Small> = fresh();
        let owner = Owner::Process(256);
        let mut created = std::vec::Vec::new();
        for node in 0..3 {
            created.extend(event_run(
                &mut a,
                request(node, owner, Some(Kind::Write), 0, 10, node),
            ));
        }
        a.depart_pid(256).unwrap();
        let released = event_cleanup(&mut a);
        assert_eq!(released.len(), 3);
        for event in created {
            let GroupEvent::Created { id, root } = event else {
                panic!("unexpected created list")
            };
            assert_eq!(
                released
                    .iter()
                    .filter(|&&event| event == GroupEvent::Released { id, root })
                    .count(),
                1
            );
        }
        assert_eq!(a.counts().paid(), 0);
    }
    #[test]
    fn long_group_retirement_reports_release_only_after_all_portions() {
        let mut a: Box<Small> = fresh();
        let owner = Owner::Process(256);
        let mut created = None;
        for region in 0..12 {
            let events = event_run(
                &mut a,
                request(0, owner, Some(Kind::Write), region * 2, 1, 2),
            );
            if region == 0 {
                let [GroupEvent::Created { id, root: 2 }] = events.as_slice() else {
                    panic!("created event")
                };
                created = Some(*id);
            } else {
                assert!(events.is_empty());
            }
        }
        assert_eq!(a.record_charge(2), Some(12));
        a.close(inode(0), owner).unwrap();
        let first = a.step();
        assert_eq!(first.visited, 8);
        assert!(first.group_event.is_none());
        assert_eq!(a.record_charge(2), Some(6));
        assert_eq!(a.group_charge(2), Some(1));
        assert_eq!(
            event_cleanup(&mut a),
            [GroupEvent::Released {
                id: created.unwrap(),
                root: 2
            }]
        );
    }
    #[test]
    fn storage_payer_survives_cancel_reply_until_actor_returns_all_debt() {
        let mut ram = crate::Ram::new(proto_fs::Timestamp::ZERO);
        let mut a: Box<Small> = fresh();
        let key = crate::storage::Root {
            id: 17,
            generation: 3,
        };
        let job = ram.storage.lock_anchor(key).unwrap();
        let root = job.index();
        let mut group = None;
        let mut group_anchor = None;
        a.start(request(
            0,
            Owner::Process(256),
            Some(Kind::Write),
            0,
            10,
            root,
        ))
        .unwrap();
        for _ in 0..100 {
            let progress = a.step();
            if let Some(GroupEvent::Created { id, root: payer }) = progress.group_event {
                assert_eq!(payer, root);
                assert!(group.replace(id).is_none());
                assert!(
                    group_anchor
                        .replace(ram.storage.retain_lock_anchor(&job).unwrap())
                        .is_none()
                );
            }
            if a.counts().private != 0 {
                break;
            }
        }
        assert!(group.is_some());
        assert_eq!(a.counts().private, 1);
        a.cancel();
        assert_eq!(a.step().completed, Some(Err(Error::Cancelled)));
        ram.storage.release_lock_anchor(job).unwrap();
        let next_key = crate::storage::Root {
            id: 17,
            generation: 4,
        };
        let peer = ram.storage.lock_anchor(next_key).unwrap();
        assert_ne!(peer.index(), root);
        ram.storage.release_lock_anchor(peer).unwrap();
        for _ in 0..100 {
            if !a.busy() {
                break;
            }
            let progress = a.step();
            if let Some(GroupEvent::Released { id, root: payer }) = progress.group_event {
                assert_eq!(Some(id), group);
                assert_eq!(payer, root);
                assert_eq!(a.counts().paid(), 0);
                ram.storage
                    .release_lock_anchor(group_anchor.take().expect("one retained group root"))
                    .unwrap();
            }
        }
        assert!(!a.busy());
        assert!(group_anchor.is_none());
        let replacement = ram.storage.lock_anchor(next_key).unwrap();
        assert_eq!(replacement.index(), root);
        ram.storage.release_lock_anchor(replacement).unwrap();
    }
    fn life_drain(a: &mut Small, page: &proto_process::lifetimes::Page) {
        for _ in 0..2000 {
            if !a.busy() {
                return;
            }
            let progress = a.step_with_life(|pid| page.live(pid));
            assert!(progress.visited <= 8);
            assert!(progress.completed.is_none());
            check(a);
        }
        panic!("life cleanup did not finish");
    }
    fn life_run(
        a: &mut Small,
        page: &proto_process::lifetimes::Page,
        request: Request,
    ) -> Result<Response, Error> {
        a.start(request)?;
        let mut completed = None;
        for _ in 0..2000 {
            let progress = a.step_with_life(|pid| page.live(pid));
            assert!(progress.visited <= 8);
            check(a);
            if let Some(result) = progress.completed {
                assert!(completed.replace(result).is_none());
            }
            if !a.busy() {
                return completed.expect("life request completion");
            }
        }
        panic!("life worker did not finish");
    }
    #[test]
    fn real_pid_page_keeps_uid_changes_and_excludes_death_before_gone() {
        use core::sync::atomic::{AtomicU64, Ordering};
        let page = proto_process::lifetimes::Page::new();
        page.publish(256).unwrap();
        page.publish(257).unwrap();
        let credentials = AtomicU64::new(1);
        let mut a: Box<Small> = fresh();
        assert_eq!(
            life_run(
                &mut a,
                &page,
                request(0, Owner::Process(256), Some(Kind::Write), 0, 10, 0)
            ),
            Ok(Response::Changed)
        );
        let ofd = Owner::Description {
            slot: 0,
            generation: 1,
        };
        assert_eq!(
            life_run(&mut a, &page, request(0, ofd, Some(Kind::Read), 20, 10, 2)),
            Ok(Response::Changed)
        );
        credentials.fetch_add(7, Ordering::Release);
        let mut query = request(0, Owner::Process(257), None, 0, 40, 1);
        query.command = Command::Get(Kind::Write);
        assert!(matches!(
            life_run(&mut a, &page, query),
            Ok(Response::Blocker(Some(Lock {
                owner: Owner::Process(256),
                ..
            })))
        ));
        assert!(page.retire(256));
        a.start(query).unwrap();
        let progress = a.step_with_life(|pid| page.live(pid));
        assert!(
            matches!(progress.completed, Some(Ok(Response::Blocker(Some(Lock { owner, .. })))) if owner == ofd)
        );
        assert_eq!(progress.visited, 3);
        assert_eq!(a.record_charge(0), Some(1));
        assert_eq!(a.group_charge(0), Some(1));
        life_drain(&mut a, &page);
        assert_eq!(a.record_charge(0), Some(0));
        assert_eq!(a.record_charge(2), Some(1));
        assert_eq!(
            life_run(
                &mut a,
                &page,
                request(0, Owner::Process(257), Some(Kind::Write), 0, 10, 1)
            ),
            Ok(Response::Changed)
        );
    }
    #[test]
    fn pid_death_between_group_entry_and_record_read_is_observed() {
        let page = proto_process::lifetimes::Page::new();
        page.publish(256).unwrap();
        page.publish(257).unwrap();
        let mut a: Box<Small> = fresh();
        life_run(
            &mut a,
            &page,
            request(0, Owner::Process(256), Some(Kind::Write), 0, 10, 0),
        )
        .unwrap();
        let mut query = request(0, Owner::Process(257), None, 0, 10, 1);
        query.command = Command::Get(Kind::Read);
        a.start(query).unwrap();
        let mut observations = 0;
        let progress = a.step_with_life(|pid| {
            let alive = page.live(pid);
            if pid == 256 {
                observations += 1;
                if observations == 1 {
                    assert!(page.retire(pid));
                }
            }
            alive
        });
        assert_eq!(observations, 2);
        assert_eq!(progress.completed, Some(Ok(Response::Blocker(None))));
        assert!(progress.visited <= 8);
        life_drain(&mut a, &page);
        assert_eq!(a.counts().paid(), 0);
    }
    #[test]
    fn dead_worker_pid_cancels_private_and_ready_copies_before_exchange() {
        for ready in [false, true] {
            let page = proto_process::lifetimes::Page::new();
            page.publish(256).unwrap();
            page.publish(257).unwrap();
            let mut a: Box<Small> = fresh();
            life_run(
                &mut a,
                &page,
                request(1, Owner::Process(257), Some(Kind::Write), 0, 10, 1),
            )
            .unwrap();
            if ready {
                life_run(
                    &mut a,
                    &page,
                    request(0, Owner::Process(256), Some(Kind::Write), 0, 10, 0),
                )
                .unwrap();
            }
            a.start(request(
                0,
                Owner::Process(256),
                Some(Kind::Write),
                10,
                10,
                0,
            ))
            .unwrap();
            let mut reached = false;
            for _ in 0..100 {
                let progress = a.step_with_life(|pid| page.live(pid));
                assert!(progress.completed.is_none());
                reached = if ready {
                    matches!(a.worker.as_ref().map(|worker| &worker.phase), Some(Phase::Prepare { work, .. }) if work.ready())
                } else {
                    a.counts().private != 0
                };
                if reached {
                    break;
                }
            }
            assert!(reached);
            assert!(page.retire(256));
            let terminal = a.step_with_life(|pid| page.live(pid));
            assert_eq!(terminal.completed, Some(Err(Error::Cancelled)));
            assert!(a.record_charge(0).unwrap() > 0);
            life_drain(&mut a, &page);
            assert_eq!(a.record_charge(0), Some(0));
            assert_eq!(a.group_charge(0), Some(0));
            assert_eq!(a.record_charge(1), Some(1));
        }
    }
    #[test]
    fn new_pid_place_cleans_previous_debt_and_survives_late_gone() {
        let page = proto_process::lifetimes::Page::new();
        page.publish(256).unwrap();
        page.publish(257).unwrap();
        let mut a: Box<Small> = fresh();
        for node in 0..2 {
            life_run(
                &mut a,
                &page,
                request(node, Owner::Process(256), Some(Kind::Write), 0, 10, node),
            )
            .unwrap();
        }
        assert!(page.retire(256));
        page.publish(512).unwrap();
        assert_eq!(
            life_run(
                &mut a,
                &page,
                request(2, Owner::Process(512), Some(Kind::Write), 0, 10, 2)
            ),
            Ok(Response::Changed)
        );
        assert_eq!(a.record_charge(0), Some(0));
        assert_eq!(a.record_charge(1), Some(0));
        assert_eq!(a.group_charge(2), Some(1));
        a.depart_pid(256).unwrap();
        assert!(!a.busy());
        assert_eq!(a.groups.tracked_pid(0), Ok(Some(512)));
        let mut query = request(2, Owner::Process(257), None, 0, 10, 1);
        query.command = Command::Get(Kind::Read);
        assert!(matches!(
            life_run(&mut a, &page, query),
            Ok(Response::Blocker(Some(Lock {
                owner: Owner::Process(512),
                ..
            })))
        ));
    }
    #[test]
    fn pid_audit_returns_debt_without_a_new_client_request() {
        let page = proto_process::lifetimes::Page::new();
        page.publish(256).unwrap();
        page.publish(257).unwrap();
        let mut a: Box<Small> = fresh();
        life_run(
            &mut a,
            &page,
            request(0, Owner::Process(256), Some(Kind::Write), 0, 10, 0),
        )
        .unwrap();
        life_run(
            &mut a,
            &page,
            request(1, Owner::Process(257), Some(Kind::Write), 0, 10, 1),
        )
        .unwrap();
        assert_eq!(a.audit_pid(4, |pid| page.live(pid)), Err(Error::Invalid));
        assert_eq!(a.audit_pid(0, |pid| page.live(pid)), Ok(false));
        assert!(page.retire(256));
        assert_eq!(a.audit_pid(0, |pid| page.live(pid)), Ok(true));
        assert_eq!(a.audit_pid(0, |pid| page.live(pid)), Ok(false));
        assert_eq!(a.groups.pid_head(256), Ok(None));
        assert_eq!(a.record_charge(0), Some(1));
        life_drain(&mut a, &page);
        assert_eq!(a.record_charge(0), Some(0));
        assert_eq!(a.record_charge(1), Some(1));
    }
    #[test]
    fn dead_query_caller_never_allocates_a_group_or_returns_a_live_result() {
        let page = proto_process::lifetimes::Page::new();
        page.publish(256).unwrap();
        page.retire(256);
        let mut a: Box<Small> = fresh();
        let mut query = request(0, Owner::Process(256), None, 0, 10, 0);
        query.command = Command::Get(Kind::Read);
        assert_eq!(life_run(&mut a, &page, query), Err(Error::Cancelled));
        assert_eq!(a.counts().paid(), 0);
        assert_eq!(a.group_charge(0), Some(0));
    }
    #[test]
    fn ofd_worker_keeps_description_life_independent_of_dead_pid_page() {
        let page = proto_process::lifetimes::Page::new();
        page.publish(256).unwrap();
        page.retire(256);
        page.publish(512).unwrap();
        let mut a: Box<Small> = fresh();
        let owner = Owner::Description {
            slot: 0,
            generation: 1,
        };
        assert_eq!(
            life_run(
                &mut a,
                &page,
                request(0, owner, Some(Kind::Write), 0, 10, 0)
            ),
            Ok(Response::Changed)
        );
        a.depart_pid(256).unwrap();
        assert_eq!(a.audit_pid(0, |pid| page.live(pid)), Ok(false));
        assert_eq!(
            life_run(
                &mut a,
                &page,
                request(0, owner, Some(Kind::Write), 10, 10, 1)
            ),
            Ok(Response::Changed)
        );
        assert_eq!(a.record_charge(0), Some(1));
        assert_eq!(a.record_charge(1), Some(0));
        a.close(inode(0), owner).unwrap();
        life_drain(&mut a, &page);
        assert_eq!(a.counts().paid(), 0);
    }
    #[test]
    fn ofd_death_between_entering_group_and_reading_record_excludes_the_blocker() {
        let mut actor = fresh::<32, 8, 4, 8, 9, 32>();
        let owner = Owner::Description {
            slot: 0,
            generation: 7,
        };
        assert_eq!(
            run(&mut actor, request(0, owner, Some(Kind::Read), 0, 1, 0)),
            Ok(Response::Changed)
        );
        let mut query = request(0, Owner::Process(257), Some(Kind::Write), 0, 1, 0);
        query.command = Command::Get(Kind::Write);
        actor.start(query).unwrap();
        let mut reads = 0;
        let progress = actor.step_with_owners(
            |_| true,
            |token| {
                assert_eq!(
                    token,
                    Token {
                        slot: 0,
                        generation: 7
                    }
                );
                reads += 1;
                reads == 1
            },
        );
        assert!(reads >= 2);
        assert!(progress.visited <= 8);
        assert_eq!(progress.completed, Some(Ok(Response::Blocker(None))));
        assert_eq!(actor.counts().published, 0);
        drain(&mut actor);
        assert_eq!(actor.counts(), budget::Counts::default());
        assert_eq!(actor.audit_description(8, |_| false), Err(Error::Invalid));
    }
}
