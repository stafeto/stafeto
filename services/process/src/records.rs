// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The records of the process service (spec 2, section 3.1): RECORDS of
//! them at most, each in an index with a generation, so that a label the
//! service gave (proto_process::Label) finds its record in O(1) and a
//! label of a gone generation finds nothing. A record comes with its
//! process, which the service creates (Create), and goes only with the
//! notification of the process's end, whose place carries the record's
//! exit label: a copy of its session that outlives the process keeps
//! nothing. A record that Spawn made is a child of the record that asked
//! for it, CHILDREN_MAX children of one record at a time, linked by their
//! indices so that a child that goes leaves its parent in O(1). A child
//! whose process ended is a zombie with its end until its parent's wait
//! takes it (`reap`); the children of a record whose process ended get the
//! service, PID 1, for their parent, and their zombies go at once
//! (CHILDREN_MAX steps). `P` is what the service keeps of the record's
//! process: its handle.
//!
//! A process group and a session are numbers, the PID of the process that
//! made them, and live in the place of that PID's index (`Numbers`): how
//! many records are in the group (zombies too), how many of those have a
//! parent in another group of their session (the group is an orphan when
//! none has, XBD 3.247), and how many records are in the session. A place
//! is free when it has no record and no member of either; a place whose
//! record went while a group or a session still carries its number is
//! held, and its index and generation are not given again (XBD 4.17:
//! neither a PID nor a group's number is reused while the group lives).

use proto_process::{
    Create, Credentials, End, INIT_PID, Label, Place, RECORDS, SPAWN_SETPGROUP, SPAWN_SETSID,
    Selector,
};

/// The children of one record at most, its zombies among them, until
/// RLIMIT_NPROC (5b design, question 3): Spawn past them is EAGAIN. Four
/// in the image of the probe of POSIX processes, which reaches the limit.
pub const CHILDREN_MAX: u32 = if cfg!(feature = "children-max-4") {
    4
} else {
    32
};

/// Where a record is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Created; one of the service's threads loads its program.
    Loading,
    /// Loaded and started.
    Alive,
    /// Its process ended so; the record waits for its parent's wait.
    Zombie(End),
}

/// What became of a record whose process ended (`exited`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// A zombie, until the wait of the parent in `parent` takes it.
    Zombie { parent: usize },
    /// Gone at once: it had no parent but PID 1.
    Reaped,
}

/// The children of a record whose process ended that live on, now the
/// service's: their pages get PPID 1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Orphans {
    indices: [u16; CHILDREN_MAX as usize],
    len: usize,
}

impl Orphans {
    pub fn as_slice(&self) -> &[u16] {
        &self.indices[..self.len]
    }
}

pub struct Record<P> {
    /// Its process, which the service created and calls with later.
    pub process: P,
    pub label: Label,
    /// The PID of its parent: INIT_PID for a record of init's table and
    /// for an orphan.
    pub parent: u32,
    pub credentials: Credentials,
    pub state: State,
    /// The ceiling of its process.
    pub ceiling: u8,
    /// Its process group and session: those of its parent, or its own PID
    /// for a record of init's table (5b T5 changes them).
    pub pgid: u32,
    pub sid: u32,
    /// The index of its parent's record while the parent lives.
    pub parent_index: Option<u16>,
    /// Whether it counts in `Numbers::links` of its group: its parent is
    /// in another group of its session.
    linked: bool,
    /// Its live children, and the first of their list.
    pub children: u32,
    first_child: Option<u16>,
    /// Its neighbours in the list of its parent's children.
    previous: Option<u16>,
    next: Option<u16>,
}

pub struct Records<P> {
    records: [Option<Record<P>>; RECORDS],
    /// The last generation each index gave, 0 for none.
    generations: [u32; RECORDS],
    /// The free indices, the last freed on top.
    free: [u16; RECORDS],
    free_len: usize,
    /// Whether an index is among the free ones.
    listed: [bool; RECORDS],
    /// The group and the session each place's PID names.
    numbers: [Numbers; RECORDS],
}

/// What a place keeps of the group and the session its PID names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Numbers {
    /// The records whose group it is, zombies too.
    members: u16,
    /// Of those, the records whose parent is in another group of their
    /// session.
    links: u16,
    /// The records whose session it is.
    sessions: u16,
    /// The session of the group, while it has members.
    session: u32,
}

impl Numbers {
    const fn unused(&self) -> bool {
        self.members == 0 && self.sessions == 0
    }
}

/// Where a new record goes: with its parent, in a group of its own, in
/// the group of a PID, or in a session of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Join {
    Inherit,
    NewGroup,
    Group(u32),
    NewSession,
}

/// Why a call of groups and sessions failed: ESRCH, EPERM, EACCES.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupError {
    NoProcess,
    Permission,
    Access,
}

impl<P> Default for Records<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P> Records<P> {
    /// No record, every index free, index 0 on top.
    pub const fn new() -> Self {
        let mut free = [0; RECORDS];
        let mut i = 0;
        while i < RECORDS {
            free[i] = (RECORDS - 1 - i) as u16;
            i += 1;
        }
        Self {
            records: [const { None }; RECORDS],
            generations: [0; RECORDS],
            free,
            free_len: RECORDS,
            listed: [true; RECORDS],
            numbers: [Numbers {
                members: 0,
                links: 0,
                sessions: 0,
                session: 0,
            }; RECORDS],
        }
    }

    /// The index of the live record that `raw` names in `place`.
    fn named(&self, raw: u64, place: Place) -> Option<usize> {
        let (label, got) = Label::parse(raw)?;
        let index = usize::from(label.index);
        (got == place
            && self.records[index]
                .as_ref()
                .is_some_and(|r| r.label == label))
        .then_some(index)
    }

    /// The index of the record whose session has `label`, if it lives.
    pub fn find(&self, label: u64) -> Option<usize> {
        self.named(label, Place::Work)
    }

    pub fn get(&self, index: usize) -> Option<&Record<P>> {
        self.records.get(index)?.as_ref()
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Record<P>> {
        self.records.get_mut(index)?.as_mut()
    }

    /// The places taken: the live records, and the places held for a
    /// group or a session whose number is still used.
    pub fn count(&self) -> usize {
        RECORDS - self.free_len
    }

    /// The label the next record gets: the free index on top, one
    /// generation on. None with every record taken (FULL).
    pub fn next_label(&self) -> Option<Label> {
        let index = *self.free[..self.free_len].last()?;
        Some(Label {
            index,
            generation: Label::next_generation(self.generations[usize::from(index)]),
        })
    }

    /// Whether the record in `index` may have another child.
    pub fn may_spawn(&self, index: usize) -> bool {
        self.get(index).is_some_and(|r| r.children < CHILDREN_MAX)
    }

    /// A record of `process`, LOADING, with the label `next_label` gave,
    /// which the caller made its exit place and session with: a child of
    /// the live record in `parent`, which counts it, in the group and
    /// session `join` says (`joining`), or of PID 1 with a group and a
    /// session of its own. O(1).
    ///
    /// # Panics
    /// When `label` is not that of `next_label`, `parent` holds no record
    /// that may have another child (`may_spawn`), or `join` names a group
    /// `joining` did not give.
    pub fn insert(
        &mut self,
        label: Label,
        process: P,
        parent: Option<usize>,
        credentials: Credentials,
        ceiling: u8,
        join: Join,
    ) -> usize {
        assert_eq!(
            self.next_label(),
            Some(label),
            "the label of the next record"
        );
        let i = usize::from(label.index);
        let own = label.pid();
        let (pid, first, (pgid, sid)) = match parent {
            Some(p) => {
                assert!(self.may_spawn(p), "a parent with room for a child");
                let parent = self.records[p].as_mut().expect("a live parent");
                parent.children += 1;
                let first = parent.first_child.replace(i as u16);
                let (pg, sid) = (parent.pgid, parent.sid);
                let group = match join {
                    Join::Inherit => (pg, sid),
                    Join::NewGroup => (own, sid),
                    Join::Group(g) => (g, sid),
                    Join::NewSession => (own, own),
                };
                (parent.label.pid(), first, group)
            }
            None => (INIT_PID, None, (own, own)),
        };
        if let Some(f) = first {
            self.records[usize::from(f)]
                .as_mut()
                .expect("a child")
                .previous = Some(i as u16);
        }
        self.free_len -= 1;
        self.listed[i] = false;
        self.generations[i] = label.generation;
        let linked = parent.is_some_and(|p| self.separates(p, pgid, sid));
        self.records[i] = Some(Record {
            process,
            label,
            parent: pid,
            credentials,
            state: State::Loading,
            ceiling,
            pgid,
            sid,
            parent_index: parent.map(|p| p as u16),
            linked,
            children: 0,
            first_child: None,
            previous: None,
            next: first,
        });
        self.enter(pgid, sid, linked);
        i
    }

    /// Whether the record in `parent` is in another group than `pgid` and
    /// in the session `sid`: a child there in `pgid` is linked to it.
    fn separates(&self, parent: usize, pgid: u32, sid: u32) -> bool {
        self.records[parent]
            .as_ref()
            .is_some_and(|p| p.pgid != pgid && p.sid == sid)
    }

    /// The place of the group or session numbered `number`, while it has
    /// one: the index of the PID and the generation fit the place.
    fn place_of(&self, number: u32) -> Option<usize> {
        let index = (number % RECORDS as u32) as usize;
        (number / RECORDS as u32 != 0 && self.generations[index] == number / RECORDS as u32)
            .then_some(index)
    }

    /// A record joins group `pgid` and session `sid`, linked or not.
    fn enter(&mut self, pgid: u32, sid: u32, linked: bool) {
        let group = self.place_of(pgid).expect("a group with a place");
        let session = self.place_of(sid).expect("a session with a place");
        let g = &mut self.numbers[group];
        if g.members == 0 {
            g.session = sid;
        }
        g.members += 1;
        g.links += u16::from(linked);
        self.numbers[session].sessions += 1;
    }

    /// A record leaves group `pgid` and session `sid`, linked or not; a
    /// place that nothing holds any more is free.
    fn leave(&mut self, pgid: u32, sid: u32, linked: bool) {
        let group = self.place_of(pgid).expect("a group with a place");
        let session = self.place_of(sid).expect("a session with a place");
        let g = &mut self.numbers[group];
        g.members -= 1;
        g.links -= u16::from(linked);
        self.numbers[session].sessions -= 1;
        self.settle(group);
        self.settle(session);
    }

    /// The place in `index` goes to the free ones when no record is in it
    /// and no group or session carries its number.
    fn settle(&mut self, index: usize) {
        if self.records[index].is_none() && self.numbers[index].unused() && !self.listed[index] {
            self.listed[index] = true;
            self.free[self.free_len] = index as u16;
            self.free_len += 1;
        }
    }

    /// Where a child of the record in `parent` goes that Spawn gave
    /// `flags` (SPAWN_SETPGROUP, SPAWN_SETSID) and `pgroup`, and will have
    /// the PID `own`: a group of its own for SETPGROUP with 0 or `own`,
    /// that of an existing group of the parent's session; its own session
    /// for SETSID. Both flags fail as setpgid of a session leader does:
    /// the order is setsid, then setpgid. None where setpgid says EPERM.
    pub fn joining(&self, parent: usize, flags: u32, pgroup: u32, own: u32) -> Option<Join> {
        let sid = self.get(parent)?.sid;
        if flags & SPAWN_SETSID != 0 {
            return (flags & SPAWN_SETPGROUP == 0).then_some(Join::NewSession);
        }
        if flags & SPAWN_SETPGROUP == 0 {
            return Some(Join::Inherit);
        }
        if pgroup == 0 || pgroup == own {
            return Some(Join::NewGroup);
        }
        let place = self.place_of(pgroup)?;
        let group = &self.numbers[place];
        (group.members > 0 && group.session == sid).then_some(Join::Group(pgroup))
    }

    /// The members of group `pgid`, 0 for a group nobody is in.
    pub fn members(&self, pgid: u32) -> usize {
        self.place_of(pgid)
            .map_or(0, |p| usize::from(self.numbers[p].members))
    }

    /// Whether group `pgid` is an orphan (XBD 3.247: no member has a
    /// parent in another group of the group's session); None for a group
    /// nobody is in. O(1).
    pub fn orphaned(&self, pgid: u32) -> Option<bool> {
        let group = &self.numbers[self.place_of(pgid)?];
        (group.members > 0).then_some(group.links == 0)
    }

    /// Whether the PID `number` still names a group or a session, or a
    /// record: its index and generation are not given again.
    pub fn held(&self, number: u32) -> bool {
        self.place_of(number)
            .is_some_and(|p| self.records[p].is_some() || !self.numbers[p].unused())
    }

    /// The session of group `pgid`, while it has members.
    pub fn session_of(&self, pgid: u32) -> Option<u32> {
        let group = &self.numbers[self.place_of(pgid)?];
        (group.members > 0).then_some(group.session)
    }

    /// The record that `pid` names for a call of `caller`: the caller for
    /// 0, otherwise a record that is no LOADING one, whose PID its parent
    /// does not know yet.
    fn target(&self, caller: usize, pid: u32) -> Option<usize> {
        if pid == 0 {
            return Some(caller);
        }
        self.find_pid(pid).filter(|&t| {
            self.records[t]
                .as_ref()
                .is_some_and(|r| r.state != State::Loading)
        })
    }

    /// getpgid of `pid` (0 for the caller's): a zombie keeps its group.
    pub fn pgid_of(&self, caller: usize, pid: u32) -> Option<u32> {
        Some(self.records[self.target(caller, pid)?].as_ref()?.pgid)
    }

    /// getsid of `pid` (0 for the caller's).
    pub fn sid_of(&self, caller: usize, pid: u32) -> Option<u32> {
        Some(self.records[self.target(caller, pid)?].as_ref()?.sid)
    }

    /// setpgid ([P24-SETPGID]) for the record in `caller`: `pid` is the
    /// caller or one of its children (ESRCH otherwise; 0 is the caller),
    /// `pgid` 0 means the target's own PID. A child is another session's
    /// (EPERM) or has started: every child came from posix_spawn, which
    /// executed its program, so EACCES, until fork comes (5g). The
    /// caller, unless it leads its session (EPERM), joins the group
    /// `pgid` of its own session, which is its own, new or not (EPERM
    /// for any other group of another session or none). The links of the
    /// caller and of its children are counted anew: CHILDREN_MAX steps.
    pub fn set_pgid(&mut self, caller: usize, pid: u32, pgid: u32) -> Result<(), GroupError> {
        let me = self.records[caller].as_ref().expect("the caller");
        let (own, sid) = (me.label.pid(), me.sid);
        if pid != 0 && pid != own {
            let child = self
                .target(caller, pid)
                .filter(|&t| {
                    self.records[t]
                        .as_ref()
                        .is_some_and(|r| r.parent_index == Some(caller as u16))
                })
                .ok_or(GroupError::NoProcess)?;
            let same = self.records[child].as_ref().is_some_and(|r| r.sid == sid);
            return Err(if same {
                GroupError::Access
            } else {
                GroupError::Permission
            });
        }
        if sid == own {
            return Err(GroupError::Permission);
        }
        let pgid = if pgid == 0 { own } else { pgid };
        if pgid != own && self.session_of(pgid) != Some(sid) {
            return Err(GroupError::Permission);
        }
        if me.pgid != pgid {
            self.regroup(caller, pgid, sid);
        }
        Ok(())
    }

    /// setsid ([P24-SETSID]) for the record in `caller`: a session and a
    /// group of its own PID, which it returns; EPERM when a group already
    /// has that number, that is when the caller leads one.
    pub fn set_sid(&mut self, caller: usize) -> Result<u32, GroupError> {
        let own = self.records[caller]
            .as_ref()
            .expect("the caller")
            .label
            .pid();
        if self.members(own) > 0 {
            return Err(GroupError::Permission);
        }
        self.regroup(caller, own, own);
        Ok(own)
    }

    /// The record in `index` moves to group `pgid` of session `sid`: the
    /// numbers of both places follow, and so do the links of the record
    /// and of its children, which count a parent in another group of
    /// their session. CHILDREN_MAX steps.
    fn regroup(&mut self, index: usize, pgid: u32, sid: u32) {
        let record = self.records[index].as_ref().expect("a record");
        let (old_pgid, old_sid, was) = (record.pgid, record.sid, record.linked);
        let linked = record
            .parent_index
            .is_some_and(|p| self.separates(usize::from(p), pgid, sid));
        self.enter(pgid, sid, linked);
        let record = self.records[index].as_mut().expect("a record");
        (record.pgid, record.sid, record.linked) = (pgid, sid, linked);
        let mut child = record.first_child;
        self.leave(old_pgid, old_sid, was);
        while let Some(c) = child {
            let c = usize::from(c);
            let (c_pgid, c_sid, c_linked, next) = {
                let r = self.records[c].as_ref().expect("a child");
                (r.pgid, r.sid, r.linked, r.next)
            };
            let now = self.separates(index, c_pgid, c_sid)
                && !matches!(
                    self.records[c].as_ref().map(|r| r.state),
                    Some(State::Zombie(_))
                );
            if now != c_linked {
                let place = self.place_of(c_pgid).expect("a group with a place");
                let links = &mut self.numbers[place].links;
                *links = if now { *links + 1 } else { *links - 1 };
                self.records[c].as_mut().expect("a child").linked = now;
            }
            child = next;
        }
    }

    /// The live children of the record in `index`, by their indices.
    pub fn children(&self, index: usize) -> impl Iterator<Item = usize> + '_ {
        let first = self.get(index).and_then(|r| r.first_child);
        core::iter::successors(first, |&c| self.records[usize::from(c)].as_ref()?.next)
            .map(usize::from)
    }

    /// The index of the record whose identity session has `label`, while
    /// the record is in the table (a zombie too: it answers who it was).
    pub fn find_identity(&self, label: u64) -> Option<usize> {
        self.named(label, Place::Identity)
    }

    /// The index of the record whose exit place has `label`, while its
    /// process lives: a label of another place, of a gone generation, of
    /// no record or of a zombie names none. O(1).
    pub fn find_exit(&self, label: u64) -> Option<usize> {
        let index = self.named(label, Place::Exit)?;
        (!matches!(self.records[index].as_ref()?.state, State::Zombie(_))).then_some(index)
    }

    /// The index of the record of `pid`, a zombie or not. O(1).
    pub fn find_pid(&self, pid: u32) -> Option<usize> {
        let index = (pid % RECORDS as u32) as u16;
        let label = Label {
            index,
            generation: pid / RECORDS as u32,
        };
        self.find(label.raw())
    }

    /// The process of the record in `index` ended with `end` (the
    /// notification of its exit place came, `find_exit`): its live
    /// children are the service's from now on (the returned orphans), its
    /// zombie children go; it is a zombie for its parent's wait, or goes
    /// at once without one or when it was still LOADING. CHILDREN_MAX
    /// steps.
    pub fn exited(&mut self, index: usize, end: End) -> (Exit, Orphans) {
        let mut orphans = Orphans::default();
        let mut child = self.records[index]
            .as_mut()
            .and_then(|r| r.first_child.take());
        while let Some(c) = child {
            let orphan = self.records[usize::from(c)].as_mut().expect("a child");
            child = orphan.next;
            orphan.parent = INIT_PID;
            orphan.parent_index = None;
            orphan.previous = None;
            orphan.next = None;
            // The service is no member of any group: the link of the
            // child to its parent's group goes.
            let (pgid, linked) = (orphan.pgid, core::mem::take(&mut orphan.linked));
            let zombie = matches!(orphan.state, State::Zombie(_));
            self.unlink(pgid, linked);
            if zombie {
                self.free_index(usize::from(c));
            } else {
                orphans.indices[orphans.len] = c;
                orphans.len += 1;
            }
        }
        let record = self.records[index].as_mut().expect("an ended record");
        record.children = 0;
        // A zombie is no process any more: its link to its parent's group
        // goes with its end (it stays a member of its own group).
        let (pgid, linked) = (record.pgid, core::mem::take(&mut record.linked));
        // A process that never ran was no child of its parent's to wait
        // for: its Spawn failed.
        let loaded = record.state != State::Loading;
        record.state = State::Zombie(end);
        self.unlink(pgid, linked);
        let record = self.records[index].as_mut().expect("an ended record");
        let exit = match record.parent_index.filter(|_| loaded) {
            Some(parent) => Exit::Zombie {
                parent: usize::from(parent),
            },
            None => {
                self.reap(index);
                Exit::Reaped
            }
        };
        (exit, orphans)
    }

    /// The zombie in `index` goes: out of its parent's list, its index on
    /// top of the free ones, its next label one generation on. O(1).
    pub fn reap(&mut self, index: usize) -> Option<Record<P>> {
        let record = self.records[index].as_ref()?;
        if !matches!(record.state, State::Zombie(_)) {
            return None;
        }
        let (previous, next, parent) = (record.previous, record.next, record.parent_index);
        match previous {
            Some(p) => {
                self.records[usize::from(p)]
                    .as_mut()
                    .expect("a sibling")
                    .next = next
            }
            None => {
                if let Some(parent) = parent.and_then(|p| self.records[usize::from(p)].as_mut()) {
                    parent.first_child = next;
                }
            }
        }
        if let Some(n) = next {
            self.records[usize::from(n)]
                .as_mut()
                .expect("a sibling")
                .previous = previous;
        }
        if let Some(parent) = parent.and_then(|p| self.records[usize::from(p)].as_mut()) {
            parent.children -= 1;
        }
        self.free_index(index)
    }

    /// A member of group `pgid` that was linked is not any more.
    fn unlink(&mut self, pgid: u32, linked: bool) {
        if linked {
            let place = self.place_of(pgid).expect("a group with a place");
            self.numbers[place].links -= 1;
        }
    }

    /// The record in `index` leaves the table and its group and session;
    /// its place is free unless a group or a session carries its number.
    fn free_index(&mut self, index: usize) -> Option<Record<P>> {
        let record = self.records[index].take()?;
        self.leave(record.pgid, record.sid, record.linked);
        self.settle(index);
        Some(record)
    }

    /// Whether the child in `child` is one `selector` takes: no LOADING
    /// child, whose PID its parent does not know yet.
    pub fn takes(&self, child: usize, selector: Selector) -> bool {
        self.get(child)
            .filter(|r| r.state != State::Loading)
            .is_some_and(|r| match selector {
                Selector::Pid(pid) => r.label.pid() == pid,
                Selector::Any => true,
                Selector::Group(pgid) => r.pgid == pgid,
            })
    }

    /// The first zombie child of the record in `parent` that `selector`
    /// takes, and whether it has any child the selector takes.
    /// CHILDREN_MAX steps.
    pub fn zombie(&self, parent: usize, selector: Selector) -> (Option<usize>, bool) {
        let mut any = false;
        for c in self.children(parent) {
            if !self.takes(c, selector) {
                continue;
            }
            any = true;
            if matches!(
                self.records[c].as_ref().map(|r| r.state),
                Some(State::Zombie(_))
            ) {
                return (Some(c), true);
            }
        }
        (None, any)
    }
}

/// The exit place of the record of `label` for the process of `create`,
/// with the service's loop at `loop_level`: the label of the copy of the
/// channel with NOTIFY, the priority of its slot and that of the
/// notification of the end, both the process's ceiling (spec 2, 3.1,
/// decision 1 of 5b), so that the end of a process lifts the service no
/// higher than the process could run, whatever the loop's level.
pub const fn exit_place(label: Label, create: &Create, loop_level: u8) -> ExitPlace {
    let _ = loop_level;
    ExitPlace {
        label: label.exit(),
        slot: create.ceiling,
        notice: create.ceiling,
    }
}

/// What `handle_label` and `process_create` take for an exit place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitPlace {
    pub label: u64,
    pub slot: u8,
    pub notice: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_process::{SIGKILL, SIGSEGV};

    fn add(t: &mut Records<u32>) -> Option<Label> {
        let label = t.next_label()?;
        t.insert(label, 0, None, Credentials::NOBODY, 31, Join::Inherit);
        Some(label)
    }

    /// A child of `parent`, LOADING.
    fn loading(t: &mut Records<u32>, parent: Label) -> Label {
        let label = t.next_label().unwrap();
        let parent = Some(usize::from(parent.index));
        t.insert(label, 0, parent, Credentials::ROOT, 31, Join::Inherit);
        label
    }

    /// A child of `parent` that was loaded.
    fn child(t: &mut Records<u32>, parent: Label) -> Label {
        let label = loading(t, parent);
        t.get_mut(usize::from(label.index)).unwrap().state = State::Alive;
        label
    }

    /// The end of the process of `label`, through its exit place.
    fn end(t: &mut Records<u32>, label: Label, end: End) -> (Exit, Orphans) {
        let index = t.find_exit(label.exit()).expect("a live record");
        t.exited(index, end)
    }

    fn state(t: &Records<u32>, label: Label) -> Option<State> {
        t.find(label.raw()).map(|i| t.get(i).unwrap().state)
    }

    #[test]
    fn the_bound_is_records_and_an_ended_record_frees_its_index() {
        let mut t = Records::<u32>::new();
        let labels: Vec<Label> = (0..RECORDS).map(|_| add(&mut t).unwrap()).collect();
        assert_eq!(t.count(), RECORDS);
        assert_eq!(t.next_label(), None, "FULL with every record taken");
        let gone = labels[17];
        assert_eq!(end(&mut t, gone, End::Exited(0)).0, Exit::Reaped);
        assert_eq!(t.find_exit(gone.exit()), None, "a record goes once");
        assert_eq!(t.count(), RECORDS - 1);
        let next = add(&mut t).unwrap();
        assert_eq!(next.index, gone.index, "the index freed last comes first");
        assert_eq!(next.pid(), gone.pid() + RECORDS as u32, "one generation on");
        for label in labels.iter().filter(|l| **l != gone) {
            end(&mut t, *label, End::Exited(0));
        }
        end(&mut t, next, End::Exited(0));
        assert_eq!(t.count(), 0);
    }

    /// Only the exit label of a live record names it for its end: its
    /// session's label, the identity label, both place bits, a label of
    /// the gone generation and an index with no record name nothing.
    #[test]
    fn the_exit_label_alone_ends_a_record() {
        let mut t = Records::<u32>::new();
        let live = add(&mut t).unwrap();
        let stale = Label {
            generation: live.generation + 1,
            ..live
        };
        let free = Label {
            index: live.index + 1,
            ..live
        };
        for raw in [
            live.raw(),
            live.identity(),
            live.exit() | live.identity(),
            stale.exit(),
            free.exit(),
            0,
        ] {
            assert_eq!(t.find_exit(raw), None, "{raw:#x}");
        }
        assert_eq!(t.find(live.raw()), Some(usize::from(live.index)));
        assert_eq!(
            t.find(live.exit()),
            None,
            "no request through the exit place"
        );
        assert_eq!(end(&mut t, live, End::Exited(3)).0, Exit::Reaped);
        // A notification of the old generation after the index came back
        // names nothing.
        let next = add(&mut t).unwrap();
        assert_eq!(next.index, live.index);
        assert_eq!(t.find_exit(live.exit()), None);
        assert_eq!(t.find(next.raw()), Some(usize::from(next.index)));
    }

    /// The identity label names the record in the table, and only through
    /// its place: the work label does not name it, nor the old generation.
    #[test]
    fn the_identity_label_names_its_record_through_its_place() {
        let mut t = Records::<u32>::new();
        let live = add(&mut t).unwrap();
        let stale = Label {
            generation: live.generation + 1,
            ..live
        };
        assert_eq!(t.find_identity(live.identity()), Some(at(live)));
        assert_eq!(t.find(live.identity()), None, "no work through it");
        assert_eq!(t.find_identity(live.raw()), None);
        assert_eq!(t.find_identity(live.exit()), None);
        assert_eq!(t.find_identity(stale.identity()), None);
        end(&mut t, live, End::Exited(0));
        assert_eq!(
            t.find_identity(live.identity()),
            None,
            "gone with the record"
        );
    }

    #[test]
    fn labels_the_service_did_not_give_name_no_record() {
        let mut t = Records::<u32>::new();
        let live = add(&mut t).unwrap();
        let stale = Label {
            generation: live.generation + 1,
            ..live
        };
        assert_eq!(state(&t, live), Some(State::Loading));
        for raw in [0, 0x1234, stale.raw(), live.raw() | 1 << 62 | 1 << 61] {
            assert_eq!(t.find(raw), None, "{raw:#x}");
        }
        assert_eq!(t.find_pid(live.pid()), Some(usize::from(live.index)));
        assert_eq!(t.find_pid(stale.pid()), None);
        assert_eq!(t.find_pid(1), None);
    }

    /// The end of a process is heard at its ceiling, below the loop's
    /// level (40, the service of the tables) or above it.
    #[test]
    fn the_exit_place_is_at_the_ceiling_of_the_process() {
        let label = Label {
            index: 3,
            generation: 1,
        };
        for (ceiling, loop_level) in [(31, 40), (1, 40), (40, 40), (31, 52)] {
            let create = Create {
                quota: 64 * 4096,
                handle_limit: 16,
                ceiling,
                priority: ceiling,
                root: false,
                parent: 0,
            };
            let place = exit_place(label, &create, loop_level);
            assert_eq!(place.label, label.exit());
            assert_eq!(
                (place.slot, place.notice),
                (ceiling, ceiling),
                "{ceiling} {loop_level}"
            );
        }
    }

    /// A record has CHILDREN_MAX children at most, its zombies among
    /// them; a child taken by a wait frees its place, and one in the middle
    /// of the list leaves the others linked.
    #[test]
    fn a_record_has_children_max_children() {
        let mut t = Records::<u32>::new();
        let parent = add(&mut t).unwrap();
        let p = usize::from(parent.index);
        let children: Vec<Label> = (0..CHILDREN_MAX)
            .map(|_| {
                assert!(t.may_spawn(p));
                child(&mut t, parent)
            })
            .collect();
        assert!(!t.may_spawn(p), "the 33rd child is refused");
        assert_eq!(t.children(p).count(), CHILDREN_MAX as usize);
        for c in &children {
            let record = t.get(usize::from(c.index)).unwrap();
            assert_eq!(record.parent, parent.pid());
            assert_eq!(record.parent_index, Some(parent.index));
            assert_eq!((record.pgid, record.sid), (parent.pid(), parent.pid()));
        }
        let (exit, _) = end(&mut t, children[5], End::Exited(7));
        assert_eq!(exit, Exit::Zombie { parent: p });
        assert!(!t.may_spawn(p), "a zombie counts");
        assert!(t.reap(usize::from(children[5].index)).is_some());
        assert!(t.may_spawn(p), "a child that was taken frees its place");
        assert_eq!(t.children(p).count(), CHILDREN_MAX as usize - 1);
        for c in [children[31], children[0]] {
            end(&mut t, c, End::Exited(0));
            assert!(t.reap(usize::from(c.index)).is_some());
        }
        assert_eq!(t.children(p).count(), CHILDREN_MAX as usize - 3);
        assert_eq!(t.get(p).unwrap().children, CHILDREN_MAX - 3);
        assert!(
            t.reap(usize::from(children[1].index)).is_none(),
            "a live child stays"
        );
    }

    /// The zombie a wait takes: by PID, any, by group; a child of another
    /// record is none of the parent's, a LOADING child is none, and one
    /// that ended LOADING leaves no zombie.
    #[test]
    fn a_wait_finds_the_zombies_of_its_selector() {
        let mut t = Records::<u32>::new();
        let parent = add(&mut t).unwrap();
        let other = add(&mut t).unwrap();
        let p = usize::from(parent.index);
        let failed = loading(&mut t, parent);
        assert_eq!(
            t.zombie(p, Selector::Any),
            (None, false),
            "a LOADING child is none"
        );
        assert_eq!(end(&mut t, failed, End::Signaled(SIGKILL)).0, Exit::Reaped);
        assert_eq!(t.get(p).unwrap().children, 0);
        let a = child(&mut t, parent);
        let b = child(&mut t, parent);
        let foreign = child(&mut t, other);
        assert_eq!(t.zombie(p, Selector::Any), (None, true));
        assert_eq!(t.zombie(p, Selector::Pid(foreign.pid())), (None, false));
        end(&mut t, foreign, End::Exited(1));
        assert_eq!(
            t.zombie(p, Selector::Any),
            (None, true),
            "a foreign zombie is none"
        );
        end(&mut t, b, End::Signaled(SIGSEGV));
        let b_index = usize::from(b.index);
        assert_eq!(t.zombie(p, Selector::Any), (Some(b_index), true));
        assert_eq!(t.zombie(p, Selector::Pid(a.pid())), (None, true));
        assert_eq!(
            t.zombie(p, Selector::Group(parent.pid())),
            (Some(b_index), true)
        );
        assert_eq!(t.zombie(p, Selector::Group(999)), (None, false));
        assert_eq!(state(&t, b), Some(State::Zombie(End::Signaled(SIGSEGV))));
        assert!(t.reap(b_index).is_some());
        assert_eq!(
            t.zombie(p, Selector::Pid(b.pid())),
            (None, false),
            "taken: ECHILD"
        );
    }

    /// The children of a record whose process ended get PID 1: the live
    /// ones are orphans, the zombies go at once, and their later end
    /// leaves no zombie; a new record in the old index is no parent.
    #[test]
    fn the_children_of_an_ended_record_get_pid_1() {
        let mut t = Records::<u32>::new();
        let grand = add(&mut t).unwrap();
        let parent = child(&mut t, grand);
        let a = child(&mut t, parent);
        let b = child(&mut t, parent);
        end(&mut t, b, End::Exited(0));
        let (exit, orphans) = end(&mut t, parent, End::Exited(0));
        assert_eq!(
            exit,
            Exit::Zombie {
                parent: usize::from(grand.index)
            }
        );
        assert_eq!(orphans.as_slice(), [a.index]);
        assert_eq!(state(&t, b), None, "the zombie went with its parent's end");
        let record = t.get(usize::from(a.index)).unwrap();
        assert_eq!((record.parent, record.parent_index), (INIT_PID, None));
        assert_eq!(end(&mut t, a, End::Exited(0)).0, Exit::Reaped);
        assert!(t.reap(usize::from(parent.index)).is_some());
        let next = add(&mut t).unwrap();
        assert_eq!(t.children(usize::from(next.index)).count(), 0);
        assert_eq!(t.get(usize::from(grand.index)).unwrap().children, 0);
    }

    /// A child of `parent` in `join`, alive.
    fn child_in(t: &mut Records<u32>, parent: Label, join: Join) -> Label {
        let label = t.next_label().unwrap();
        let p = Some(usize::from(parent.index));
        t.insert(label, 0, p, Credentials::ROOT, 31, join);
        t.get_mut(usize::from(label.index)).unwrap().state = State::Alive;
        label
    }

    fn at(l: Label) -> usize {
        usize::from(l.index)
    }

    /// A table record leads a group and a session of its own PID; a child
    /// is in its parent's, or in a group or a session of its own PID.
    #[test]
    fn a_record_starts_in_a_group_and_a_session() {
        let mut t = Records::<u32>::new();
        let p = add(&mut t).unwrap();
        let a = child_in(&mut t, p, Join::Inherit);
        let b = child_in(&mut t, p, Join::NewGroup);
        let c = child_in(&mut t, p, Join::NewSession);
        let ids = |l: Label| {
            let r = t.get(at(l)).unwrap();
            (r.pgid, r.sid)
        };
        assert_eq!(ids(p), (p.pid(), p.pid()));
        assert_eq!(ids(a), (p.pid(), p.pid()));
        assert_eq!(ids(b), (b.pid(), p.pid()));
        assert_eq!(ids(c), (c.pid(), c.pid()));
        assert_eq!(t.members(p.pid()), 2);
        assert_eq!(t.members(b.pid()), 1);
        assert_eq!(t.session_of(b.pid()), Some(p.pid()));
        assert_eq!(t.session_of(c.pid()), Some(c.pid()));
        assert_eq!(t.members(999), 0);
        assert_eq!(t.orphaned(999), None);
    }

    /// XBD 3.247: a group is an orphan when no member has a parent in
    /// another group of its session. A table record's group is one (its
    /// parent is the service); a child group of a record of the same
    /// session is not, until its parent goes or leaves the session.
    #[test]
    fn a_group_is_an_orphan_when_no_parent_is_a_link() {
        let mut t = Records::<u32>::new();
        let p = add(&mut t).unwrap();
        let a = child_in(&mut t, p, Join::NewGroup);
        let session_child = child_in(&mut t, p, Join::NewSession);
        let grandchild = child_in(&mut t, a, Join::Inherit);
        assert_eq!(t.orphaned(p.pid()), Some(true), "its parent is the service");
        assert_eq!(
            t.orphaned(a.pid()),
            Some(false),
            "a's parent p is in another group"
        );
        assert_eq!(
            t.orphaned(session_child.pid()),
            Some(true),
            "p is in another session: no link"
        );
        // The parent goes: its child's link goes with it.
        end(&mut t, p, End::Exited(0));
        assert_eq!(t.orphaned(a.pid()), Some(true));
        assert_eq!(t.members(a.pid()), 2, "a and its child stay members");
        // The grandchild's parent is in its own group: no link either way.
        assert_eq!(t.orphaned(grandchild.pid()), None);
    }

    /// setpgid moves a record and recounts the links of its children: a
    /// child that shared its parent's group is linked once the parent
    /// leaves, and the old group, which had no link, is not an orphan.
    #[test]
    fn moving_a_parent_recounts_the_links_of_its_children() {
        let mut t = Records::<u32>::new();
        let p = add(&mut t).unwrap();
        let mid = child_in(&mut t, p, Join::Inherit);
        let kid = child_in(&mut t, mid, Join::Inherit);
        assert_eq!(t.orphaned(p.pid()), Some(true));
        assert_eq!(t.set_pgid(at(mid), 0, 0), Ok(()));
        assert_eq!(t.get(at(mid)).unwrap().pgid, mid.pid());
        assert_eq!(
            t.orphaned(mid.pid()),
            Some(false),
            "mid's parent p is a link"
        );
        assert_eq!(
            t.orphaned(p.pid()),
            Some(false),
            "kid's parent mid left the group"
        );
        assert_eq!((t.members(p.pid()), t.members(mid.pid())), (2, 1));
        // The child follows its parent into the group, no link left.
        assert_eq!(t.set_pgid(at(kid), 0, mid.pid()), Ok(()));
        assert_eq!(t.orphaned(p.pid()), Some(true));
        assert_eq!(t.orphaned(mid.pid()), Some(false));
        assert_eq!(t.members(mid.pid()), 2);
        // A zombie member links nothing: mid ends, kid goes to the service.
        end(&mut t, mid, End::Exited(0));
        assert_eq!(t.orphaned(mid.pid()), Some(true));
    }

    /// The PID of a group's leader is not given again while a member
    /// lives, and the place stays held after the leader is gone.
    #[test]
    fn the_pid_of_a_leader_is_held_while_a_member_lives() {
        let mut t = Records::<u32>::new();
        let p = add(&mut t).unwrap();
        let leader = child_in(&mut t, p, Join::NewGroup);
        let member = child_in(&mut t, leader, Join::Inherit);
        assert_eq!(member_group(&t, member), leader.pid());
        end(&mut t, leader, End::Exited(0));
        assert!(t.reap(at(leader)).is_some());
        assert_eq!(t.find_pid(leader.pid()), None, "the record is gone");
        assert!(t.held(leader.pid()), "the group still carries the number");
        assert_eq!(t.members(leader.pid()), 1);
        // Every index but the held ones can be taken: the held place is
        // never the next, and PIDs of its index never come back.
        let mut taken = Vec::new();
        while let Some(label) = t.next_label() {
            assert_ne!(label.index, leader.index, "a held place is not given");
            taken.push(add(&mut t).unwrap());
        }
        assert_eq!(
            taken.len(),
            RECORDS - 3,
            "p, the held place and its member are taken"
        );
        for l in taken {
            end(&mut t, l, End::Exited(0));
        }
        // The last member goes: the place is free, one generation on.
        end(&mut t, member, End::Exited(0));
        assert!(!t.held(leader.pid()));
        // Its index is among the free ones now, one generation on.
        let again = (0..RECORDS).find_map(|_| {
            let label = add(&mut t)?;
            (label.index == leader.index).then_some(label)
        });
        assert_eq!(again.map(|l| l.generation), Some(leader.generation + 1));
    }

    fn member_group(t: &Records<u32>, l: Label) -> u32 {
        t.get(at(l)).unwrap().pgid
    }

    /// A session's number is held by its members too: the leader's place
    /// is not free while a record is in the session.
    #[test]
    fn the_pid_of_a_session_leader_is_held_while_its_session_lives() {
        let mut t = Records::<u32>::new();
        let p = add(&mut t).unwrap();
        let leader = child_in(&mut t, p, Join::NewSession);
        let member = child_in(&mut t, leader, Join::Inherit);
        end(&mut t, leader, End::Exited(0));
        t.reap(at(leader));
        assert!(t.held(leader.pid()));
        // The member is also in the group that has the leader's number.
        assert_eq!(t.members(leader.pid()), 1);
        assert_eq!(t.set_sid(at(member)), Ok(member.pid()));
        assert!(
            !t.held(leader.pid()),
            "no member of group or session is left"
        );
        assert!(t.held(member.pid()));
    }

    /// setpgid by the numbers of [P24-SETPGID].
    #[test]
    fn setpgid_refuses_by_the_posix_rules() {
        let mut t = Records::<u32>::new();
        let p = add(&mut t).unwrap();
        let other = add(&mut t).unwrap();
        let a = child_in(&mut t, p, Join::Inherit);
        let b = child_in(&mut t, p, Join::NewSession);
        let loading = loading(&mut t, p);
        let g = child_in(&mut t, a, Join::Inherit);
        assert_eq!(
            t.set_pgid(at(p), 0, 0),
            Err(GroupError::Permission),
            "a session leader"
        );
        assert_eq!(
            t.set_pgid(at(p), a.pid(), a.pid()),
            Err(GroupError::Access),
            "a child has started"
        );
        assert_eq!(
            t.set_pgid(at(p), b.pid(), 0),
            Err(GroupError::Permission),
            "a child of another session"
        );
        assert_eq!(
            t.set_pgid(at(p), g.pid(), 0),
            Err(GroupError::NoProcess),
            "a grandchild"
        );
        assert_eq!(
            t.set_pgid(at(p), other.pid(), 0),
            Err(GroupError::NoProcess),
            "no child"
        );
        assert_eq!(
            t.set_pgid(at(p), loading.pid(), 0),
            Err(GroupError::NoProcess),
            "not started"
        );
        assert_eq!(t.set_pgid(at(p), 999_999, 0), Err(GroupError::NoProcess));
        assert_eq!(
            t.set_pgid(at(a), 0, other.pid()),
            Err(GroupError::Permission),
            "a group of another session"
        );
        assert_eq!(
            t.set_pgid(at(a), 0, 12_345),
            Err(GroupError::Permission),
            "no such group"
        );
        assert_eq!(
            t.set_pgid(at(a), a.pid(), a.pid()),
            Ok(()),
            "itself, by PID"
        );
        assert_eq!(member_group(&t, a), a.pid());
        // g joins a's group by a new group of the same session: its parent's.
        assert_eq!(t.set_pgid(at(g), 0, a.pid()), Ok(()));
        assert_eq!(
            t.set_pgid(at(g), 0, p.pid()),
            Ok(()),
            "back to the first group"
        );
        assert_eq!(t.set_pgid(at(g), 0, 0), Ok(()));
        assert_eq!(member_group(&t, g), g.pid());
        assert_eq!(t.members(a.pid()), 1);
    }

    /// setsid: a new session and group of the caller's PID, EPERM for a
    /// leader of a group; getpgid and getsid see every record, a zombie too.
    #[test]
    fn setsid_and_the_getters() {
        let mut t = Records::<u32>::new();
        let p = add(&mut t).unwrap();
        let a = child_in(&mut t, p, Join::Inherit);
        let b = child_in(&mut t, p, Join::NewGroup);
        assert_eq!(
            t.set_sid(at(p)),
            Err(GroupError::Permission),
            "p leads a group"
        );
        assert_eq!(
            t.set_sid(at(b)),
            Err(GroupError::Permission),
            "b leads a group"
        );
        assert_eq!(t.set_sid(at(a)), Ok(a.pid()));
        assert_eq!(t.sid_of(at(a), 0), Some(a.pid()));
        assert_eq!(t.pgid_of(at(a), 0), Some(a.pid()));
        assert_eq!(t.sid_of(at(p), a.pid()), Some(a.pid()));
        assert_eq!(t.pgid_of(at(p), b.pid()), Some(b.pid()));
        assert_eq!(t.sid_of(at(p), 0), Some(p.pid()));
        assert_eq!(t.members(p.pid()), 1, "a left p's group");
        assert_eq!(t.set_sid(at(a)), Err(GroupError::Permission), "a leads now");
        end(&mut t, b, End::Exited(0));
        assert_eq!(
            t.pgid_of(at(p), b.pid()),
            Some(b.pid()),
            "a zombie keeps its group"
        );
        assert_eq!(t.pgid_of(at(p), 999_999), None);
        let loading = loading(&mut t, p);
        assert_eq!(
            t.pgid_of(at(p), loading.pid()),
            None,
            "a LOADING record is none"
        );
    }

    /// setsid of a former group leader: its group lives on with a member,
    /// so the number is taken (EPERM), whatever group the caller is in now.
    #[test]
    fn setsid_of_a_leader_whose_group_lives_on() {
        let mut t = Records::<u32>::new();
        let p = add(&mut t).unwrap();
        let b = child_in(&mut t, p, Join::NewGroup);
        let _member = child_in(&mut t, p, Join::Group(b.pid()));
        assert_eq!(t.set_pgid(at(b), 0, p.pid()), Ok(()), "b leaves its group");
        assert_eq!(t.members(b.pid()), 1);
        assert_eq!(t.set_sid(at(b)), Err(GroupError::Permission));
    }

    /// Spawn's group flags: a group of its own, an existing group of the
    /// parent's session, its own session; both flags and a group of
    /// another session or none are refused.
    #[test]
    fn spawn_flags_choose_the_group_and_session() {
        let mut t = Records::<u32>::new();
        let p = add(&mut t).unwrap();
        let other = add(&mut t).unwrap();
        let a = child_in(&mut t, p, Join::NewGroup);
        let (pi, own) = (at(p), 777);
        let (group, sess) = (SPAWN_SETPGROUP, SPAWN_SETSID);
        assert_eq!(t.joining(pi, 0, 5, own), Some(Join::Inherit));
        assert_eq!(t.joining(pi, group, 0, own), Some(Join::NewGroup));
        assert_eq!(t.joining(pi, group, own, own), Some(Join::NewGroup));
        assert_eq!(
            t.joining(pi, group, a.pid(), own),
            Some(Join::Group(a.pid()))
        );
        assert_eq!(
            t.joining(pi, group, other.pid(), own),
            None,
            "another session"
        );
        assert_eq!(t.joining(pi, group, 4242, own), None, "no such group");
        assert_eq!(t.joining(pi, sess, 0, own), Some(Join::NewSession));
        assert_eq!(t.joining(pi, sess | group, 0, own), None);
    }
}
