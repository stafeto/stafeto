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
    Selector, WCONTINUED, WEXITED, WSTOPPED, WaitResult,
};

/// The children of one record at most, its zombies among them, until
/// RLIMIT_NPROC (5b design, question 3): Spawn past them is EAGAIN. The
/// probe of POSIX processes reaches it with children from files (5c).
pub const CHILDREN_MAX: u32 = 32;

/// Where a record is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Created; one of the service's threads loads its program.
    Loading,
    /// Loaded and started.
    Alive,
    /// Its process ended so; the record waits for its parent's wait.
    Zombie(End),
    /// Native death revoked authority; ownership waits for ACK/cleanup.
    EndPendingLoading(Option<End>),
    EndPendingAlive(Option<End>),
    /// One resident journal drains the exact image before Zombie/reuse.
    EndingLoading(End),
    EndingAlive(End),
}
impl State {
    pub const fn end_pending(self) -> bool {
        matches!(
            self,
            Self::EndPendingLoading(_)
                | Self::EndPendingAlive(_)
                | Self::EndingLoading(_)
                | Self::EndingAlive(_)
        )
    }
    pub const fn live(self) -> bool {
        matches!(self, Self::Loading | Self::Alive)
    }
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

pub struct Record<P, C = ()> {
    /// Its process, which the service created and calls with later.
    pub process: P,
    /// Exact private executable custody through native process death.
    pub active_exec: Option<C>,
    pub label: Label,
    /// The PID of its parent: INIT_PID for a record of init's table and
    /// for an orphan.
    pub parent: u32,
    pub credentials: Credentials,
    pub groups: proto_process::Groups,
    pub limits: proto_process::ResourceLimits,
    pub root: proto_process::ExpenditureRoot,
    pub state: State,
    /// Suspension is independent of image loading and process lifetime.
    pub stopped: Option<u8>,
    pub stop_epoch: u64,
    pub cont_epoch: u64,
    stop_report: Option<u8>,
    cont_report: bool,
    first_ready: Option<u16>,
    ready_previous: Option<u16>,
    ready_next: Option<u16>,
    ready: bool,
    /// The ceiling of its process.
    pub ceiling: u8,
    /// The quota and the room for handles of its process, which a child
    /// it spawns from a file gets too (5c).
    pub quota: u64,
    pub handle_limit: u32,
    /// The image number of its process: IMAGE, then that of each exec
    /// that committed (5c). Its session, exit place and identity carry it.
    pub image: u32,
    /// The last image number an exec of the record took, committed or
    /// not: the next exec takes one more, so no number names two attempts.
    pub tried: u32,
    /// Initial full epoch or successful loader ticket, retained after Take.
    image_origin: u64,
    pub source_origin: crate::initial_origin::SourceOrigin,
    pub active_guard_label: u64,
    #[cfg(feature = "image-probe")]
    pub image_probe: crate::image_probe::Observation,
    /// Its process group and session: those of its parent, or its own PID
    /// for a record of init's table.
    pub pgid: u32,
    pub sid: u32,
    pub ctty: Option<(u32, u64)>,
    /// The index of its parent's record while the parent lives.
    pub parent_index: Option<u16>,
    /// Whether it counts in `Numbers::links` of its group: its parent is
    /// in another group of its session.
    linked: bool,
    /// Whether its process ran a program of its own: SpawnCommit (the
    /// child of posix_spawn starts with its file) and ExecCommit set it,
    /// ForkCommit does not ([P24-SETPGID]: EACCES for a child that did).
    pub execed: bool,
    /// Its live children, and the first of their list.
    pub children: u32,
    first_child: Option<u16>,
    /// Its neighbours in the list of its parent's children.
    previous: Option<u16>,
    next: Option<u16>,
}

impl<P, C> Record<P, C> {
    pub fn loader_ticket(&self, initial_ticket: u64) -> Option<u64> {
        (!(self.image == proto_process::IMAGE && initial_ticket != 0)).then_some(self.image_origin)
    }
    pub fn initial_origin(
        &self,
        initial_ticket: u64,
    ) -> Option<crate::initial_origin::InitialOrigin> {
        (self.image == proto_process::IMAGE && initial_ticket != 0)
            .then(|| self.source_origin.initial_origin())
            .flatten()
    }
    pub fn set_initial_origin(
        &mut self,
        initial_ticket: u64,
        origin: crate::initial_origin::InitialOrigin,
    ) -> bool {
        self.image == proto_process::IMAGE
            && initial_ticket != 0
            && self.source_origin.set_initial_origin(origin)
    }
    pub fn initial_epoch(&self, initial_ticket: u64) -> Option<u64> {
        self.initial_origin(initial_ticket)
            .map(|_| self.image_origin)
    }
    pub fn set_initial_epoch(&mut self, initial_ticket: u64, epoch: u64) -> bool {
        if self.initial_origin(initial_ticket).is_none() || epoch == 0 || self.image_origin != 0 {
            return false;
        }
        self.image_origin = epoch;
        true
    }
    pub fn matches_initial_ack(
        &self,
        initial_ticket: u64,
        ack: proto_process::initial_ack::Ack,
    ) -> bool {
        self.initial_epoch(initial_ticket) == Some(ack.epoch)
            && initial_ticket == ack.ticket
            && ack.label == self.label.raw_at(self.image)
            && ack.receipt
                == proto_process::initial_map::Receipt {
                    key: proto_process::initial_map::Key {
                        key: initial_ticket,
                        image: self.image,
                    },
                    label: self.label.raw_at(self.image),
                    pid: self.label.pid(),
                    init_ticket: initial_ticket,
                }
    }
    pub fn initial_ack_replay_matches(
        &self,
        initial_ticket: u64,
        ack: proto_process::initial_ack::Ack,
    ) -> bool {
        self.matches_initial_ack(initial_ticket, ack)
            && self
                .initial_origin(initial_ticket)
                .is_some_and(|origin| origin.flags & crate::initial_origin::INIT_ACKED != 0)
    }
    pub fn set_loader_ticket(&mut self, ticket: u64) {
        self.source_origin.clear_initial_flags();
        self.image_origin = ticket;
    }
}

pub struct Records<P, C = ()> {
    records: [Option<Record<P, C>>; RECORDS],
    /// The last generation each index gave, 0 for none.
    generations: [u32; RECORDS],
    /// The free indices, the last freed on top.
    free: [u16; RECORDS],
    free_len: usize,
    /// A reservation keeps its index unavailable before a process is inserted.
    slots: [SlotState; RECORDS],
    /// The group and the session each place's PID names.
    numbers: [Numbers; RECORDS],
    orphaned: crate::queue::Queue,
}

/// The fixed record indices carry one authoritative lifecycle byte each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum SlotState {
    Free,
    Reserved,
    Used,
    Retired,
    Retaining,
}

/// Exact removed row remains unavailable until its resident caps settle.
#[derive(Debug, PartialEq, Eq)]
pub struct Retirement {
    key: crate::preparing::Key,
}
impl Retirement {
    pub const fn key(&self) -> crate::preparing::Key {
        self.key
    }
}

pub type RetainedRecord<P, C> = (Record<P, C>, Retirement);
pub struct EndMetadata<P, C> {
    pub exit: Exit,
    pub retired: Option<RetainedRecord<P, C>>,
}

/// Exclusive ownership of one prepaid record index and its issued generation.
/// The caller consumes or cancels it before discarding its resident preparation.
#[derive(Debug, PartialEq, Eq)]
pub struct Reservation {
    label: Label,
}
impl Reservation {
    pub const fn label(&self) -> Label {
        self.label
    }
}

/// A parent snapshot names one image and its captured group/session namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartParent {
    label: Label,
    image: u32,
    pgid: u32,
    sid: u32,
}
impl StartParent {
    pub const fn label(&self) -> Label {
        self.label
    }
    pub const fn image(&self) -> u32 {
        self.image
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumeError {
    Stale,
    Parent,
    Group,
}

/// Failed publication retains both the paid reservation and the process.
pub struct ConsumeRefused<P> {
    pub reservation: Reservation,
    pub process: P,
    pub error: ConsumeError,
}

/// What a place keeps of the group and the session its PID names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Numbers {
    /// The records whose group it is, zombies too.
    members: u16,
    stopped: u16,
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

impl<P, C> Default for Records<P, C> {
    fn default() -> Self {
        Self::with_exec_custody()
    }
}

impl<P> Records<P> {
    /// Construct records with the legacy value-only executable custody.
    pub const fn new() -> Self {
        Self::with_exec_custody()
    }
}

impl<P, C> Records<P, C> {
    /// The credentials effect is admitted before a generation can become terminal.
    pub fn change_credentials(
        &mut self,
        index: usize,
        operation: proto_process::Change,
        id: u32,
        generation: u64,
    ) -> Result<(), u32> {
        if generation & proto_process::GENERATION_DEAD != 0 {
            return Err(proto_process::NO_PROCESS);
        }
        if !proto_process::generation_room(generation, 1) {
            return Err(proto_process::AGAIN);
        }
        let record = self.get_mut(index).ok_or(proto_process::NO_PROCESS)?;
        if !record.state.live() {
            return Err(proto_process::NO_PROCESS);
        }
        let next =
            posix_credentials::change(record.credentials, operation, id).map_err(|e| match e {
                posix_credentials::Error::Invalid => proto_process::INVALID,
                posix_credentials::Error::Permission => proto_process::PERMISSION,
            })?;
        record.credentials = next;
        Ok(())
    }
    /// No record, every index free, index 0 on top.
    pub const fn with_exec_custody() -> Self {
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
            slots: [SlotState::Free; RECORDS],
            numbers: [Numbers {
                members: 0,
                stopped: 0,
                links: 0,
                sessions: 0,
                session: 0,
            }; RECORDS],
            orphaned: crate::queue::Queue::new(),
        }
    }

    /// The index of the live record that `raw` names in `place`: a
    /// session, an exit place and an identity of its present image, a
    /// loader of any (the service checks the image of its place). A copy
    /// of an old image's identity vouches for nothing after the exec.
    fn named(&self, raw: u64, place: Place) -> Option<usize> {
        let (label, got, image) = Label::parse_image(raw)?;
        let index = usize::from(label.index);
        let any_image = place == Place::Loader;
        (got == place
            && self.records[index].as_ref().is_some_and(|r| {
                r.label == label && (any_image || r.image == image) && !r.state.end_pending()
            }))
        .then_some(index)
    }

    /// The label of the session of the record in `index`, of its present
    /// image.
    pub fn session_label(&self, index: usize) -> Option<u64> {
        let r = self.get(index)?;
        Some(r.label.raw_at(r.image))
    }

    /// The index of the record whose session has `label`, if it lives.
    pub fn find(&self, label: u64) -> Option<usize> {
        self.named(label, Place::Work)
    }

    pub fn get(&self, index: usize) -> Option<&Record<P, C>> {
        self.records.get(index)?.as_ref()
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Record<P, C>> {
        self.records.get_mut(index)?.as_mut()
    }

    /// Replace custody only with a successful, already prepaid image commit.
    pub fn replace_active_exec(&mut self, index: usize, cap: Option<C>) -> Option<C> {
        core::mem::replace(
            &mut self.get_mut(index).expect("a committed record").active_exec,
            cap,
        )
    }

    pub fn take_active_exec(&mut self, index: usize) -> Option<C> {
        self.get_mut(index)?.active_exec.take()
    }

    /// The unavailable places: records, live group/session numbers and
    /// permanently retired indices whose label generation is exhausted.
    pub fn count(&self) -> usize {
        RECORDS - self.free_len
    }

    /// The label the next record gets: the free index on top, one
    /// generation on. None with every record taken (FULL).
    pub fn next_label(&self) -> Option<Label> {
        let index = *self.free[..self.free_len].last()?;
        Some(Label {
            index,
            generation: Label::next_generation(self.generations[usize::from(index)])?,
        })
    }

    /// Retire one free index whose credentials generation cannot admit a load.
    /// A later request considers the next index; this refusal remains O(1).
    pub fn retire_next(&mut self, label: Label) {
        assert_eq!(self.next_label(), Some(label));
        let index = usize::from(label.index);
        self.free_len -= 1;
        self.slots[index] = SlotState::Retired;
        self.generations[index] = proto_process::GENERATION_MAX;
    }

    /// Burn one label generation and remove its slot from the free list.
    pub fn reserve_next(&mut self) -> Option<Reservation> {
        let label = self.next_label()?;
        let index = usize::from(label.index);
        assert_eq!(self.slots[index], SlotState::Free);
        self.free_len -= 1;
        self.slots[index] = SlotState::Reserved;
        self.generations[index] = label.generation;
        Some(Reservation { label })
    }

    fn exact_reservation(&self, reservation: &Reservation) -> bool {
        let label = reservation.label;
        let index = usize::from(label.index);
        index < RECORDS
            && self.slots[index] == SlotState::Reserved
            && self.generations[index] == label.generation
            && self.records[index].is_none()
    }

    /// Cleanup uses the issued generation and needs no new admission.
    pub fn cancel_reserved(&mut self, reservation: Reservation) -> Result<(), Reservation> {
        if !self.exact_reservation(&reservation) {
            return Err(reservation);
        }
        let index = usize::from(reservation.label.index);
        self.slots[index] = SlotState::Used;
        self.settle(index);
        Ok(())
    }

    pub fn start_parent(&self, index: usize) -> Option<StartParent> {
        let record = self.get(index)?;
        (record.state == State::Alive).then_some(StartParent {
            label: record.label,
            image: record.image,
            pgid: record.pgid,
            sid: record.sid,
        })
    }

    /// The native caller checks its captured credentials generation before this call.
    /// Every refusal returns the caller's existing ownership for bounded cleanup.
    pub fn consume_reserved(
        &mut self,
        reservation: Reservation,
        process: P,
        parent: Option<StartParent>,
        credentials: Credentials,
        ceiling: u8,
        join: Join,
    ) -> Result<usize, ConsumeRefused<P>> {
        let fail = if !self.exact_reservation(&reservation) {
            Some(ConsumeError::Stale)
        } else if let Some(parent) = parent {
            let index = usize::from(parent.label.index);
            if self.start_parent(index) != Some(parent) || !self.may_spawn(index) {
                Some(ConsumeError::Parent)
            } else {
                let (flags, group) = match join {
                    Join::Inherit => (0, 0),
                    Join::NewGroup => (SPAWN_SETPGROUP, reservation.label.pid()),
                    Join::Group(group) => (SPAWN_SETPGROUP, group),
                    Join::NewSession => (SPAWN_SETSID, 0),
                };
                (self.joining(index, flags, group, reservation.label.pid()) != Some(join))
                    .then_some(ConsumeError::Group)
            }
        } else {
            None
        };
        if let Some(error) = fail {
            return Err(ConsumeRefused {
                reservation,
                process,
                error,
            });
        }
        Ok(self.insert_consumed(
            reservation.label,
            process,
            parent.map(|p| usize::from(p.label.index)),
            credentials,
            ceiling,
            join,
        ))
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
        let reservation = self.reserve_next().expect("the next record slot");
        self.insert_consumed(
            reservation.label,
            process,
            parent,
            credentials,
            ceiling,
            join,
        )
    }

    fn insert_consumed(
        &mut self,
        label: Label,
        process: P,
        parent: Option<usize>,
        credentials: Credentials,
        ceiling: u8,
        join: Join,
    ) -> usize {
        let i = usize::from(label.index);
        assert_eq!(self.slots[i], SlotState::Reserved);
        assert_eq!(self.generations[i], label.generation);
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
        self.slots[i] = SlotState::Used;
        let linked = parent.is_some_and(|p| self.separates(p, pgid, sid));
        let groups = parent.map_or(proto_process::Groups::EMPTY, |p| {
            self.records[p].as_ref().unwrap().groups
        });
        let limits = parent.map_or(proto_process::ResourceLimits::initial(0), |p| {
            self.records[p].as_ref().unwrap().limits
        });
        let root = parent.map_or(
            proto_process::ExpenditureRoot {
                pid: label.pid(),
                generation: label.generation,
            },
            |p| self.records[p].as_ref().unwrap().root,
        );
        self.records[i] = Some(Record {
            process,
            active_exec: None,
            label,
            parent: pid,
            credentials,
            groups,
            limits,
            root,
            state: State::Loading,
            stopped: None,
            stop_epoch: 0,
            cont_epoch: 0,
            stop_report: None,
            cont_report: false,
            first_ready: None,
            ready_previous: None,
            ready_next: None,
            ready: false,
            ceiling,
            quota: 0,
            handle_limit: 0,
            image: proto_process::IMAGE,
            tried: proto_process::IMAGE,
            image_origin: 0,
            source_origin: parent.map_or(crate::initial_origin::SourceOrigin::UNKNOWN, |p| {
                self.records[p].as_ref().unwrap().source_origin.inherited()
            }),
            active_guard_label: 0,
            #[cfg(feature = "image-probe")]
            image_probe: crate::image_probe::Observation::default(),
            pgid,
            sid,
            ctty: None,
            parent_index: parent.map(|p| p as u16),
            linked,
            execed: false,
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
        self.mark_orphan(group, linked);
        self.numbers[session].sessions -= 1;
        self.settle(group);
        self.settle(session);
    }

    /// The place in `index` goes to the free ones when no record is in it
    /// and no group or session carries its number.
    fn settle(&mut self, index: usize) {
        if self.records[index].is_none()
            && self.numbers[index].unused()
            && self.slots[index] == SlotState::Used
        {
            self.orphaned.remove(index);
            if Label::next_generation(self.generations[index]).is_none() {
                self.slots[index] = SlotState::Retired;
                return;
            }
            self.slots[index] = SlotState::Free;
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
            return self
                .get(caller)
                .filter(|record| !record.state.end_pending())
                .map(|_| caller);
        }
        self.find_pid(pid).filter(|&t| {
            self.records[t]
                .as_ref()
                .is_some_and(|r| r.state != State::Loading && !r.state.end_pending())
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
    /// caller or one of its children, a zombie among them (ESRCH
    /// otherwise; 0 is the caller), `pgid` 0 means the target's own PID. A
    /// child that ran a program of its own (`execed`: posix_spawn or exec)
    /// is EACCES, one of another session or a leader of its session EPERM;
    /// a child of fork otherwise moves as the caller does. The target,
    /// unless it leads its session (EPERM), joins the group `pgid` of the
    /// caller's session, which is the target's own, new or not (EPERM for
    /// any other group of another session or none). The links of the
    /// target and of its children are counted anew: CHILDREN_MAX steps.
    /// A child that execed in another session gets EACCES: POSIX gives the
    /// errors no order, and Linux checks the session first (EPERM).
    pub fn set_pgid(&mut self, caller: usize, pid: u32, pgid: u32) -> Result<(), GroupError> {
        if self
            .get(caller)
            .is_none_or(|record| record.state.end_pending())
        {
            return Err(GroupError::NoProcess);
        }
        let me = self.records[caller].as_ref().expect("the caller");
        let (own, sid) = (me.label.pid(), me.sid);
        let target = if pid != 0 && pid != own {
            let child = self
                .target(caller, pid)
                .filter(|&t| {
                    self.records[t]
                        .as_ref()
                        .is_some_and(|r| r.parent_index == Some(caller as u16))
                })
                .ok_or(GroupError::NoProcess)?;
            let r = self.records[child].as_ref().expect("a child");
            if r.execed {
                return Err(GroupError::Access);
            }
            if r.sid != sid {
                return Err(GroupError::Permission);
            }
            child
        } else {
            caller
        };
        let record = self.records[target].as_ref().expect("the target");
        let (pid, current) = (record.label.pid(), record.pgid);
        if record.sid == pid {
            return Err(GroupError::Permission);
        }
        let pgid = if pgid == 0 { pid } else { pgid };
        if pgid != pid && self.session_of(pgid) != Some(sid) {
            return Err(GroupError::Permission);
        }
        if current != pgid {
            self.regroup(target, pgid, sid);
        }
        Ok(())
    }

    /// setsid ([P24-SETSID]) for the record in `caller`: a session and a
    /// group of its own PID, which it returns; EPERM when a group already
    /// has that number, that is when the caller leads one.
    pub fn set_sid(&mut self, caller: usize) -> Result<u32, GroupError> {
        if self
            .get(caller)
            .is_none_or(|record| record.state.end_pending())
        {
            return Err(GroupError::NoProcess);
        }
        let own = self.records[caller]
            .as_ref()
            .expect("the caller")
            .label
            .pid();
        if self.members(own) > 0 {
            return Err(GroupError::Permission);
        }
        self.records[caller].as_mut().expect("caller").ctty = None;
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
        let stopped = record.stopped.is_some();
        self.enter(pgid, sid, linked);
        if stopped {
            let old = self.place_of(old_pgid).expect("the old group");
            let new = self.place_of(pgid).expect("the new group");
            self.numbers[old].stopped -= 1;
            self.numbers[new].stopped += 1;
        }
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
                self.mark_orphan(place, c_linked && !now);
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

    /// The index of the record whose loader's session or identity has
    /// `label`, while the record is in the table.
    pub fn find_loader(&self, label: u64) -> Option<usize> {
        self.named(label, Place::Loader)
    }

    /// The index of the record whose exit place of any image has `label`
    /// and that image, while its process lives (an exec's old process or
    /// new one, 5c). O(1).
    pub fn find_exit_any(&self, label: u64) -> Option<(usize, u32)> {
        let (named, place, image) = Label::parse_image(label)?;
        let index = usize::from(named.index);
        let record = self.records[index].as_ref()?;
        (place == Place::Exit && record.label == named && !matches!(record.state, State::Zombie(_)))
            .then_some((index, image))
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
        self.records[usize::from(index)]
            .as_ref()
            .is_some_and(|r| r.label == label)
            .then_some(usize::from(index))
    }

    /// Mark native death without releasing its namespace or any owner.
    /// None preserves an unknown reason; the first known reason wins.
    pub fn mark_end_pending(&mut self, key: crate::preparing::Key, reason: Option<End>) -> bool {
        let Some(record) = self.get_mut(usize::from(key.label.index)) else {
            return false;
        };
        if record.label != key.label || record.image != key.image {
            return false;
        }
        let first = match record.state {
            State::Loading | State::Alive => {
                record.state = if record.state == State::Alive {
                    State::EndPendingAlive(reason)
                } else {
                    State::EndPendingLoading(reason)
                };
                true
            }
            State::EndPendingLoading(None) | State::EndPendingAlive(None) if reason.is_some() => {
                record.state = if matches!(record.state, State::EndPendingAlive(_)) {
                    State::EndPendingAlive(reason)
                } else {
                    State::EndPendingLoading(reason)
                };
                false
            }
            _ => false,
        };
        if first {
            self.ready_remove(usize::from(key.label.index));
        }
        first
    }

    pub fn end_reason(&self, key: crate::preparing::Key) -> Option<End> {
        let record = self.get(usize::from(key.label.index))?;
        if record.label != key.label || record.image != key.image {
            return None;
        }
        match record.state {
            State::EndPendingLoading(reason) | State::EndPendingAlive(reason) => reason,
            State::EndingLoading(reason) | State::EndingAlive(reason) => Some(reason),
            _ => None,
        }
    }

    /// CPU-only ownership transfer. The caller pays one close outside.
    pub fn begin_end_retained(&mut self, key: crate::preparing::Key) -> Option<Option<C>> {
        let index = usize::from(key.label.index);
        let record = self.get_mut(index)?;
        if record.label != key.label || record.image != key.image {
            return None;
        }
        record.state = match record.state {
            State::EndPendingLoading(Some(reason)) => State::EndingLoading(reason),
            State::EndPendingAlive(Some(reason)) => State::EndingAlive(reason),
            _ => return None,
        };
        Some(record.active_exec.take())
    }

    pub fn ending_child(&self, key: crate::preparing::Key) -> Option<crate::preparing::Key> {
        let record = self.get(usize::from(key.label.index))?;
        if record.label != key.label
            || record.image != key.image
            || !matches!(
                record.state,
                State::EndingLoading(_) | State::EndingAlive(_)
            )
        {
            return None;
        }
        let child = self.get(usize::from(record.first_child?))?;
        Some(crate::preparing::Key {
            label: child.label,
            image: child.image,
        })
    }

    /// Remove one live sibling head without touching capability owners.
    pub fn orphan_ending_child(
        &mut self,
        parent: crate::preparing::Key,
        child: crate::preparing::Key,
    ) -> bool {
        if self.ending_child(parent) != Some(child) {
            return false;
        }
        let index = usize::from(child.label.index);
        let record = self.get_mut(index).expect("the checked child");
        if !record.state.live() {
            return false;
        }
        let next = record.next;
        let (pgid, linked) = (record.pgid, core::mem::take(&mut record.linked));
        record.parent = INIT_PID;
        record.parent_index = None;
        record.previous = None;
        record.next = None;
        self.ready_remove(index);
        self.unlink(pgid, linked);
        let parent = self
            .get_mut(usize::from(parent.label.index))
            .expect("the ending parent");
        parent.first_child = next;
        parent.children -= 1;
        if let Some(next) = next {
            self.get_mut(usize::from(next))
                .expect("the next sibling")
                .previous = None;
        }
        true
    }

    /// Detach one complete Zombie, withholding its slot across close.
    pub fn reap_retained(&mut self, key: crate::preparing::Key) -> Option<RetainedRecord<P, C>> {
        let index = usize::from(key.label.index);
        let record = self.get(index)?;
        if record.label != key.label
            || record.image != key.image
            || !matches!(record.state, State::Zombie(_))
        {
            return None;
        }
        self.slots[index] = SlotState::Retaining;
        let record = self.reap(index).expect("the checked complete zombie");
        Some((record, Retirement { key }))
    }

    /// No capability effects. Only the holder of the exact token releases.
    pub fn release_retained(&mut self, token: Retirement) -> Result<(), Retirement> {
        let index = usize::from(token.key.label.index);
        if self.slots[index] != SlotState::Retaining
            || self.generations[index] != token.key.label.generation
            || self.records[index].is_some()
        {
            return Err(token);
        }
        self.slots[index] = SlotState::Used;
        self.settle(index);
        Ok(())
    }

    /// Final CPU metadata after every child and executable owner settled.
    /// A no-parent record is returned, never implicitly dropped here.
    pub fn finish_end_metadata(&mut self, key: crate::preparing::Key) -> Option<EndMetadata<P, C>> {
        let index = usize::from(key.label.index);
        let record = self.get(index)?;
        if record.label != key.label
            || record.image != key.image
            || record.children != 0
            || record.first_child.is_some()
            || record.active_exec.is_some()
        {
            return None;
        }
        let (reason, loaded) = match record.state {
            State::EndingLoading(reason) => (reason, false),
            State::EndingAlive(reason) => (reason, true),
            _ => return None,
        };
        self.ready_remove(index);
        self.set_stopped(index, None);
        let record = self.get_mut(index).expect("the checked ending record");
        let (pgid, linked) = (record.pgid, core::mem::take(&mut record.linked));
        record.state = State::Zombie(reason);
        // Initial origin survives Zombie until reap for exact Init ACK.
        if record.image != proto_process::IMAGE {
            record.image_origin = 0;
        }
        record.stop_report = None;
        record.cont_report = false;
        let parent = record.parent_index.filter(|_| loaded);
        self.unlink(pgid, linked);
        self.ready_add(index);
        match parent {
            Some(parent) => Some(EndMetadata {
                exit: Exit::Zombie {
                    parent: usize::from(parent),
                },
                retired: None,
            }),
            None => Some(EndMetadata {
                exit: Exit::Reaped,
                retired: self.reap_retained(key),
            }),
        }
    }

    /// The process of the record in `index` ended with `end` (the
    /// notification of its exit place came, `find_exit`): its live
    /// children are the service's from now on (the returned orphans), its
    /// zombie children go; it is a zombie for its parent's wait, or goes
    /// at once without one or when it was still LOADING. CHILDREN_MAX
    /// steps.
    pub fn exited(&mut self, index: usize, end: End) -> (Exit, Orphans) {
        // Custody ends before the record can become a waitable zombie.
        let active = self.take_active_exec(index);
        drop(active);
        self.ready_remove(index);
        self.set_stopped(index, None);
        let mut orphans = Orphans::default();
        let mut child = self.records[index]
            .as_mut()
            .and_then(|r| r.first_child.take());
        while let Some(c) = child {
            self.ready_remove(usize::from(c));
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
        // Initial origin survives Zombie until reap for exact Init ACK.
        if record.image != proto_process::IMAGE {
            record.image_origin = 0;
        }
        record.stop_report = None;
        record.cont_report = false;
        self.unlink(pgid, linked);
        self.ready_add(index);
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
    pub fn reap(&mut self, index: usize) -> Option<Record<P, C>> {
        let record = self.records[index].as_ref()?;
        if !matches!(record.state, State::Zombie(_)) {
            return None;
        }
        let (previous, next, parent) = (record.previous, record.next, record.parent_index);
        self.ready_remove(index);
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
            self.mark_orphan(place, true);
        }
    }

    /// The record in `index` leaves the table and its group and session;
    /// its place is free unless a group or a session carries its number.
    fn free_index(&mut self, index: usize) -> Option<Record<P, C>> {
        self.ready_remove(index);
        if self.get(index).is_some_and(|r| r.stopped.is_some()) {
            self.set_stopped(index, None);
        }
        let record = self.records[index].take()?;
        self.leave(record.pgid, record.sid, record.linked);
        self.settle(index);
        Some(record)
    }

    /// Whether the child in `child` is one `selector` takes: no LOADING
    /// child, whose PID its parent does not know yet.
    pub fn takes(&self, child: usize, selector: Selector) -> bool {
        self.get(child)
            .filter(|r| match r.state {
                State::Loading => false,
                State::EndPendingLoading(_) | State::EndingLoading(_) => false,
                State::EndPendingAlive(_) | State::EndingAlive(_) => true,
                _ => true,
            })
            .is_some_and(|r| match selector {
                Selector::Pid(pid) => r.label.pid() == pid,
                Selector::Any => true,
                Selector::Group(pgid) => r.pgid == pgid,
            })
    }

    /// A link removal that makes a stopped group orphaned schedules its signals.
    fn mark_orphan(&mut self, group: usize, removed_link: bool) {
        let g = &self.numbers[group];
        if removed_link && g.links == 0 && g.stopped != 0 && g.members != 0 {
            self.orphaned.push(group);
        }
    }

    pub fn has_orphans(&self) -> bool {
        !self.orphaned.is_empty()
    }

    /// One group whose parent links disappeared, with its current PID generation.
    pub fn take_orphan(&mut self) -> Option<u32> {
        let group = self.orphaned.pop()?;
        let g = &self.numbers[group];
        (g.members != 0 && g.links == 0 && g.stopped != 0)
            .then_some(self.generations[group] * RECORDS as u32 + group as u32)
    }

    /// Change suspension and its group count without changing Loading/Alive.
    pub fn set_stopped(&mut self, index: usize, signal: Option<u8>) -> bool {
        let r = self.records[index].as_mut().expect("a record");
        let was = r.stopped.is_some();
        let now = signal.is_some();
        if was == now {
            return false;
        }
        r.stopped = signal;
        let group = r.pgid;
        let place = self.place_of(group).expect("a group");
        let count = &mut self.numbers[place].stopped;
        if now {
            *count += 1
        } else {
            *count -= 1
        }
        true
    }

    fn ready_add(&mut self, index: usize) {
        let r = self.records[index].as_ref().expect("a child");
        if r.ready || r.state == State::Loading || r.state.end_pending() {
            return;
        }
        let Some(parent) = r.parent_index else { return };
        let first = self.records[usize::from(parent)]
            .as_mut()
            .expect("a parent")
            .first_ready
            .replace(index as u16);
        if let Some(first) = first {
            self.records[usize::from(first)]
                .as_mut()
                .expect("a ready child")
                .ready_previous = Some(index as u16);
        }
        let r = self.records[index].as_mut().expect("a child");
        r.ready = true;
        r.ready_previous = None;
        r.ready_next = first;
    }

    fn ready_remove(&mut self, index: usize) {
        let Some(r) = self.records[index].as_mut() else {
            return;
        };
        if !core::mem::take(&mut r.ready) {
            return;
        }
        let (previous, next, parent) =
            (r.ready_previous.take(), r.ready_next.take(), r.parent_index);
        if let Some(previous) = previous {
            self.records[usize::from(previous)]
                .as_mut()
                .expect("a ready sibling")
                .ready_next = next;
        } else if let Some(parent) = parent {
            self.records[usize::from(parent)]
                .as_mut()
                .expect("a parent")
                .first_ready = next;
        }
        if let Some(next) = next {
            self.records[usize::from(next)]
                .as_mut()
                .expect("a ready sibling")
                .ready_previous = previous;
        }
    }

    /// Keep a child's stop or continuation for wait, linking it once in O(1).
    pub fn report(&mut self, index: usize, signal: Option<u8>) {
        let r = self.records[index].as_mut().expect("a child");
        if let Some(signal) = signal {
            r.stop_report = Some(signal);
            r.cont_report = false;
        } else {
            r.stop_report = None;
            r.cont_report = true
        }
        self.ready_add(index);
    }

    pub fn reported(
        &self,
        parent: usize,
        selector: Selector,
        options: u32,
    ) -> Option<(usize, WaitResult)> {
        let mut next = self.get(parent)?.first_ready;
        while let Some(child) = next {
            let child = usize::from(child);
            let r = self.get(child)?;
            next = r.ready_next;
            if !self.takes(child, selector) {
                continue;
            }
            let (pid, uid) = (r.label.pid(), r.credentials.uid);
            if let State::Zombie(end) = r.state
                && options & WEXITED != 0
            {
                return Some((child, WaitResult::Ended { pid, end, uid }));
            }
            if options & WSTOPPED != 0
                && let Some(signal) = r.stop_report
            {
                return Some((child, WaitResult::Stopped { pid, signal, uid }));
            }
            if options & WCONTINUED != 0 && r.cont_report {
                return Some((child, WaitResult::Continued { pid, uid }));
            }
        }
        None
    }

    pub fn consume_report(&mut self, child: usize, result: WaitResult) {
        let r = self.records[child].as_mut().expect("a child");
        match result {
            WaitResult::Stopped { .. } => r.stop_report = None,
            WaitResult::Continued { .. } => r.cont_report = false,
            _ => return,
        }
        if r.stop_report.is_none() && !r.cont_report {
            self.ready_remove(child)
        }
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

    #[test]
    fn acknowledged_initial_replay_requires_every_current_key_and_receipt_field() {
        use crate::initial_origin::{INIT_ACKED, InitialOrigin, SourceOrigin};
        let mut table = Records::<u32>::new();
        let label = add(&mut table).unwrap();
        let record = table.get_mut(at(label)).unwrap();
        let ticket = 83;
        let epoch = 0x1234_5678_8765_4321;
        record.source_origin = SourceOrigin::boot(4, false).unwrap();
        assert!(record.set_initial_epoch(ticket, epoch));
        let ack = proto_process::initial_ack::Ack {
            epoch,
            ticket,
            label: label.raw_at(record.image),
            receipt: proto_process::initial_map::Receipt {
                key: proto_process::initial_map::Key {
                    key: ticket,
                    image: record.image,
                },
                label: label.raw_at(record.image),
                pid: label.pid(),
                init_ticket: ticket,
            },
        };
        assert!(record.matches_initial_ack(ticket, ack));
        assert!(!record.initial_ack_replay_matches(ticket, ack));
        assert!(record.set_initial_origin(ticket, InitialOrigin::new(4, INIT_ACKED).unwrap()));
        assert!(record.initial_ack_replay_matches(ticket, ack));
        assert!(record.initial_ack_replay_matches(ticket, ack));
        for field in 0..8 {
            let mut other = ack;
            match field {
                0 => other.epoch ^= 1 << 48,
                1 => other.ticket ^= 1,
                2 => other.label ^= 1,
                3 => other.receipt.key.key ^= 1,
                4 => other.receipt.key.image += 1,
                5 => other.receipt.label ^= 1,
                6 => other.receipt.pid ^= 1,
                _ => other.receipt.init_ticket ^= 1,
            }
            assert!(
                !record.initial_ack_replay_matches(ticket, other),
                "field {field}"
            );
        }
        assert!(!record.initial_ack_replay_matches(ticket + 1, ack));
        record.state = State::Zombie(End::Exited(0));
        assert!(record.initial_ack_replay_matches(ticket, ack));
        record.image += 1;
        assert!(!record.initial_ack_replay_matches(ticket, ack));
    }
    #[test]
    fn persistent_initial_epoch_keeps_high_bits_and_requires_boot_discriminator() {
        use crate::initial_origin::{INIT_ACKED, InitialOrigin, SourceOrigin};
        let mut table = Records::<u32>::new();
        let label = add(&mut table).unwrap();
        let record = table.get_mut(at(label)).unwrap();
        let ticket = 91;
        assert_eq!(record.initial_epoch(ticket), None);
        assert!(!record.set_initial_epoch(ticket, 7));
        record.source_origin = SourceOrigin::boot(3, false).unwrap();
        assert!(record.set_initial_origin(ticket, InitialOrigin::new(3, 0).unwrap()));
        assert_eq!(record.initial_epoch(ticket), Some(0));
        assert!(!record.set_initial_epoch(ticket, 0));
        let epoch = 0x9876_5432_1234_5678;
        assert!(record.set_initial_epoch(ticket, epoch));
        assert!(!record.set_initial_epoch(ticket, epoch + 1));
        assert!(record.set_initial_origin(ticket, InitialOrigin::new(3, INIT_ACKED).unwrap()));
        assert_eq!(record.initial_epoch(ticket), Some(epoch));
        assert_eq!(record.initial_epoch(0), None);
        assert_eq!(record.loader_ticket(ticket), None);
        record.source_origin.capture_suspend(true);
        record.source_origin.finish_suspend();
        assert_eq!(record.initial_epoch(ticket), Some(epoch));
        assert_eq!(
            record
                .source_origin
                .inherited()
                .initial_origin()
                .unwrap()
                .flags,
            0
        );
        record.state = State::Zombie(End::Exited(0));
        assert_eq!(record.initial_epoch(ticket), Some(epoch));
        record.image += 1;
        assert_eq!(record.initial_epoch(ticket), None);
        record.set_loader_ticket(29);
        assert_eq!(record.loader_ticket(ticket), Some(29));
        assert_eq!(record.source_origin.initial_origin().unwrap().flags, 0);
        record.source_origin = SourceOrigin::UNKNOWN;
        assert_eq!(record.initial_origin(ticket), None);
    }

    #[test]
    fn native_end_pending_revokes_lookup_without_releasing_namespace_or_first_reason() {
        let mut table = Records::<u32>::new();
        let parent = add(&mut table).unwrap();
        let label = child(&mut table, parent);
        let key = crate::preparing::Key {
            label,
            image: proto_process::IMAGE,
        };
        table.report(at(label), Some(proto_process::SIGSTOP));
        assert!(
            table
                .reported(at(parent), Selector::Any, WSTOPPED)
                .is_some()
        );
        assert!(table.mark_end_pending(key, None));
        assert_eq!(table.find(label.raw()), None);
        assert_eq!(table.find_identity(label.identity()), None);
        assert_eq!(table.find_loader(label.loader()), None);
        assert_eq!(table.start_parent(at(label)), None);
        assert_eq!(table.target(at(parent), label.pid()), None);
        assert_eq!(table.set_pgid(at(label), 0, 0), Err(GroupError::NoProcess));
        assert_eq!(
            table.change_credentials(at(label), proto_process::Change::EffectiveUid, 33, 1),
            Err(proto_process::NO_PROCESS)
        );
        assert_eq!(
            table.find_pid(label.pid()),
            Some(at(label)),
            "namespace remains owned before ACK"
        );
        assert_eq!(
            table.reported(at(parent), Selector::Any, WEXITED | WSTOPPED),
            None
        );
        assert_eq!(
            table.begin_end_retained(key),
            None,
            "unknown reason is not fabricated"
        );
        assert!(!table.mark_end_pending(key, Some(End::Exited(7))));
        assert!(!table.mark_end_pending(key, Some(End::Signaled(SIGKILL))));
        assert_eq!(table.end_reason(key), Some(End::Exited(7)));
        let old = crate::preparing::Key {
            image: key.image + 1,
            ..key
        };
        assert!(!table.mark_end_pending(old, Some(End::Exited(8))));
        assert_eq!(table.begin_end_retained(key), Some(None));
        assert_eq!(
            table.change_credentials(at(label), proto_process::Change::EffectiveUid, 33, 1),
            Err(proto_process::NO_PROCESS)
        );
        assert_eq!(table.reported(at(parent), Selector::Any, WEXITED), None);
        assert_eq!(
            table.finish_end_metadata(key).unwrap().exit,
            Exit::Zombie { parent: at(parent) }
        );
        assert!(table.reported(at(parent), Selector::Any, WEXITED).is_some());
    }

    #[test]
    fn retained_zombie_slot_is_unavailable_across_close_refusal_and_exact_release() {
        let mut table = Records::<u32>::new();
        let parent = add(&mut table).unwrap();
        let label = child(&mut table, parent);
        let key = crate::preparing::Key {
            label,
            image: proto_process::IMAGE,
        };
        table.exited(at(label), End::Exited(7));
        let (record, token) = table.reap_retained(key).unwrap();
        assert_eq!(record.label, label);
        assert_eq!(token.key(), key);
        assert!(
            table.reap_retained(key).is_none(),
            "duplicate Wait cannot take its owners"
        );
        assert_eq!(table.slots[at(label)], SlotState::Retaining);
        let next = table.reserve_next().unwrap();
        assert_ne!(
            next.label().index,
            label.index,
            "a failed close keeps the detached slot withheld"
        );
        table.cancel_reserved(next).unwrap();
        // The native caller retains record owners and token on refusal;
        // only its successful one-cap close reaches release_retained.
        table.release_retained(token).unwrap();
        let reused = table.next_label().unwrap();
        assert_eq!(reused.index, label.index);
        assert_ne!(reused, label);
        assert!(!table.mark_end_pending(key, Some(End::Exited(8))));
    }

    #[test]
    fn one_child_end_metadata_drains_32_children_with_retained_slot_release() {
        let mut table = Records::<u32>::new();
        let parent = add(&mut table).unwrap();
        let mut children = Vec::new();
        for n in 0..CHILDREN_MAX {
            let label = child(&mut table, parent);
            if n % 2 == 0 {
                table.exited(at(label), End::Exited(0));
            }
            children.push(label);
        }
        table.get_mut(at(parent)).unwrap().state = State::Alive;
        let key = crate::preparing::Key {
            label: parent,
            image: proto_process::IMAGE,
        };
        table.mark_end_pending(key, Some(End::Exited(7)));
        table.begin_end_retained(key).unwrap();
        assert!(table.finish_end_metadata(key).is_none());
        let mut visits = 0;
        while let Some(child) = table.ending_child(key) {
            if matches!(table.get(at(child.label)).unwrap().state, State::Zombie(_)) {
                let (record, token) = table.reap_retained(child).unwrap();
                assert_eq!(record.label, child.label);
                assert!(table.ending_child(key).map(|next| next.label) != Some(child.label));
                table.release_retained(token).unwrap();
            } else {
                assert!(table.orphan_ending_child(key, child));
                assert_eq!(table.get(at(child.label)).unwrap().parent, INIT_PID);
            }
            visits += 1;
        }
        assert_eq!(visits, CHILDREN_MAX);
        let metadata = table.finish_end_metadata(key).unwrap();
        assert_eq!(metadata.exit, Exit::Reaped);
        let (record, token) = metadata.retired.unwrap();
        assert_eq!(record.label, parent);
        assert_eq!(table.slots[at(parent)], SlotState::Retaining);
        table.release_retained(token).unwrap();
    }

    #[test]
    fn retained_end_transfers_noncopy_owners_without_running_drop() {
        use core::cell::Cell;
        use std::rc::Rc;
        struct Owner(Rc<Cell<u32>>);
        impl Drop for Owner {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = Rc::new(Cell::new(0));
        let mut table = Records::<Owner, Owner>::with_exec_custody();
        let label = table.next_label().unwrap();
        let index = table.insert(
            label,
            Owner(drops.clone()),
            None,
            Credentials::ROOT,
            31,
            Join::NewSession,
        );
        table.get_mut(index).unwrap().active_exec = Some(Owner(drops.clone()));
        table.get_mut(index).unwrap().state = State::Alive;
        let key = crate::preparing::Key {
            label,
            image: proto_process::IMAGE,
        };
        assert!(table.mark_end_pending(key, Some(End::Exited(0))));
        let executable = table.begin_end_retained(key).unwrap().unwrap();
        assert_eq!(drops.get(), 0);
        drop(executable);
        assert_eq!(drops.get(), 1);
        let (record, token) = table.finish_end_metadata(key).unwrap().retired.unwrap();
        assert_eq!(drops.get(), 1);
        assert!(table.get(index).is_none());
        assert_eq!(table.slots[index], SlotState::Retaining);
        assert_ne!(table.next_label().unwrap().index, label.index);
        drop(record);
        assert_eq!(drops.get(), 2);
        table.release_retained(token).unwrap();
        assert_eq!(table.next_label().unwrap().index, label.index);
    }

    #[test]
    fn eight_records_and_248_reservations_pay_the_same_fixed_table() {
        let mut table = Records::<u32>::new();
        for _ in 0..8 {
            let label = table.next_label().unwrap();
            table.insert(
                label,
                label.pid(),
                None,
                Credentials::ROOT,
                31,
                Join::NewSession,
            );
        }
        let mut reserved = Vec::new();
        for _ in 0..248 {
            let reservation = table.reserve_next().unwrap();
            assert!(table.find_pid(reservation.label().pid()).is_none());
            assert!(
                table
                    .find_identity(reservation.label().identity())
                    .is_none()
            );
            table.settle(usize::from(reservation.label().index));
            assert!(table.exact_reservation(&reservation));
            reserved.push(reservation);
        }
        assert_eq!(table.count(), RECORDS);
        assert!(table.reserve_next().is_none());
        assert!(table.next_label().is_none());
        for reservation in reserved.into_iter().rev() {
            table.cancel_reserved(reservation).unwrap();
        }
        assert_eq!(table.count(), 8);
        assert_eq!(core::mem::size_of::<SlotState>(), 1);
    }

    #[test]
    fn reserved_records_publish_out_of_order_and_burn_canceled_generations() {
        let mut table = Records::<u32>::new();
        let first = table.reserve_next().unwrap();
        let first_label = first.label();
        let second = table.reserve_next().unwrap();
        let second_label = second.label();
        let index = table
            .consume_reserved(second, 7, None, Credentials::ROOT, 31, Join::NewSession)
            .unwrap_or_else(|_| panic!("an exact reservation"));
        assert_eq!(index, usize::from(second_label.index));
        assert_eq!(table.find_pid(second_label.pid()), Some(index));
        assert_eq!(table.find_pid(first_label.pid()), None);
        table.cancel_reserved(first).unwrap();
        let reused = table.reserve_next().unwrap();
        assert_eq!(reused.label().index, first_label.index);
        assert!(reused.label().generation > first_label.generation);
        let stale = Reservation { label: first_label };
        assert!(table.cancel_reserved(stale).is_err());
        let stale = Reservation { label: first_label };
        let failed = table
            .consume_reserved(stale, 9, None, Credentials::ROOT, 31, Join::NewSession)
            .err()
            .unwrap();
        assert_eq!(failed.error, ConsumeError::Stale);
        assert_eq!(failed.process, 9);
        assert!(table.exact_reservation(&reused));
        table.cancel_reserved(reused).unwrap();
        assert_eq!(table.count(), 1);
    }

    #[test]
    fn terminal_reserved_generation_cancels_without_a_fresh_mint() {
        let mut table = Records::<u32>::new();
        table.generations[0] = proto_process::GENERATION_MAX - 1;
        let last = table.reserve_next().unwrap();
        assert_eq!(last.label().generation, proto_process::GENERATION_MAX);
        table.cancel_reserved(last).unwrap();
        assert_eq!(table.slots[0], SlotState::Retired);
        table.settle(0);
        assert_eq!(table.next_label().unwrap().index, 1);
        assert_eq!(table.count(), 1);
    }

    #[test]
    fn consume_after_parent_reuse_returns_every_existing_owned_value() {
        use std::{cell::Cell, rc::Rc};
        struct Process(Rc<Cell<u32>>);
        impl Drop for Process {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = Rc::new(Cell::new(0));
        let mut table = Records::<Process>::new();
        let label = table.next_label().unwrap();
        let parent = table.insert(
            label,
            Process(drops.clone()),
            None,
            Credentials::ROOT,
            31,
            Join::NewSession,
        );
        table.get_mut(parent).unwrap().state = State::Alive;
        let origin = table.start_parent(parent).unwrap();
        let reservation = table.reserve_next().unwrap();
        table.exited(parent, End::exited(0));
        let next = table.next_label().unwrap();
        assert_eq!(next.index, label.index);
        table.insert(
            next,
            Process(drops.clone()),
            None,
            Credentials::ROOT,
            31,
            Join::NewSession,
        );
        table.get_mut(parent).unwrap().state = State::Alive;
        let failed = table
            .consume_reserved(
                reservation,
                Process(drops.clone()),
                Some(origin),
                Credentials::ROOT,
                31,
                Join::Inherit,
            )
            .err()
            .unwrap();
        assert_eq!(failed.error, ConsumeError::Parent);
        assert_eq!(drops.get(), 1);
        assert_eq!(table.get(parent).unwrap().children, 0);
        assert!(table.exact_reservation(&failed.reservation));
        table.cancel_reserved(failed.reservation).unwrap();
        drop(failed.process);
        assert_eq!(drops.get(), 2);
    }

    #[test]
    fn consume_rechecks_child_limit_image_and_group_before_publication() {
        let mut table = Records::<u32>::new();
        let label = table.next_label().unwrap();
        let parent = table.insert(label, 0, None, Credentials::ROOT, 31, Join::NewSession);
        table.get_mut(parent).unwrap().state = State::Alive;
        let origin = table.start_parent(parent).unwrap();
        let reservation = table.reserve_next().unwrap();
        table.get_mut(parent).unwrap().image += 1;
        let failed = table
            .consume_reserved(
                reservation,
                1,
                Some(origin),
                Credentials::ROOT,
                31,
                Join::Inherit,
            )
            .err()
            .unwrap();
        assert_eq!(failed.error, ConsumeError::Parent);
        table.get_mut(parent).unwrap().image -= 1;
        table.get_mut(parent).unwrap().children = CHILDREN_MAX;
        let failed = table
            .consume_reserved(
                failed.reservation,
                failed.process,
                Some(origin),
                Credentials::ROOT,
                31,
                Join::Inherit,
            )
            .err()
            .unwrap();
        assert_eq!(failed.error, ConsumeError::Parent);
        table.get_mut(parent).unwrap().children = 0;
        let failed = table
            .consume_reserved(
                failed.reservation,
                failed.process,
                Some(origin),
                Credentials::ROOT,
                31,
                Join::Group(u32::MAX),
            )
            .err()
            .unwrap();
        assert_eq!(failed.error, ConsumeError::Group);
        assert_eq!(table.get(parent).unwrap().children, 0);
        assert_eq!(table.count(), 2);
        table.cancel_reserved(failed.reservation).unwrap();
        assert_eq!(table.count(), 1);
    }

    #[test]
    fn exhausted_credentials_leave_the_real_record_unchanged() {
        let mut t = Records::<u32>::new();
        let label = t.next_label().unwrap();
        let index = t.insert(label, 0, None, Credentials::ROOT, 31, Join::NewSession);
        let last = proto_process::GENERATION_DEAD - 1;
        assert_eq!(
            t.change_credentials(index, proto_process::Change::EffectiveUid, 33, last),
            Err(proto_process::AGAIN)
        );
        assert_eq!(t.get(index).unwrap().credentials, Credentials::ROOT);
        t.change_credentials(index, proto_process::Change::EffectiveUid, 33, last - 1)
            .unwrap();
        assert_eq!(t.get(index).unwrap().credentials.euid, 33);
        let retained = t.get(index).unwrap().credentials;
        assert_eq!(
            t.change_credentials(index, proto_process::Change::EffectiveUid, 0, u64::MAX),
            Err(proto_process::NO_PROCESS)
        );
        assert_eq!(t.get(index).unwrap().credentials, retained);
        assert_eq!(t.exited(index, End::exited(0)).0, Exit::Reaped);
    }

    #[test]
    fn retiring_a_free_credentials_index_keeps_other_indices_available() {
        let mut t = Records::<u32>::new();
        let retired = t.next_label().unwrap();
        t.retire_next(retired);
        assert_eq!(t.count(), 1);
        assert_eq!(t.slots[usize::from(retired.index)], SlotState::Retired);
        let live = t.next_label().unwrap();
        assert_eq!(live.index, 1);
        let index = t.insert(live, 0, None, Credentials::ROOT, 31, Join::NewSession);
        t.exited(index, End::exited(0));
        assert_eq!(t.next_label().unwrap().index, live.index);
        assert_eq!(t.count(), 1);
        t.settle(usize::from(retired.index));
        assert_eq!(t.slots[usize::from(retired.index)], SlotState::Retired);
    }

    #[test]
    fn an_exhausted_record_index_never_reissues_its_identity() {
        let mut t = Records::<u32>::new();
        t.generations[0] = proto_process::GENERATION_MAX - 1;
        let last = t.next_label().unwrap();
        assert_eq!(last.index, 0);
        assert_eq!(last.generation, proto_process::GENERATION_MAX);
        let index = t.insert(last, 0, None, Credentials::ROOT, 31, Join::NewSession);
        assert_eq!(t.find_identity(last.identity()), Some(index));
        assert_eq!(t.exited(index, End::exited(0)).0, Exit::Reaped);
        assert_eq!(t.find_identity(last.identity()), None);
        assert_eq!(t.slots[index], SlotState::Retired);
        assert_eq!(t.count(), 1, "the exhausted index remains unavailable");
        let next = t.next_label().unwrap();
        assert_eq!(next.index, 1);
        assert_eq!(next.generation, 1);
        t.insert(next, 0, None, Credentials::ROOT, 31, Join::NewSession);
        assert_eq!(t.find_identity(last.identity()), None);
        assert_eq!(t.find_loader(last.loader()), None);
        assert_eq!(t.find_identity(next.identity()), Some(1));
    }
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
    fn new_status_replaces_wnowait_stop_continue_and_exit() {
        let mut t = Records::<u32>::new();
        let parent_label = add(&mut t).unwrap();
        let child_label = child(&mut t, parent_label);
        let (parent, child) = (
            usize::from(parent_label.index),
            usize::from(child_label.index),
        );
        let selector = Selector::Any;
        t.report(child, Some(proto_process::SIGSTOP));
        assert!(matches!(
            t.reported(parent, selector, WSTOPPED),
            Some((_, WaitResult::Stopped { .. }))
        ));
        t.report(child, None);
        assert_eq!(t.reported(parent, selector, WSTOPPED), None);
        assert!(matches!(
            t.reported(parent, selector, WCONTINUED),
            Some((_, WaitResult::Continued { .. }))
        ));
        t.report(child, Some(proto_process::SIGTSTP));
        assert_eq!(t.reported(parent, selector, WCONTINUED), None);
        t.exited(child, End::Exited(7));
        assert_eq!(t.reported(parent, selector, WSTOPPED | WCONTINUED), None);
        assert!(matches!(
            t.reported(parent, selector, WEXITED),
            Some((_, WaitResult::Ended { .. }))
        ));
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
                ticket: 0,
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
        // A child of fork moves until it execs; one that ran a program of
        // its own (posix_spawn or exec) does not.
        let f = child_in(&mut t, p, Join::Inherit);
        assert_eq!(t.set_pgid(at(p), f.pid(), 0), Ok(()), "a child of fork");
        assert_eq!(t.pgid_of(at(p), f.pid()), Some(f.pid()));
        assert_eq!(
            t.set_pgid(at(p), f.pid(), p.pid()),
            Ok(()),
            "back to the parent's"
        );
        assert_eq!(t.pgid_of(at(p), f.pid()), Some(p.pid()));
        t.get_mut(at(a)).unwrap().execed = true;
        assert_eq!(
            t.set_pgid(at(p), a.pid(), a.pid()),
            Err(GroupError::Access),
            "a child ran a program of its own"
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

    /// After an exec (5c) the session and the exit place of the old image
    /// name no record, those of the new one do, and the identity of either
    /// names the same record; the PID stays.
    #[test]
    fn an_exec_moves_the_session_and_the_identity() {
        let mut t = Records::<u32>::new();
        let live = add(&mut t).unwrap();
        let i = at(live);
        t.get_mut(i).unwrap().image = 2;
        assert_eq!(t.find(live.raw()), None, "the old image's session");
        assert_eq!(t.find_exit(live.exit()), None, "the old image's end");
        assert_eq!(t.find(live.raw_at(2)), Some(i));
        assert_eq!(t.session_label(i), Some(live.raw_at(2)));
        assert_eq!(t.find_exit(live.exit_at(2)), Some(i));
        assert_eq!(
            t.find_identity(live.identity()),
            None,
            "the old image's identity"
        );
        assert_eq!(t.find_identity(live.identity_at(2)), Some(i));
        assert_eq!(t.find_loader(live.loader_at(3)), Some(i));
        assert_eq!(t.find_pid(live.pid()), Some(i));
    }
    #[test]
    fn child_inherits_groups_finite_limits_and_the_original_expenditure_root() {
        let mut records = Records::<u32>::new();
        let parent = add(&mut records).unwrap();
        let i = parent.index as usize;
        let mut groups = proto_process::Groups::EMPTY;
        groups.count = 16;
        groups.ids = [42; 16];
        let limits = proto_process::ResourceLimits::initial(3 * 1024 * 1024);
        let root = records.get(i).unwrap().root;
        records.get_mut(i).unwrap().groups = groups;
        records.get_mut(i).unwrap().limits = limits;
        let child = child(&mut records, parent);
        let child = records.get(child.index as usize).unwrap();
        assert_eq!(child.groups, groups);
        assert_eq!(child.limits, limits);
        assert_eq!(child.root, root);
        assert_ne!(child.label.pid(), root.pid);
        assert_eq!(limits.values[proto_process::NOFILE].soft, 32);
        assert!(
            limits
                .values
                .iter()
                .all(|l| l.soft <= l.hard && l.hard != u64::MAX)
        );
    }
}
