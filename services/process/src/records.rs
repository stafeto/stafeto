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

use proto_process::{Create, Credentials, End, INIT_PID, Label, Place, RECORDS, Selector};

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

    /// The live records.
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
    /// the live record in `parent`, which counts it, or of PID 1. O(1).
    ///
    /// # Panics
    /// When `label` is not that of `next_label`, or `parent` holds no
    /// record that may have another child (`may_spawn`).
    pub fn insert(
        &mut self,
        label: Label,
        process: P,
        parent: Option<usize>,
        credentials: Credentials,
        ceiling: u8,
    ) -> usize {
        assert_eq!(
            self.next_label(),
            Some(label),
            "the label of the next record"
        );
        let i = usize::from(label.index);
        let (pid, first, group) = match parent {
            Some(p) => {
                assert!(self.may_spawn(p), "a parent with room for a child");
                let parent = self.records[p].as_mut().expect("a live parent");
                parent.children += 1;
                let first = parent.first_child.replace(i as u16);
                (parent.label.pid(), first, (parent.pgid, parent.sid))
            }
            None => (INIT_PID, None, (label.pid(), label.pid())),
        };
        if let Some(f) = first {
            self.records[usize::from(f)]
                .as_mut()
                .expect("a child")
                .previous = Some(i as u16);
        }
        self.free_len -= 1;
        self.generations[i] = label.generation;
        self.records[i] = Some(Record {
            process,
            label,
            parent: pid,
            credentials,
            state: State::Loading,
            ceiling,
            pgid: group.0,
            sid: group.1,
            parent_index: parent.map(|p| p as u16),
            children: 0,
            first_child: None,
            previous: None,
            next: first,
        });
        i
    }

    /// The live children of the record in `index`, by their indices.
    pub fn children(&self, index: usize) -> impl Iterator<Item = usize> + '_ {
        let first = self.get(index).and_then(|r| r.first_child);
        core::iter::successors(first, |&c| self.records[usize::from(c)].as_ref()?.next)
            .map(usize::from)
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
            if matches!(orphan.state, State::Zombie(_)) {
                self.free_index(usize::from(c));
            } else {
                orphans.indices[orphans.len] = c;
                orphans.len += 1;
            }
        }
        let record = self.records[index].as_mut().expect("an ended record");
        record.children = 0;
        // A process that never ran was no child of its parent's to wait
        // for: its Spawn failed.
        let loaded = record.state != State::Loading;
        record.state = State::Zombie(end);
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

    /// The record in `index` leaves the table, its index on top of the
    /// free ones.
    fn free_index(&mut self, index: usize) -> Option<Record<P>> {
        let record = self.records[index].take()?;
        self.free[self.free_len] = index as u16;
        self.free_len += 1;
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
        t.insert(label, 0, None, Credentials::NOBODY, 31);
        Some(label)
    }

    /// A child of `parent`, LOADING.
    fn loading(t: &mut Records<u32>, parent: Label) -> Label {
        let label = t.next_label().unwrap();
        let parent = Some(usize::from(parent.index));
        t.insert(label, 0, parent, Credentials::ROOT, 31);
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
}
