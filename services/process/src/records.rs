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
//! indices so that a child that goes leaves its parent in O(1); the
//! children of a record that goes get the service, PID 1, for their parent
//! (CHILDREN_MAX steps). `P` is what the service keeps of the record's
//! process: its handle.

use proto_process::{Create, Credentials, INIT_PID, Label, Place, RECORDS};

/// The live children of one record at most, until RLIMIT_NPROC (5b
/// design, question 3): Spawn past them is EAGAIN.
pub const CHILDREN_MAX: u32 = 32;

/// Where a record is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Created; one of the service's threads loads its program.
    Loading,
    /// Loaded and started.
    Alive,
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
    ) -> usize {
        assert_eq!(
            self.next_label(),
            Some(label),
            "the label of the next record"
        );
        let i = usize::from(label.index);
        let (pid, first) = match parent {
            Some(p) => {
                assert!(self.may_spawn(p), "a parent with room for a child");
                let parent = self.records[p].as_mut().expect("a live parent");
                parent.children += 1;
                let first = parent.first_child.replace(i as u16);
                (parent.label.pid(), first)
            }
            None => (INIT_PID, None),
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

    /// The record whose exit place has `label` goes: the notification of
    /// its process's end came. Its index waits on top of the free ones,
    /// its next label one generation on. A label of another place, of a
    /// gone generation or of no record takes nothing. O(1).
    pub fn ended(&mut self, label: u64) -> Option<Record<P>> {
        let index = self.named(label, Place::Exit)?;
        let record = self.records[index].take()?;
        // Out of its parent's list.
        match record.previous {
            Some(p) => {
                self.records[usize::from(p)]
                    .as_mut()
                    .expect("a sibling")
                    .next = record.next
            }
            None => {
                if let Some(parent) = record
                    .parent_index
                    .and_then(|p| self.records[usize::from(p)].as_mut())
                {
                    parent.first_child = record.next;
                }
            }
        }
        if let Some(n) = record.next {
            self.records[usize::from(n)]
                .as_mut()
                .expect("a sibling")
                .previous = record.previous;
        }
        if let Some(parent) = record
            .parent_index
            .and_then(|p| self.records[usize::from(p)].as_mut())
        {
            parent.children -= 1;
        }
        // Its children are the service's, PID 1: CHILDREN_MAX at most.
        let mut child = record.first_child;
        while let Some(c) = child {
            let orphan = self.records[usize::from(c)].as_mut().expect("a child");
            child = orphan.next;
            orphan.parent = INIT_PID;
            orphan.parent_index = None;
            orphan.previous = None;
            orphan.next = None;
        }
        self.free[self.free_len] = index as u16;
        self.free_len += 1;
        Some(record)
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
    use proto_process::INIT_PID;

    fn add(t: &mut Records<u32>) -> Option<Label> {
        let label = t.next_label()?;
        t.insert(label, 0, None, Credentials::NOBODY);
        Some(label)
    }

    fn child(t: &mut Records<u32>, parent: Label) -> Label {
        let label = t.next_label().unwrap();
        t.insert(label, 0, Some(usize::from(parent.index)), Credentials::ROOT);
        label
    }

    /// A record has CHILDREN_MAX live children at most; a child that ends
    /// frees its place, and one that ended in the middle of the list
    /// leaves the others linked.
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
        assert_eq!(t.get(p).unwrap().children, CHILDREN_MAX);
        assert_eq!(t.children(p).count(), CHILDREN_MAX as usize);
        for c in &children {
            let record = t.get(usize::from(c.index)).unwrap();
            assert_eq!(record.parent, parent.pid());
            assert_eq!(record.parent_index, Some(parent.index));
        }
        assert!(t.ended(children[5].exit()).is_some());
        assert!(t.may_spawn(p), "a child that ended frees its place");
        assert_eq!(t.children(p).count(), CHILDREN_MAX as usize - 1);
        assert!(!t.children(p).any(|c| c == usize::from(children[5].index)));
        // The first and the last of the list go too.
        assert!(t.ended(children[31].exit()).is_some());
        assert!(t.ended(children[0].exit()).is_some());
        assert_eq!(t.children(p).count(), CHILDREN_MAX as usize - 3);
        assert_eq!(t.get(p).unwrap().children, CHILDREN_MAX - 3);
    }

    /// The children of a record that ends get PID 1; a new record in its
    /// index is no parent of theirs.
    #[test]
    fn the_children_of_an_ended_record_get_pid_1() {
        let mut t = Records::<u32>::new();
        let parent = add(&mut t).unwrap();
        let a = child(&mut t, parent);
        let b = child(&mut t, parent);
        assert!(t.ended(parent.exit()).is_some());
        for c in [a, b] {
            let record = t.get(usize::from(c.index)).unwrap();
            assert_eq!(record.parent, INIT_PID);
            assert_eq!(record.parent_index, None);
        }
        let next = add(&mut t).unwrap();
        assert_eq!(next.index, parent.index);
        assert_eq!(t.children(usize::from(next.index)).count(), 0);
        assert!(t.ended(a.exit()).is_some());
        assert_eq!(t.get(usize::from(next.index)).unwrap().children, 0);
    }

    #[test]
    fn the_bound_is_records_and_an_ended_record_frees_its_index() {
        let mut t = Records::<u32>::new();
        let labels: Vec<Label> = (0..RECORDS).map(|_| add(&mut t).unwrap()).collect();
        assert_eq!(t.count(), RECORDS);
        assert_eq!(t.next_label(), None, "FULL with every record taken");
        let gone = labels[17];
        assert!(t.ended(gone.exit()).is_some());
        assert!(t.ended(gone.exit()).is_none(), "a record goes once");
        assert_eq!(t.count(), RECORDS - 1);
        let next = add(&mut t).unwrap();
        assert_eq!(next.index, gone.index, "the index freed last comes first");
        assert_eq!(next.pid(), gone.pid() + RECORDS as u32, "one generation on");
        for label in labels.iter().filter(|l| **l != gone) {
            assert!(t.ended(label.exit()).is_some());
        }
        assert!(t.ended(next.exit()).is_some());
        assert_eq!(t.count(), 0);
    }

    /// Only the exit label of a live record takes it away: its session's
    /// label, the identity label, both place bits, a label of the gone
    /// generation and an index with no record take nothing.
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
            assert!(t.ended(raw).is_none(), "{raw:#x}");
        }
        assert_eq!(t.count(), 1);
        assert_eq!(t.find(live.raw()), Some(usize::from(live.index)));
        assert_eq!(
            t.find(live.exit()),
            None,
            "no request through the exit place"
        );
        let record = t.ended(live.exit()).expect("the exit label ends it");
        assert_eq!(record.label, live);
        // A notification of the old generation after the index came back
        // leaves the new record.
        let next = add(&mut t).unwrap();
        assert_eq!(next.index, live.index);
        assert!(t.ended(live.exit()).is_none());
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
        assert_eq!(
            t.get(usize::from(live.index)).unwrap().state,
            State::Loading
        );
        for raw in [0, 0x1234, stale.raw(), live.raw() | 1 << 62 | 1 << 61] {
            assert_eq!(t.find(raw), None, "{raw:#x}");
        }
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
}
