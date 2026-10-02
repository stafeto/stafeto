// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The records of the process service (spec 2, section 3.1): RECORDS of
//! them at most, each in an index with a generation, so that a label the
//! service gave (proto_process::Label) finds its record in O(1) and a
//! label of a gone generation finds nothing. A record comes with its
//! process, which the service creates (Create), and goes only with the
//! notification of the process's end, whose place carries the record's
//! exit label: a copy of its session that outlives the process keeps
//! nothing. `P` is what the service keeps of the record's process: its
//! handle.

use proto_process::{Credentials, Label, Place, RECORDS};

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
    pub parent: u32,
    pub credentials: Credentials,
    pub state: State,
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
    pub fn new() -> Self {
        let mut free = [0; RECORDS];
        for (i, slot) in free.iter_mut().enumerate() {
            *slot = (RECORDS - 1 - i) as u16;
        }
        Self {
            records: core::array::from_fn(|_| None),
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

    /// A record of `process`, LOADING, with the label `next_label` gave,
    /// which the caller made its exit place and session with: O(1).
    ///
    /// # Panics
    /// When `label` is not that of `next_label`.
    pub fn insert(
        &mut self,
        label: Label,
        process: P,
        parent: u32,
        credentials: Credentials,
    ) -> usize {
        assert_eq!(
            self.next_label(),
            Some(label),
            "the label of the next record"
        );
        let i = usize::from(label.index);
        self.free_len -= 1;
        self.generations[i] = label.generation;
        self.records[i] = Some(Record {
            process,
            label,
            parent,
            credentials,
            state: State::Loading,
        });
        i
    }

    /// The record whose exit place has `label` goes: the notification of
    /// its process's end came. Its index waits on top of the free ones,
    /// its next label one generation on. A label of another place, of a
    /// gone generation or of no record takes nothing. O(1).
    pub fn ended(&mut self, label: u64) -> Option<Record<P>> {
        let index = self.named(label, Place::Exit)?;
        let record = self.records[index].take()?;
        self.free[self.free_len] = index as u16;
        self.free_len += 1;
        Some(record)
    }
}

/// The exit place of the record of `label` for a process of `ceiling`: its
/// label and the priority of the notification of the end, the process's
/// ceiling (spec 2, section 3.1), so that the end of a process lifts the
/// service no higher than the process could run.
pub const fn exit_place(label: Label, ceiling: u8) -> (u64, u8) {
    (label.exit(), ceiling)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_process::INIT_PID;

    fn add(t: &mut Records<u32>) -> Option<Label> {
        let label = t.next_label()?;
        t.insert(label, 0, INIT_PID, Credentials::NOBODY);
        Some(label)
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

    /// The end of a process is heard at its ceiling.
    #[test]
    fn the_exit_place_is_at_the_ceiling_of_the_process() {
        let label = Label {
            index: 3,
            generation: 1,
        };
        for ceiling in [1, 31, 40] {
            assert_eq!(exit_place(label, ceiling), (label.exit(), ceiling));
        }
    }
}
