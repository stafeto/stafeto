// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The records of the process service (spec 2, section 3.1): RECORDS of
//! them at most, each in an index with a generation, so that the label of
//! its session (proto_process::Label) finds it in O(1) and a label of a
//! gone generation finds nothing. A record made through Child counts in
//! its maker's children, CHILDREN_MAX at a time. `P` is what the service
//! keeps of the record's process: its handle.

use proto_process::{Credentials, Label, RECORDS};

/// The live records one record makes through Child at most, so that no
/// process fills the table (RLIMIT_NPROC of 5b replaces it).
pub const CHILDREN_MAX: u32 = 32;

pub struct Record<P> {
    /// Its process, which the service keeps for its later calls (5b).
    pub process: P,
    pub label: Label,
    pub parent: u32,
    pub credentials: Credentials,
    /// The live records Child made through its session.
    pub children: u32,
    /// The record whose Child made it, by its label.
    pub maker: Option<Label>,
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

    /// The index of the record whose session has `label`, if it lives.
    pub fn find(&self, label: u64) -> Option<usize> {
        let label = Label::from_raw(label)?;
        let index = usize::from(label.index);
        self.records[index]
            .as_ref()
            .is_some_and(|r| r.label == label)
            .then_some(index)
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

    /// Whether the record in `index` may make another through Child.
    pub fn may_make(&self, index: usize) -> bool {
        self.get(index).is_some_and(|r| r.children < CHILDREN_MAX)
    }

    /// A record of `process` with the label `next_label` gave, which the
    /// caller made its session with: O(1). Its maker counts it.
    ///
    /// # Panics
    /// When `label` is not that of `next_label`, or a maker is not live.
    pub fn insert(
        &mut self,
        label: Label,
        process: P,
        parent: u32,
        credentials: Credentials,
        maker: Option<Label>,
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
            children: 0,
            maker,
        });
        if let Some(m) = maker {
            self.records[usize::from(m.index)]
                .as_mut()
                .filter(|r| r.label == m)
                .expect("a live maker")
                .children += 1;
        }
        i
    }

    /// The record whose session has `label` goes, when it lives: its maker,
    /// if it still lives, counts one child less, and its index waits on
    /// top of the free ones, its next label one generation on. O(1).
    pub fn remove(&mut self, label: u64) -> Option<Record<P>> {
        let index = self.find(label)?;
        let record = self.records[index].take()?;
        if let Some(m) = record.maker
            && let Some(i) = self.find(m.raw())
            && let Some(maker) = self.records[i].as_mut()
        {
            maker.children -= 1;
        }
        self.free[self.free_len] = index as u16;
        self.free_len += 1;
        Some(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_process::INIT_PID;

    fn add(t: &mut Records<u32>, maker: Option<Label>) -> Option<Label> {
        let label = t.next_label()?;
        t.insert(label, 0, INIT_PID, Credentials::NOBODY, maker);
        Some(label)
    }

    #[test]
    fn the_bound_is_records_and_a_gone_record_frees_its_index() {
        let mut t = Records::<u32>::new();
        let labels: Vec<Label> = (0..RECORDS).map(|_| add(&mut t, None).unwrap()).collect();
        assert_eq!(t.count(), RECORDS);
        assert_eq!(t.next_label(), None, "FULL with every record taken");
        let gone = labels[17];
        assert!(t.remove(gone.raw()).is_some());
        assert!(t.remove(gone.raw()).is_none(), "a record goes once");
        assert_eq!(t.count(), RECORDS - 1);
        let next = add(&mut t, None).unwrap();
        assert_eq!(next.index, gone.index, "the index freed last comes first");
        assert_eq!(next.pid(), gone.pid() + RECORDS as u32, "one generation on");
        for label in labels.iter().filter(|l| **l != gone) {
            assert!(t.remove(label.raw()).is_some());
        }
        assert!(t.remove(next.raw()).is_some());
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn labels_the_service_did_not_give_name_no_record() {
        let mut t = Records::<u32>::new();
        let live = add(&mut t, None).unwrap();
        let stale = Label {
            generation: live.generation + 1,
            ..live
        };
        let free = Label {
            index: live.index + 1,
            ..live
        };
        assert_eq!(t.find(live.raw()), Some(usize::from(live.index)));
        for raw in [0, 0x1234, stale.raw(), free.raw(), live.raw() | 1 << 62] {
            assert_eq!(t.find(raw), None, "{raw:#x}");
            assert!(t.remove(raw).is_none(), "{raw:#x}");
        }
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn a_maker_makes_children_max_at_a_time() {
        let mut t = Records::<u32>::new();
        let maker = add(&mut t, None).unwrap();
        let index = usize::from(maker.index);
        let children: Vec<Label> = (0..CHILDREN_MAX)
            .map(|_| {
                assert!(t.may_make(index));
                add(&mut t, Some(maker)).unwrap()
            })
            .collect();
        assert!(!t.may_make(index), "FULL past CHILDREN_MAX");
        assert_eq!(t.get(index).unwrap().children, CHILDREN_MAX);
        assert!(t.remove(children[3].raw()).is_some());
        assert!(t.may_make(index), "a child that went frees its place");
        // A child outlives its maker; its end touches no other record.
        assert!(t.remove(maker.raw()).is_some());
        let other = add(&mut t, None).unwrap();
        assert_eq!(other.index, maker.index);
        assert!(t.remove(children[4].raw()).is_some());
        assert_eq!(t.get(index).unwrap().children, 0);
    }
}
