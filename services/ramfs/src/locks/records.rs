// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Paid immutable chains of lock regions. A preparation owns its private
//! chain until publication or bounded reclamation returns every charge.

use super::Lock;

const NONE: u16 = u16::MAX;
pub const PORTION: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NoLocks,
    Invalid,
}

/// One exact lifetime of a paid record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Id {
    slot: u16,
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub lock: Lock,
    pub next: Option<Id>,
    root: u16,
    private: bool,
}

impl Record {
    pub const fn root(self) -> u16 {
        self.root
    }
    pub const fn is_published(self) -> bool {
        !self.private
    }
}

#[derive(Clone, Copy)]
enum Slot {
    Fresh,
    Free(u16),
    Paid(Record),
    Exhausted,
}

/// The immutable region pool. Root charges cover both published records
/// and private preparation, with separate space left for other roots.
pub struct Pool<const N: usize, const ROOTS: usize, const SHARE: usize> {
    slots: [Slot; N],
    generations: [u64; N],
    used: [u16; ROOTS],
    fresh: u16,
    free: u16,
    available: u16,
}

impl<const N: usize, const ROOTS: usize, const SHARE: usize> Pool<N, ROOTS, SHARE> {
    pub const fn new() -> Self {
        assert!(N > 0 && N <= NONE as usize);
        assert!(ROOTS > 0 && ROOTS <= NONE as usize);
        assert!(SHARE > 0 && SHARE <= N);
        Self {
            slots: [Slot::Fresh; N],
            generations: [0; N],
            used: [0; ROOTS],
            fresh: 0,
            free: NONE,
            available: N as u16,
        }
    }

    pub const fn available(&self) -> usize {
        self.available as usize
    }

    pub fn used(&self, root: u16) -> Option<usize> {
        self.used.get(root as usize).map(|n| usize::from(*n))
    }

    pub fn get(&self, id: Id) -> Option<&Record> {
        if self.generations.get(id.slot as usize) != Some(&id.generation) {
            return None;
        }
        match self.slots.get(id.slot as usize)? {
            Slot::Paid(record) => Some(record),
            _ => None,
        }
    }

    /// A missing exact lifetime is an error during a chain walk.
    pub fn read(&self, id: Id) -> Result<&Record, Error> {
        self.get(id).ok_or(Error::Invalid)
    }

    fn mark_published(&mut self, id: Id) -> Result<Option<Id>, Error> {
        let record = *self.read(id)?;
        if !record.private {
            return Err(Error::Invalid);
        }
        let Slot::Paid(record) = &mut self.slots[id.slot as usize] else {
            unreachable!("validated paid record")
        };
        record.private = false;
        Ok(record.next)
    }

    /// Prepend to an exclusively owned chain. A record's next link is
    /// immutable; each allocation acquires its charge before returning.
    /// All records of a chain retain the same expenditure root and owner.
    pub fn prepend(&mut self, root: u16, lock: Lock, head: Option<Id>) -> Result<Id, Error> {
        let used = self.used.get(root as usize).ok_or(Error::Invalid)?;
        if let Some(head) = head {
            let record = self.get(head).ok_or(Error::Invalid)?;
            if !record.private || record.root != root || record.lock.owner != lock.owner {
                return Err(Error::Invalid);
            }
        }
        if *used as usize >= SHARE || self.available == 0 {
            return Err(Error::NoLocks);
        }
        let slot = if self.free != NONE {
            let slot = self.free;
            let Slot::Free(next) = self.slots[slot as usize] else {
                unreachable!("the free head is vacant")
            };
            self.free = next;
            slot
        } else {
            assert!((self.fresh as usize) < N);
            let slot = self.fresh;
            self.fresh += 1;
            slot
        };
        let index = slot as usize;
        // Exhausted generations are excluded from the free list.
        let generation = self.generations[index]
            .checked_add(1)
            .expect("fresh lifetime");
        self.generations[index] = generation;
        self.slots[index] = Slot::Paid(Record {
            lock,
            next: head,
            root,
            private: true,
        });
        self.used[root as usize] += 1;
        self.available -= 1;
        Ok(Id { slot, generation })
    }

    fn release(&mut self, id: Id) -> Result<Option<Id>, Error> {
        let record = *self.get(id).ok_or(Error::Invalid)?;
        let index = id.slot as usize;
        self.used[record.root as usize] -= 1;
        if id.generation == u64::MAX {
            self.slots[index] = Slot::Exhausted;
        } else {
            self.slots[index] = Slot::Free(self.free);
            self.free = id.slot;
            self.available += 1;
        }
        Ok(record.next)
    }
}

impl<const N: usize, const ROOTS: usize, const SHARE: usize> Default for Pool<N, ROOTS, SHARE> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationProgress {
    pub visited: usize,
    pub complete: bool,
}

/// Exclusive preparation custody until every record forbids a shared tail.
/// The group can switch its head only after marking completes.
pub struct Publish {
    head: Option<Id>,
    cursor: Option<Id>,
}

impl Publish {
    pub const fn new(head: Option<Id>) -> Self {
        Self { head, cursor: head }
    }

    pub fn head(&self) -> Result<Option<Id>, Error> {
        if self.cursor.is_some() {
            Err(Error::Invalid)
        } else {
            Ok(self.head)
        }
    }

    pub fn step<const N: usize, const ROOTS: usize, const SHARE: usize>(
        &mut self,
        pool: &mut Pool<N, ROOTS, SHARE>,
    ) -> Result<PublicationProgress, Error> {
        self.step_limit(pool, PORTION)
    }

    /// Spend only the caller's remaining portion, capped by PORTION.
    pub fn step_limit<const N: usize, const ROOTS: usize, const SHARE: usize>(
        &mut self,
        pool: &mut Pool<N, ROOTS, SHARE>,
        limit: usize,
    ) -> Result<PublicationProgress, Error> {
        let mut visited = 0;
        while visited < limit.min(PORTION) {
            let Some(cursor) = self.cursor else { break };
            self.cursor = pool.mark_published(cursor)?;
            visited += 1;
        }
        Ok(PublicationProgress {
            visited,
            complete: self.cursor.is_none(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub released: usize,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReclaimFailure {
    pub error: Error,
    /// Records freed by this failed invocation, still credited exactly once.
    pub released: usize,
}

/// Exclusive custody of a retired chain; retain this cursor while paid
/// records remain. Each step releases at most PORTION exact lifetimes.
pub struct Reclaim {
    head: Option<Id>,
    released_total: usize,
    failure: Option<ReclaimFailure>,
}

impl Reclaim {
    pub const fn new(head: Option<Id>) -> Self {
        Self {
            head,
            released_total: 0,
            failure: None,
        }
    }

    pub fn failure(&self) -> Option<ReclaimFailure> {
        self.failure
    }

    pub fn step<const N: usize, const ROOTS: usize, const SHARE: usize>(
        &mut self,
        pool: &mut Pool<N, ROOTS, SHARE>,
    ) -> Result<Progress, ReclaimFailure> {
        self.step_limit(pool, PORTION)
    }

    /// Group cleanup can reserve part of the portion for its own metadata.
    pub fn step_limit<const N: usize, const ROOTS: usize, const SHARE: usize>(
        &mut self,
        pool: &mut Pool<N, ROOTS, SHARE>,
        limit: usize,
    ) -> Result<Progress, ReclaimFailure> {
        if let Some(failure) = self.failure {
            return Err(ReclaimFailure {
                error: failure.error,
                released: 0,
            });
        }
        let mut released = 0;
        while released < limit.min(PORTION) {
            let Some(head) = self.head else { break };
            match pool.release(head) {
                Ok(next) => self.head = next,
                Err(error) => {
                    let failure = ReclaimFailure { error, released };
                    self.failure = Some(failure);
                    debug_assert!(
                        self.released_total == 0,
                        "invalid retired chain after paid progress: {failure:?}"
                    );
                    return Err(failure);
                }
            }
            released += 1;
            self.released_total += 1;
        }
        Ok(Progress {
            released,
            complete: self.head.is_none(),
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::locks::{Kind, Owner, Range};

    fn lock(start: i64) -> Lock {
        Lock {
            owner: Owner::Process(256),
            kind: Kind::Write,
            range: Range::relative(0, start, 1).unwrap(),
        }
    }

    #[test]
    fn published_chain_cannot_become_a_private_shared_tail() {
        let mut pool = Pool::<4, 1, 4>::new();
        let tail = pool.prepend(0, lock(0), None).unwrap();
        let head = pool.prepend(0, lock(1), Some(tail)).unwrap();
        let mut publication = Publish::new(Some(head));
        assert_eq!(publication.head(), Err(Error::Invalid));
        assert_eq!(
            publication.step(&mut pool),
            Ok(PublicationProgress {
                visited: 2,
                complete: true
            })
        );
        assert_eq!(publication.head(), Ok(Some(head)));
        assert_eq!(pool.prepend(0, lock(2), Some(head)), Err(Error::Invalid));
        assert_eq!(pool.prepend(0, lock(2), Some(tail)), Err(Error::Invalid));
        assert_eq!(pool.used(0), Some(2));
        assert_eq!(pool.available(), 2);
        assert_eq!(pool.read(head).unwrap().next, Some(tail));
        Reclaim::new(publication.head().unwrap())
            .step(&mut pool)
            .unwrap();
        assert_eq!(pool.read(head), Err(Error::Invalid));
        assert_eq!(pool.read(tail), Err(Error::Invalid));
    }

    #[test]
    fn publication_marks_at_most_eight_without_releasing_any_charge() {
        let mut pool = Pool::<20, 1, 20>::new();
        let mut head = None;
        for byte in 0..20 {
            head = Some(pool.prepend(0, lock(byte), head).unwrap());
        }
        let mut publication = Publish::new(head);
        for visited in [8, 8, 4] {
            let progress = publication.step(&mut pool).unwrap();
            assert_eq!(progress.visited, visited);
            assert_eq!(pool.used(0), Some(20));
            assert_eq!(pool.available(), 0);
        }
        assert_eq!(publication.head(), Ok(head));
        let mut cursor = publication.head().unwrap();
        while let Some(id) = cursor {
            let record = pool.read(id).unwrap();
            assert!(!record.private);
            cursor = record.next;
        }
        assert_eq!(
            publication.step(&mut pool),
            Ok(PublicationProgress {
                visited: 0,
                complete: true
            })
        );
    }

    #[test]
    fn one_root_cannot_consume_the_other_roots_record_reserve() {
        let mut pool = Pool::<12, 2, 8>::new();
        let mut head = None;
        for byte in 0..8 {
            head = Some(pool.prepend(0, lock(byte), head).unwrap());
        }
        assert_eq!(pool.prepend(0, lock(8), head), Err(Error::NoLocks));
        assert_eq!(pool.used(0), Some(8));
        let mut other = None;
        for byte in 0..4 {
            other = Some(pool.prepend(1, lock(byte), other).unwrap());
        }
        assert_eq!(pool.available(), 0);
        assert_eq!(pool.prepend(1, lock(4), other), Err(Error::NoLocks));
        assert!(pool.get(head.unwrap()).unwrap().next.is_some());
        let mut reclaim = Reclaim::new(head);
        assert_eq!(
            reclaim.step(&mut pool),
            Ok(Progress {
                released: 8,
                complete: true
            })
        );
        assert_eq!(pool.used(0), Some(0));
        assert_eq!(pool.used(1), Some(4));
        assert_eq!(pool.available(), 8);
    }

    #[test]
    fn reclaim_keeps_all_remaining_records_paid_and_stops_after_eight() {
        let mut pool = Pool::<20, 1, 20>::new();
        let mut head = None;
        for byte in 0..20 {
            head = Some(pool.prepend(0, lock(byte), head).unwrap());
        }
        let mut reclaim = Reclaim::new(head);
        for (released, remaining) in [(8, 12), (8, 4), (4, 0)] {
            assert_eq!(
                reclaim.step(&mut pool),
                Ok(Progress {
                    released,
                    complete: remaining == 0
                })
            );
            assert_eq!(pool.used(0), Some(remaining));
            assert_eq!(pool.available(), 20 - remaining);
        }
        assert_eq!(
            reclaim.step(&mut pool),
            Ok(Progress {
                released: 0,
                complete: true
            })
        );
    }

    #[test]
    fn stale_chain_cannot_release_or_link_a_reused_record() {
        let mut pool = Pool::<1, 1, 1>::new();
        let old = pool.prepend(0, lock(0), None).unwrap();
        Reclaim::new(Some(old)).step(&mut pool).unwrap();
        let new = pool.prepend(0, lock(1), None).unwrap();
        assert_eq!(old.slot, new.slot);
        assert_ne!(old.generation, new.generation);
        assert_eq!(
            Reclaim::new(Some(old)).step(&mut pool),
            Err(ReclaimFailure {
                error: Error::Invalid,
                released: 0
            })
        );
        assert_eq!(pool.prepend(0, lock(2), Some(old)), Err(Error::Invalid));
        assert_eq!(pool.used(0), Some(1));
        assert_eq!(pool.get(new).unwrap().lock, lock(1));
    }

    #[test]
    fn invalid_retired_tail_reports_prior_releases_once_and_keeps_new_custody() {
        let mut pool = Pool::<4, 1, 4>::new();
        let stale = pool.prepend(0, lock(0), None).unwrap();
        Reclaim::new(Some(stale)).step(&mut pool).unwrap();
        let fresh = pool.prepend(0, lock(1), None).unwrap();
        assert_eq!(fresh.slot, stale.slot);
        let head = pool.prepend(0, lock(2), None).unwrap();
        let Slot::Paid(record) = &mut pool.slots[head.slot as usize] else {
            panic!("paid head")
        };
        // Simulate an internal stale link, preserving the newly paid record.
        record.next = Some(stale);
        let mut reclaim = Reclaim::new(Some(head));
        #[cfg(debug_assertions)]
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { reclaim.step(&mut pool) }))
                .is_err()
        );
        #[cfg(not(debug_assertions))]
        assert_eq!(
            reclaim.step(&mut pool),
            Err(ReclaimFailure {
                error: Error::Invalid,
                released: 1
            })
        );
        assert_eq!(
            reclaim.failure(),
            Some(ReclaimFailure {
                error: Error::Invalid,
                released: 1
            })
        );
        assert_eq!(pool.used(0), Some(1));
        assert_eq!(pool.available(), 3);
        assert_eq!(pool.read(fresh).unwrap().lock, lock(1));
        assert_eq!(
            reclaim.step(&mut pool),
            Err(ReclaimFailure {
                error: Error::Invalid,
                released: 0
            })
        );
        assert_eq!(pool.used(0), Some(1));
    }

    #[test]
    fn invalid_roots_and_foreign_chains_have_no_allocation_effect() {
        let mut pool = Pool::<4, 2, 4>::new();
        assert_eq!(pool.prepend(2, lock(0), None), Err(Error::Invalid));
        let head = pool.prepend(0, lock(0), None).unwrap();
        assert_eq!(pool.prepend(1, lock(1), Some(head)), Err(Error::Invalid));
        let foreign = Lock {
            owner: Owner::Process(512),
            ..lock(1)
        };
        assert_eq!(pool.prepend(0, foreign, Some(head)), Err(Error::Invalid));
        assert_eq!(pool.available(), 3);
        assert_eq!(pool.used(0), Some(1));
        assert_eq!(pool.used(1), Some(0));
    }

    #[test]
    fn exhausted_record_lifetimes_return_charges_and_never_wrap() {
        let mut pool = Pool::<2, 1, 2>::new();
        pool.generations[0] = u64::MAX - 1;
        let last = pool.prepend(0, lock(0), None).unwrap();
        assert_eq!(last.generation, u64::MAX);
        Reclaim::new(Some(last)).step(&mut pool).unwrap();
        assert_eq!(pool.used(0), Some(0));
        assert_eq!(pool.available(), 1);
        let other = pool.prepend(0, lock(1), None).unwrap();
        assert_ne!(other.slot, last.slot);
        assert_eq!(pool.prepend(0, lock(2), None), Err(Error::NoLocks));
        assert_eq!(pool.get(last), None);
    }
}
