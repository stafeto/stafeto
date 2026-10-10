// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Service-driven private copies; the actor validates its group epoch at commit.

use super::{Kind, Lock, Owner, Range, budget, records};
use budget::Budget;
use records::{Id, Pool, Publish};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    NoLocks,
    Busy,
}
impl From<records::Error> for Error {
    fn from(error: records::Error) -> Self {
        match error {
            records::Error::Invalid => Self::Invalid,
            records::Error::NoLocks => Self::NoLocks,
        }
    }
}
impl From<budget::Error> for Error {
    fn from(error: budget::Error) -> Self {
        match error {
            budget::Error::Invalid => Self::Invalid,
            budget::Error::NoLocks => Self::NoLocks,
            budget::Error::Busy => Self::Busy,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Failure {
    pub error: Error,
    pub visited: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub visited: usize,
    pub ready: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Retirement {
    pub root: u16,
    pub head: Option<Id>,
    pub count: usize,
}
#[derive(Debug, PartialEq, Eq)]
pub struct Commit {
    pub root: u16,
    pub head: Option<Id>,
    pub count: usize,
    pub retired: Retirement,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Expand,
    Copy,
    Insert,
    Check,
    Mark,
    Ready,
    Committed,
    Cancelled,
}

/// Exclusive custody of one private copy and its logical preparation budget.
/// The source is canonical: disjoint regions with adjacent equal kinds merged.
/// The actor retains source records until this preparation finishes or aborts.
pub struct Prepare {
    root: u16,
    owner: Owner,
    kind: Option<Kind>,
    original: Range,
    expanded: Range,
    old_head: Option<Id>,
    old_count: usize,
    cursor: Option<Id>,
    seen: usize,
    head: Option<Id>,
    count: usize,
    pending: [Option<Lock>; 2],
    phase: Phase,
    publication: Option<Publish>,
    failure: Option<Error>,
    visited: usize,
}
impl Prepare {
    pub fn begin<const R: usize>(
        budget: &mut Budget<R>,
        root: u16,
        owner: Owner,
        old_head: Option<Id>,
        old_count: usize,
        kind: Option<Kind>,
        cut: Range,
    ) -> Result<Self, Error> {
        if old_head.is_none() != (old_count == 0) || old_count > budget::ROOT_LIVE {
            return Err(Error::Invalid);
        }
        budget.begin(root)?;
        Ok(Self {
            root,
            owner,
            kind,
            original: cut,
            expanded: cut,
            old_head,
            old_count,
            cursor: old_head,
            seen: 0,
            head: None,
            count: 0,
            pending: [None; 2],
            phase: if kind.is_some() {
                Phase::Expand
            } else {
                Phase::Copy
            },
            publication: None,
            failure: None,
            visited: 0,
        })
    }
    pub fn ready(&self) -> bool {
        self.phase == Phase::Ready && self.failure.is_none()
    }
    fn read<const N: usize, const R: usize, const S: usize>(
        &mut self,
        pool: &Pool<N, R, S>,
        id: Id,
    ) -> Result<records::Record, Error> {
        self.visited += 1;
        let record = *pool.read(id)?;
        if record.root() != self.root || record.lock.owner != self.owner || !record.is_published() {
            return Err(Error::Invalid);
        }
        self.seen += 1;
        if self.seen > self.old_count {
            return Err(Error::Invalid);
        }
        self.cursor = record.next;
        Ok(record)
    }
    fn allocate<const N: usize, const R: usize, const S: usize>(
        &mut self,
        pool: &mut Pool<N, R, S>,
        budget: &mut Budget<R>,
        lock: Lock,
    ) -> Result<(), Error> {
        self.visited += 1;
        if budget.can_charge_private()? != self.root {
            return Err(Error::Invalid);
        }
        let head = pool.prepend(self.root, lock, self.head)?;
        budget.charge_private().expect("preflighted private charge");
        self.head = Some(head);
        self.count += 1;
        Ok(())
    }
    /// The caller reserves group visits before passing its remaining allowance.
    pub fn step<const N: usize, const R: usize, const S: usize>(
        &mut self,
        pool: &mut Pool<N, R, S>,
        budget: &mut Budget<R>,
        limit: usize,
    ) -> Result<Progress, Failure> {
        if let Some(error) = self.failure {
            return Err(Failure { error, visited: 0 });
        }
        self.visited = 0;
        match self.step_inner(pool, budget, limit.min(records::PORTION)) {
            Ok(()) => Ok(Progress {
                visited: self.visited,
                ready: self.ready(),
            }),
            Err(error) => {
                self.failure = Some(error);
                Err(Failure {
                    error,
                    visited: self.visited,
                })
            }
        }
    }
    fn step_inner<const N: usize, const R: usize, const S: usize>(
        &mut self,
        pool: &mut Pool<N, R, S>,
        budget: &mut Budget<R>,
        limit: usize,
    ) -> Result<(), Error> {
        if matches!(self.phase, Phase::Committed | Phase::Cancelled)
            || budget.preparing() != Some(self.root)
        {
            return Err(Error::Invalid);
        }
        while self.visited < limit {
            match self.phase {
                Phase::Expand => {
                    if let Some(id) = self.cursor {
                        let record = self.read(pool, id)?;
                        let original = Lock {
                            owner: self.owner,
                            kind: self.kind.expect("set kind"),
                            range: self.original,
                        };
                        if record.lock.merge(original).is_some() {
                            self.expanded = self
                                .expanded
                                .merge(record.lock.range)
                                .expect("touches original");
                        }
                    } else {
                        if self.seen != self.old_count {
                            return Err(Error::Invalid);
                        }
                        self.cursor = self.old_head;
                        self.seen = 0;
                        self.phase = Phase::Copy;
                    }
                }
                Phase::Copy => {
                    if let Some(lock) = self.pending[0] {
                        self.allocate(pool, budget, lock)?;
                        self.pending = [self.pending[1], None];
                    } else if let Some(id) = self.cursor {
                        let record = self.read(pool, id)?;
                        self.pending = record.lock.remainder(self.owner, self.expanded);
                    } else {
                        if self.seen != self.old_count {
                            return Err(Error::Invalid);
                        }
                        self.phase = Phase::Insert;
                    }
                }
                Phase::Insert => {
                    if let Some(kind) = self.kind {
                        self.allocate(
                            pool,
                            budget,
                            Lock {
                                owner: self.owner,
                                kind,
                                range: self.expanded,
                            },
                        )?;
                    }
                    self.phase = Phase::Check;
                }
                Phase::Check => {
                    budget.can_publish(self.old_count)?;
                    self.publication = Some(Publish::new(self.head));
                    self.phase = Phase::Mark;
                }
                Phase::Mark => {
                    let remaining = limit - self.visited;
                    // A corrupt private chain reports the conservative remaining cost.
                    self.visited += remaining;
                    let progress = self
                        .publication
                        .as_mut()
                        .expect("mark custody")
                        .step_limit(pool, remaining)?;
                    self.visited -= remaining - progress.visited;
                    if progress.complete {
                        self.phase = Phase::Ready;
                    }
                }
                Phase::Ready => break,
                Phase::Committed | Phase::Cancelled => return Err(Error::Invalid),
            }
        }
        Ok(())
    }
    /// The actor checks the group's exact epoch before this constant exchange.
    /// A rejected exchange preserves private custody for cancel and cleanup.
    pub fn commit<const R: usize>(&mut self, budget: &mut Budget<R>) -> Result<Commit, Error> {
        if !self.ready() || budget.preparing() != Some(self.root) {
            return Err(Error::Invalid);
        }
        let head = self
            .publication
            .as_ref()
            .expect("complete marking")
            .head()?;
        budget.publish(self.old_count)?;
        self.phase = Phase::Committed;
        self.head = None;
        Ok(Commit {
            root: self.root,
            head,
            count: self.count,
            retired: Retirement {
                root: self.root,
                head: self.old_head,
                count: self.old_count,
            },
        })
    }
    /// Preserve every spent place through cleanup, including partially marked copies.
    pub fn cancel<const R: usize>(&mut self, budget: &mut Budget<R>) -> Result<Retirement, Error> {
        if matches!(self.phase, Phase::Committed | Phase::Cancelled)
            || budget.preparing() != Some(self.root)
        {
            return Err(Error::Invalid);
        }
        budget.cancel()?;
        self.phase = Phase::Cancelled;
        Ok(Retirement {
            root: self.root,
            head: self.head.take(),
            count: self.count,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use records::Reclaim;
    use std::vec::Vec;
    const OWNER: Owner = Owner::Process(256);
    fn range(start: usize, length: usize) -> Range {
        Range::relative(0, start as i64, length as i64).unwrap()
    }
    fn source<const N: usize>(
        pool: &mut Pool<N, 2, N>,
        budget: &mut Budget<2>,
        cells: &[u8],
        reverse: bool,
    ) -> (Option<Id>, usize) {
        let mut locks = Vec::new();
        let mut start = 0;
        while start < cells.len() {
            let value = cells[start];
            let mut end = start + 1;
            while end < cells.len() && cells[end] == value {
                end += 1;
            }
            if value != 0 {
                locks.push(Lock {
                    owner: OWNER,
                    kind: if value == 1 { Kind::Read } else { Kind::Write },
                    range: range(start, end - start),
                });
            }
            start = end;
        }
        if reverse {
            locks.reverse();
        }
        budget.begin(0).unwrap();
        let mut head = None;
        for lock in &locks {
            head = Some(pool.prepend(0, *lock, head).unwrap());
            budget.charge_private().unwrap();
        }
        let mut mark = Publish::new(head);
        while !mark.step(pool).unwrap().complete {}
        budget.publish(0).unwrap();
        (head, locks.len())
    }
    fn map<const N: usize>(pool: &Pool<N, 2, N>, mut head: Option<Id>, width: usize) -> Vec<u8> {
        let mut result = std::vec![0; width];
        let mut locks = Vec::new();
        while let Some(id) = head {
            let record = pool.read(id).unwrap();
            assert_eq!(record.lock.owner, OWNER);
            assert!(record.is_published());
            let lock = record.lock;
            for old in &locks {
                assert!(lock.merge(*old).is_none());
            }
            for (byte, value) in result.iter_mut().enumerate() {
                if lock.range.first() <= byte as u64 && byte as u64 <= lock.range.last() {
                    assert_eq!(*value, 0, "overlapping canonical regions");
                    *value = if lock.kind == Kind::Read { 1 } else { 2 };
                }
            }
            locks.push(lock);
            head = record.next;
        }
        result
    }
    fn reclaim<const N: usize>(
        pool: &mut Pool<N, 2, N>,
        budget: &mut Budget<2>,
        retired: Retirement,
    ) {
        let mut cleanup = Reclaim::new(retired.head);
        let mut total = 0;
        loop {
            let progress = cleanup.step_limit(pool, 1).unwrap();
            assert!(progress.released <= 1);
            budget
                .release_retired(retired.root, progress.released)
                .unwrap();
            total += progress.released;
            if progress.complete {
                break;
            }
        }
        assert_eq!(total, retired.count);
    }
    #[test]
    fn arbitrary_chain_order_matches_an_independent_six_byte_model() {
        let mut cases = 0;
        for encoded in 0..729 {
            let mut value = encoded;
            let mut cells = [0; 6];
            for byte in &mut cells {
                *byte = (value % 3) as u8;
                value /= 3;
            }
            for reverse in [false, true] {
                for start in 0..6 {
                    for length in 1..=6 - start {
                        for replacement in 0..3 {
                            let mut pool = Pool::<32, 2, 32>::new();
                            let mut budget = Budget::<2>::new();
                            let (head, count) = source(&mut pool, &mut budget, &cells, reverse);
                            let kind = match replacement {
                                0 => None,
                                1 => Some(Kind::Read),
                                _ => Some(Kind::Write),
                            };
                            let mut work = Prepare::begin(
                                &mut budget,
                                0,
                                OWNER,
                                head,
                                count,
                                kind,
                                range(start, length),
                            )
                            .unwrap();
                            let mut steps = 0;
                            while !work.ready() {
                                let progress = work.step(&mut pool, &mut budget, 7).unwrap();
                                assert!(progress.visited <= 7);
                                assert_eq!(map(&pool, head, 6), cells);
                                assert_eq!(budget.root(0).unwrap().published, count);
                                if !progress.ready {
                                    assert_eq!(work.commit(&mut budget), Err(Error::Invalid));
                                }
                                steps += 1;
                                assert!(steps < 20);
                            }
                            let commit = work.commit(&mut budget).unwrap();
                            let mut expected = cells;
                            expected[start..start + length].fill(replacement);
                            assert_eq!(map(&pool, commit.head, 6), expected);
                            let paid = pool.used(0).unwrap();
                            assert_eq!(budget.root(0).unwrap().paid(), paid);
                            reclaim(&mut pool, &mut budget, commit.retired);
                            assert_eq!(pool.used(0), Some(commit.count));
                            assert_eq!(budget.root(0).unwrap().paid(), commit.count);
                            cases += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 91_854);
    }
    #[test]
    fn cancellation_at_every_visit_keeps_source_and_paid_copy_until_cleanup() {
        let cells: Vec<u8> = (0..40).map(|n| if n % 2 == 0 { 2 } else { 0 }).collect();
        let mut positions = 0;
        for stop in 0..150 {
            let mut pool = Pool::<64, 2, 64>::new();
            let mut budget = Budget::<2>::new();
            let (head, count) = source(&mut pool, &mut budget, &cells, false);
            let mut work = Prepare::begin(
                &mut budget,
                0,
                OWNER,
                head,
                count,
                Some(Kind::Read),
                range(5, 10),
            )
            .unwrap();
            for _ in 0..stop {
                if work.ready() {
                    break;
                }
                assert!(work.step(&mut pool, &mut budget, 1).unwrap().visited <= 1);
            }
            let was_ready = work.ready();
            assert_eq!(map(&pool, head, cells.len()), cells);
            let paid = pool.used(0).unwrap();
            let retired = work.cancel(&mut budget).unwrap();
            assert_eq!(pool.used(0), Some(paid));
            assert_eq!(budget.root(0).unwrap().paid(), paid);
            assert_eq!(budget.root(0).unwrap().retired, retired.count);
            assert_eq!(work.cancel(&mut budget), Err(Error::Invalid));
            assert_eq!(work.commit(&mut budget), Err(Error::Invalid));
            reclaim(&mut pool, &mut budget, retired);
            assert_eq!(pool.used(0), Some(count));
            assert_eq!(budget.root(0).unwrap().published, count);
            assert_eq!(budget.root(0).unwrap().paid(), count);
            assert_eq!(map(&pool, head, cells.len()), cells);
            positions += 1;
            if was_ready {
                break;
            }
        }
        assert!(positions > 60);
        assert!(positions < 150);
    }
    #[test]
    fn allocation_failure_keeps_partial_copy_and_returns_exact_retirement() {
        let mut pool = Pool::<5, 2, 5>::new();
        let mut budget = Budget::<2>::new();
        let cells = [2, 0, 2, 0, 2];
        let (head, count) = source(&mut pool, &mut budget, &cells, false);
        let mut work =
            Prepare::begin(&mut budget, 0, OWNER, head, count, None, range(10, 1)).unwrap();
        let failure = work.step(&mut pool, &mut budget, 8).unwrap_err();
        assert_eq!(failure.error, Error::NoLocks);
        assert!(failure.visited <= 8);
        assert_eq!(
            work.step(&mut pool, &mut budget, 8),
            Err(Failure {
                error: Error::NoLocks,
                visited: 0
            })
        );
        assert_eq!(map(&pool, head, 5), cells);
        assert_eq!(pool.used(0), Some(5));
        assert_eq!(budget.root(0).unwrap().private, 2);
        let retired = work.cancel(&mut budget).unwrap();
        assert_eq!(retired.count, 2);
        assert_eq!(budget.root(0).unwrap().retired, 2);
        reclaim(&mut pool, &mut budget, retired);
        assert_eq!(pool.used(0), Some(3));
        assert_eq!(map(&pool, head, 5), cells);
    }
    #[test]
    fn malformed_source_owner_root_count_and_private_state_fail_before_publication() {
        for problem in 0..4 {
            let mut pool = Pool::<8, 2, 8>::new();
            let mut budget = Budget::<2>::new();
            let (head, count) = source(&mut pool, &mut budget, &[2], false);
            let owner = if problem == 0 {
                Owner::Process(257)
            } else {
                OWNER
            };
            let root = if problem == 1 { 1 } else { 0 };
            let count = if problem == 2 { count + 1 } else { count };
            let head = if problem == 3 {
                Some(
                    pool.prepend(
                        0,
                        Lock {
                            owner: OWNER,
                            kind: Kind::Read,
                            range: range(3, 1),
                        },
                        None,
                    )
                    .unwrap(),
                )
            } else {
                head
            };
            let mut work =
                Prepare::begin(&mut budget, root, owner, head, count, None, range(5, 1)).unwrap();
            let mut rejected = false;
            for _ in 0..32 {
                if let Err(failure) = work.step(&mut pool, &mut budget, 1) {
                    assert_eq!(failure.error, Error::Invalid);
                    assert!(failure.visited <= 1);
                    rejected = true;
                    break;
                }
                assert!(!work.ready(), "malformed source became ready");
            }
            assert!(rejected, "malformed source did not finish with Invalid");
            assert!(!work.ready());
            assert_eq!(work.commit(&mut budget), Err(Error::Invalid));
            let retired = work.cancel(&mut budget).unwrap();
            reclaim(&mut pool, &mut budget, retired);
        }
    }
    #[test]
    fn eof_replacement_and_unlock_preserve_the_finite_left_edge() {
        let mut pool = Pool::<32, 2, 32>::new();
        let mut budget = Budget::<2>::new();
        let cells = [2; 12];
        let (head, count) = source(&mut pool, &mut budget, &cells, false);
        let eof = Range::relative(0, 4, 0).unwrap();
        let mut set =
            Prepare::begin(&mut budget, 0, OWNER, head, count, Some(Kind::Read), eof).unwrap();
        while !set.ready() {
            set.step(&mut pool, &mut budget, 7).unwrap();
        }
        let commit = set.commit(&mut budget).unwrap();
        let mut expected = [1; 16];
        expected[..4].fill(2);
        assert_eq!(map(&pool, commit.head, 16), expected);
        reclaim(&mut pool, &mut budget, commit.retired);
        let mut unlock =
            Prepare::begin(&mut budget, 0, OWNER, commit.head, commit.count, None, eof).unwrap();
        while !unlock.ready() {
            unlock.step(&mut pool, &mut budget, 7).unwrap();
        }
        let commit = unlock.commit(&mut budget).unwrap();
        expected[4..].fill(0);
        assert_eq!(map(&pool, commit.head, 16), expected);
        assert_eq!(commit.count, 1);
        reclaim(&mut pool, &mut budget, commit.retired);
        assert_eq!(pool.used(0), Some(1));
    }

    #[test]
    fn marking_and_reclaim_use_the_remaining_allowance_including_zero_and_large_input() {
        let mut pool = Pool::<32, 2, 32>::new();
        let mut budget = Budget::<2>::new();
        let cells: Vec<u8> = (0..20).map(|n| if n % 2 == 0 { 2 } else { 0 }).collect();
        let (head, count) = source(&mut pool, &mut budget, &cells, false);
        let mut work =
            Prepare::begin(&mut budget, 0, OWNER, head, count, None, range(30, 1)).unwrap();
        assert_eq!(
            work.step(&mut pool, &mut budget, 0),
            Ok(Progress {
                visited: 0,
                ready: false
            })
        );
        while !work.ready() {
            let limit = if work.phase == Phase::Mark { 3 } else { 999 };
            let progress = work.step(&mut pool, &mut budget, limit).unwrap();
            assert!(progress.visited <= limit.min(records::PORTION));
        }
        let commit = work.commit(&mut budget).unwrap();
        let mut cleanup = Reclaim::new(commit.retired.head);
        assert_eq!(cleanup.step_limit(&mut pool, 0).unwrap().released, 0);
        assert_eq!(cleanup.step_limit(&mut pool, 3).unwrap().released, 3);
        budget.release_retired(0, 3).unwrap();
        let progress = cleanup.step_limit(&mut pool, 999).unwrap();
        assert_eq!(progress.released, 7);
        budget.release_retired(0, 7).unwrap();
        assert!(progress.complete);
        assert_eq!(map(&pool, commit.head, cells.len()), cells);
    }
}
