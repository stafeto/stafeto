// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Generations and detach states in the existing Place state word.

use core::sync::atomic::{AtomicU64, Ordering};

pub(super) const FREE: u64 = 0;
pub(super) const MAKING: u64 = 1;
pub(super) const LIVE: u64 = 2;
pub(super) const EXITED: u64 = 4;
pub(super) const RELEASED: u64 = 8;
pub(super) const DETACHING: u64 = 16;
pub(super) const DETACHED: u64 = 32;
const FLAGS: u64 = 63;
const MAX_GENERATION: u64 = u64::MAX >> 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerStatus {
    Alive,
    Detaching,
    Detached,
    Gone,
}

#[repr(transparent)]
pub(super) struct Lifetime(AtomicU64);

impl Lifetime {
    pub(super) const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub(super) fn load(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    pub(super) fn flags(&self) -> u64 {
        self.load() & FLAGS
    }

    pub(super) fn main(&self) {
        self.0.store((1 << 6) | LIVE, Ordering::Release);
    }

    /// Reserve a new lifetime. The final generation is a tombstone.
    pub(super) fn reserve(&self) -> bool {
        let old = self.load();
        if old & FLAGS != FREE || old >> 6 == MAX_GENERATION {
            return false;
        }
        let next = (old >> 6) + 1;
        let flags = if next == MAX_GENERATION { FREE } else { MAKING };
        self.0
            .compare_exchange(
                old,
                (next << 6) | flags,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
            && next != MAX_GENERATION
    }

    pub(super) fn set_flags(&self, flags: u64) {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                Some((old & !FLAGS) | flags)
            })
            .expect("flags update is unconditional");
    }

    /// A failed native start preserves a concurrent final detach.
    pub(super) fn rollback(&self) {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                Some((old & !LIVE) | MAKING)
            })
            .expect("rollback preserves the reserved lifetime");
    }

    pub(super) fn add_flags(&self, flags: u64) {
        self.0.fetch_or(flags, Ordering::AcqRel);
    }

    pub(super) fn token(&self, index: usize) -> Option<u64> {
        let state = self.load();
        let generation = state >> 6;
        (index < 64 && generation != 0 && generation != MAX_GENERATION)
            .then_some((generation << 6) | index as u64)
    }

    pub(super) fn owner(&self, index: usize) -> Option<u64> {
        let state = self.load();
        (index < 64 && state & (LIVE | DETACHING | DETACHED) == LIVE)
            .then_some((state & !FLAGS) | index as u64)
            .filter(|value| *value >> 6 != 0 && *value >> 6 != MAX_GENERATION)
    }

    pub(super) fn status(&self, owner: u64) -> OwnerStatus {
        let state = self.load();
        if state & !FLAGS != owner & !FLAGS || state & (LIVE | MAKING) == 0 {
            OwnerStatus::Gone
        } else if state & DETACHED != 0 {
            OwnerStatus::Detached
        } else if state & DETACHING != 0 {
            OwnerStatus::Detaching
        } else {
            OwnerStatus::Alive
        }
    }

    pub(super) fn begin_detach(&self, owner: u64) -> OwnerStatus {
        loop {
            let state = self.load();
            match self.status(owner) {
                OwnerStatus::Alive => {}
                status => return status,
            }
            if self
                .0
                .compare_exchange(
                    state,
                    state | DETACHING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return OwnerStatus::Detaching;
            }
        }
    }

    pub(super) fn finish_detach(&self, owner: u64) -> bool {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                (state & !FLAGS == owner & !FLAGS && state & DETACHING != 0)
                    .then_some((state & !DETACHING) | DETACHED)
            })
            .is_ok()
    }

    pub(super) fn claim_collect(&self) -> bool {
        let state = self.load();
        state & FLAGS == LIVE | EXITED | RELEASED | DETACHED
            && self
                .0
                .compare_exchange(
                    state,
                    (state & !FLAGS) | MAKING | DETACHED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
    }

    /// Child-exclusive fork discards the inherited recovery records first.
    pub(super) fn after_fork(&self, survivor: bool) {
        self.set_flags(if survivor { LIVE } else { FREE });
    }

    pub(super) fn free(&self) {
        assert!(self.flags() & DETACHED != 0, "detach precedes Place reuse");
        self.set_flags(FREE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_and_permanent_main() {
        assert_eq!(core::mem::size_of::<Lifetime>(), 8);
        let state = Lifetime::new();
        state.main();
        assert_eq!(state.owner(0), Some(64));
        assert!(!state.reserve());
    }

    #[test]
    fn lifetime_reuse_rejects_old_owner_and_finish() {
        let state = Lifetime::new();
        assert!(state.reserve());
        state.set_flags(LIVE);
        let first = state.owner(63).unwrap();
        state.begin_detach(first);
        assert!(state.finish_detach(first));
        state.add_flags(EXITED | RELEASED);
        assert!(state.claim_collect());
        state.free();
        assert!(state.reserve());
        state.set_flags(LIVE);
        let second = state.owner(63).unwrap();
        assert_ne!(first, second);
        assert_eq!(state.status(first), OwnerStatus::Gone);
        assert!(!state.finish_detach(first));
        assert_eq!(state.owner(63), Some(second));
    }

    #[test]
    fn max_transition_mints_no_owner_and_existing_cleanup_works() {
        let state = Lifetime(AtomicU64::new(((MAX_GENERATION - 2) << 6) | FREE));
        assert!(state.reserve());
        state.set_flags(LIVE);
        let owner = state.owner(1).unwrap();
        assert_eq!(owner >> 6, MAX_GENERATION - 1);
        state.begin_detach(owner);
        state.finish_detach(owner);
        state.set_flags(MAKING | DETACHED);
        state.free();
        assert!(!state.reserve());
        assert_eq!(state.load() >> 6, MAX_GENERATION);
        assert_eq!(state.owner(1), None);
        assert_eq!(state.token(1), None);
        assert!(!state.reserve());
    }

    #[test]
    fn all_paid_rows_reuse_only_after_deferred_detach_retry() {
        let rows: [Lifetime; 63] = core::array::from_fn(|_| Lifetime::new());
        for (index, row) in rows.iter().enumerate() {
            assert!(row.reserve());
            row.set_flags(LIVE | EXITED | RELEASED);
            row.begin_detach(row.token(index + 1).unwrap());
        }
        assert!(
            rows.iter()
                .all(|row| !row.reserve() && !row.claim_collect())
        );
        for (index, row) in rows.iter().enumerate() {
            let owner = row.token(index + 1).unwrap();
            assert_eq!(row.status(owner), OwnerStatus::Detaching);
            assert!(row.finish_detach(owner));
            assert!(row.claim_collect());
            row.free();
            assert!(row.reserve());
            assert_ne!(row.token(index + 1), Some(owner));
        }
    }

    #[test]
    fn deferred_detach_preserves_charged_row_until_retry() {
        let state = Lifetime::new();
        assert!(state.reserve());
        state.set_flags(LIVE | EXITED | RELEASED);
        let owner = state.token(5).unwrap();
        assert_eq!(state.begin_detach(owner), OwnerStatus::Detaching);
        // A busy callback completes no local transition.
        assert_eq!(state.status(owner), OwnerStatus::Detaching);
        assert!(!state.claim_collect());
        assert!(!state.reserve());
        assert_eq!(state.token(5), Some(owner));
        assert!(state.finish_detach(owner));
        assert!(state.claim_collect());
        state.free();
        assert!(state.reserve());
        assert_ne!(state.token(5), Some(owner));
    }

    #[test]
    fn native_ended_detaches_before_release_without_collecting() {
        let state = Lifetime::new();
        state.reserve();
        state.set_flags(LIVE);
        let owner = state.owner(2).unwrap();
        assert_eq!(state.begin_detach(owner), OwnerStatus::Detaching);
        assert_eq!(state.owner(2), None);
        assert!(!state.claim_collect());
        state.finish_detach(owner);
        assert!(!state.claim_collect());
        state.add_flags(EXITED);
        assert!(!state.claim_collect());
        state.add_flags(RELEASED);
        assert!(state.claim_collect());
    }

    #[test]
    fn release_and_exit_metadata_require_completed_owner_detach() {
        let state = Lifetime::new();
        state.reserve();
        state.set_flags(LIVE | EXITED | RELEASED);
        let owner = state.token(1).unwrap();
        assert!(!state.claim_collect());
        state.begin_detach(owner);
        assert!(!state.claim_collect());
        state.finish_detach(owner);
        assert!(state.claim_collect());
    }

    #[test]
    fn detach_helper_death_allows_idempotent_sibling_completion() {
        let state = Lifetime::new();
        state.reserve();
        state.set_flags(LIVE);
        let owner = state.owner(1).unwrap();
        state.begin_detach(owner);
        assert_eq!(state.begin_detach(owner), OwnerStatus::Detaching);
        assert!(state.finish_detach(owner));
        assert_eq!(state.begin_detach(owner), OwnerStatus::Detached);
        assert!(!state.finish_detach(owner));
    }

    #[test]
    fn start_rollback_consumes_generation_before_free() {
        let state = Lifetime::new();
        state.reserve();
        let owner = state.token(1).unwrap();
        assert_eq!(state.owner(1), None);
        state.begin_detach(owner);
        state.finish_detach(owner);
        state.free();
        state.reserve();
        assert_ne!(state.token(1), Some(owner));
    }

    #[test]
    fn start_failure_preserves_completed_final_detach() {
        let state = Lifetime::new();
        state.reserve();
        state.set_flags(LIVE);
        let owner = state.owner(1).unwrap();
        state.begin_detach(owner);
        state.finish_detach(owner);
        state.rollback();
        assert_eq!(state.status(owner), OwnerStatus::Detached);
        assert!(!state.finish_detach(owner));
        state.free();
        assert_eq!(state.flags(), FREE);
    }

    #[test]
    fn fork_preserves_generations_and_reinitializes_flags() {
        let state = Lifetime::new();
        state.reserve();
        state.set_flags(LIVE);
        let owner = state.owner(7).unwrap();
        state.begin_detach(owner);
        state.after_fork(true);
        assert_eq!(state.owner(7), Some(owner));
        state.after_fork(false);
        assert_eq!(state.flags(), FREE);
        state.reserve();
        assert_ne!(state.token(7), Some(owner));
    }

    #[test]
    fn cleanup_handler_new_open_is_discarded_by_final_detach() {
        use posix_fd::{Abandoned, Flags, OwnerToken, Table};
        let state = Lifetime::new();
        state.reserve();
        state.set_flags(LIVE);
        let value = state.owner(3).unwrap();
        let owner = OwnerToken::new(value).unwrap();
        let mut table = Table::<u32, 4, u64>::default();
        let (interrupted, claim) = table.begin_open(owner, 100).unwrap();
        table.reserve_open(claim, 0, Flags::default()).unwrap();
        table.release_claim(claim).unwrap();
        // The cancellation boundary abandons its exact interrupted operation.
        table.abandon_open(interrupted).unwrap();
        assert_eq!(state.owner(3), Some(value));
        // A user cleanup handler opens another file on the same live owner.
        let (cleanup, claim) = table.begin_open(owner, 101).unwrap();
        let entry = table.reserve_open(claim, 0, Flags::default()).unwrap();
        table.stage_committed(claim, 42).unwrap();
        table.publish_open(claim).unwrap();
        state.begin_detach(value);
        assert!(matches!(
            table.abandon_owner(owner),
            Some(Abandoned::Discarded {
                release: Some(42),
                ..
            })
        ));
        assert!(table.open_snapshot(cleanup).is_err());
        assert!(table.get(entry.fd).is_err());
        assert_eq!(table.abandon_owner(owner), None);
        state.finish_detach(value);
        assert_eq!(state.status(value), OwnerStatus::Detached);
        // The interrupted record stays resident for a live sibling's cleanup.
        assert_eq!(table.open_snapshot(interrupted).unwrap().owner, None);
    }

    #[test]
    fn live_sibling_reclaims_pending_before_dead_owner_join() {
        use posix_fd::{Claim, Flags, OwnerToken, Replacement, Table};
        let state = Lifetime::new();
        state.reserve();
        state.set_flags(LIVE);
        let value = state.owner(1).unwrap();
        let owner = OwnerToken::new(value).unwrap();
        let helper = OwnerToken::new(66).unwrap();
        let mut table = Table::<u32, 4, u64>::default();
        let source = table.insert(12, Flags::default()).unwrap();
        let (open, claim) = table.begin_open(owner, 100).unwrap();
        let pending = table.reserve_open(claim, 0, Flags::default()).unwrap();
        assert_eq!(
            table.try_dup2(source, pending.fd),
            Ok(Replacement::Pending(open))
        );
        assert_eq!(table.claim_open(open, helper), Ok(Claim::Busy(owner)));
        // Native Ended was verified by the collector; no relibc release yet.
        state.begin_detach(value);
        table.abandon_owner(owner).unwrap();
        state.finish_detach(value);
        assert!(!state.claim_collect());
        let Claim::Acquired { token: claim, .. } = table.claim_open(open, helper).unwrap() else {
            panic!("sibling acquires the abandoned exact operation")
        };
        table.begin_cancel(claim).unwrap();
        table.finish_cancel(open, 5).unwrap();
        assert!(table.open_snapshot(open).is_err());
        assert_eq!(table.dup2(source, pending.fd), Ok((pending.fd, None)));
        assert_eq!(table.get(pending.fd), Ok(12));
    }
}
