// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Generations and detach states in the existing Place state word.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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

/// What `claim_collect_unpinned` did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Claim {
    /// The row is the collector's.
    Taken,
    /// The row is not collectible yet.
    Unready,
    /// A sender pins the row; it stays for the next pass.
    Pinned,
}

/// A sender's pin of a row: the collector leaves the row alone while a pin
/// stands. Dropping it gives the pin back.
pub(super) struct Pin<'a> {
    pins: &'a AtomicU32,
    index: usize,
    on_last: fn(usize),
}

impl Drop for Pin<'_> {
    fn drop(&mut self) {
        if self.pins.fetch_sub(1, Ordering::SeqCst) == 1 {
            (self.on_last)(self.index);
        }
    }
}

impl Lifetime {
    pub(super) const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub(super) fn load(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    /// The word with the order of the pin protocol: a total order with the
    /// sender's `PINS` increment and the collector's claim.
    pub(super) fn load_seq(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
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

    /// Renew a detached native scope in the same live kernel-thread row.
    /// The final generation keeps the resident row charged until actual End.
    pub(super) fn renew_native_scope(&self) -> bool {
        let old = self.load();
        if old & FLAGS != LIVE | DETACHED || old >> 6 == MAX_GENERATION {
            return false;
        }
        let next = (old >> 6) + 1;
        let flags = if next == MAX_GENERATION {
            LIVE | DETACHED
        } else {
            LIVE
        };
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
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |old| {
                Some((old & !LIVE) | MAKING)
            })
            .expect("rollback preserves the reserved lifetime");
    }

    /// Direct kernel exit has no libc join owner. A libc EXITED row retains
    /// its published return value until join or detach supplies RELEASED.
    pub(super) fn native_ended(&self) {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                Some(if old & LIVE == 0 {
                    old
                } else {
                    old | EXITED | if old & EXITED == 0 { RELEASED } else { 0 }
                })
            })
            .expect("End preserves lifetime generation");
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

    /// Takes the row for collection; gives its word before the claim.
    /// SeqCst: the claim and the sender's pin are ordered in one total order.
    pub(super) fn claim_collect(&self) -> Option<u64> {
        let state = self.load();
        (state & FLAGS == LIVE | EXITED | RELEASED | DETACHED
            && self
                .0
                .compare_exchange(
                    state,
                    (state & !FLAGS) | MAKING | DETACHED,
                    Ordering::SeqCst,
                    Ordering::Acquire,
                )
                .is_ok())
        .then_some(state)
    }

    /// Gives back a claim whose row a sender pinned: the word `prior`
    /// returns. Only the collector holds the row in MAKING | DETACHED, so
    /// the exchange cannot fail.
    pub(super) fn unclaim(&self, prior: u64) {
        self.0
            .compare_exchange(
                (prior & !FLAGS) | MAKING | DETACHED,
                prior,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .expect("unclaim of a row that is not the collector's claim");
    }

    /// Claims the row for collection unless a sender pins it: `pinned`
    /// tells whether one does. Both sides of the claim are looked at, so a
    /// sender whose pin came after the first look sees MAKING (and goes)
    /// or the collector sees the pin (and gives the row back).
    pub(super) fn claim_collect_unpinned(&self, pinned: impl Fn() -> bool) -> Claim {
        if pinned() {
            return Claim::Pinned;
        }
        let Some(prior) = self.claim_collect() else {
            return Claim::Unready;
        };
        if pinned() {
            self.unclaim(prior);
            return Claim::Pinned;
        }
        Claim::Taken
    }

    /// The sender's side: pins the row of a live thread, or None (ESRCH).
    /// The pin is a count in `pins` (SeqCst), then the word is read again
    /// (SeqCst): the collector writes the word and then reads the count, so
    /// one of the two sees the other. The generation must be the same and
    /// the row LIVE and not MAKING; the flags that the live thread changes
    /// itself (EXITED, RELEASED, DETACHING, DETACHED) are not compared.
    /// `on_last` runs for the sender whose release brought the count to
    /// zero.
    pub(super) fn try_pin<'a>(
        &self,
        pins: &'a AtomicU32,
        index: usize,
        on_last: fn(usize),
    ) -> Option<Pin<'a>> {
        let seen = self.load();
        if seen & (LIVE | MAKING) != LIVE {
            return None;
        }
        pins.fetch_add(1, Ordering::SeqCst);
        let pin = Pin {
            pins,
            index,
            on_last,
        };
        let now = self.load_seq();
        (now >> 6 == seen >> 6 && now & (LIVE | MAKING) == LIVE).then_some(pin)
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
    fn native_cleanup_debt_stays_making_on_repeated_end_observation() {
        let row = Lifetime::new();
        assert!(row.reserve());
        row.set_flags(LIVE);
        let owner = row.owner(1).unwrap();
        row.begin_detach(owner);
        row.finish_detach(owner);
        row.native_ended();
        assert!(row.claim_collect().is_some());
        let claimed = row.load();
        row.native_ended();
        assert_eq!(row.load(), claimed);
        assert_eq!(row.flags(), MAKING | DETACHED);
        assert!(!row.reserve());
    }

    #[test]
    fn native_libc_joinable_end_keeps_return_value_until_release() {
        let row = Lifetime::new();
        assert!(row.reserve());
        row.set_flags(LIVE);
        let owner = row.owner(1).unwrap();
        row.begin_detach(owner);
        row.finish_detach(owner);
        row.add_flags(EXITED);
        row.native_ended();
        assert_eq!(row.flags(), LIVE | EXITED | DETACHED);
        assert!(row.claim_collect().is_none());
        row.add_flags(RELEASED);
        assert!(row.claim_collect().is_some());
    }

    #[test]
    fn native_direct_kernel_end_and_detached_libc_end_are_collectible() {
        for libc_detached in [false, true] {
            let row = Lifetime::new();
            assert!(row.reserve());
            row.set_flags(LIVE);
            let owner = row.owner(1).unwrap();
            row.begin_detach(owner);
            row.finish_detach(owner);
            if libc_detached {
                row.add_flags(EXITED | RELEASED);
            }
            row.native_ended();
            assert!(row.claim_collect().is_some());
        }
    }

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
        assert!(state.claim_collect().is_some());
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
                .all(|row| !row.reserve() && row.claim_collect().is_none())
        );
        for (index, row) in rows.iter().enumerate() {
            let owner = row.token(index + 1).unwrap();
            assert_eq!(row.status(owner), OwnerStatus::Detaching);
            assert!(row.finish_detach(owner));
            assert!(row.claim_collect().is_some());
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
        assert!(state.claim_collect().is_none());
        assert!(!state.reserve());
        assert_eq!(state.token(5), Some(owner));
        assert!(state.finish_detach(owner));
        assert!(state.claim_collect().is_some());
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
        assert!(state.claim_collect().is_none());
        state.finish_detach(owner);
        assert!(state.claim_collect().is_none());
        state.add_flags(EXITED);
        assert!(state.claim_collect().is_none());
        state.add_flags(RELEASED);
        assert!(state.claim_collect().is_some());
    }

    #[test]
    fn release_and_exit_metadata_require_completed_owner_detach() {
        let state = Lifetime::new();
        state.reserve();
        state.set_flags(LIVE | EXITED | RELEASED);
        let owner = state.token(1).unwrap();
        assert!(state.claim_collect().is_none());
        state.begin_detach(owner);
        assert!(state.claim_collect().is_none());
        state.finish_detach(owner);
        assert!(state.claim_collect().is_some());
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
        assert!(state.claim_collect().is_none());
        let Claim::Acquired { token: claim, .. } = table.claim_open(open, helper).unwrap() else {
            panic!("sibling acquires the abandoned exact operation")
        };
        table.begin_cancel(claim).unwrap();
        table.finish_cancel(open, 5).unwrap();
        assert!(table.open_snapshot(open).is_err());
        assert_eq!(table.dup2(source, pending.fd), Ok((pending.fd, None)));
        assert_eq!(table.get(pending.fd), Ok(12));
    }
    #[test]
    fn native_sequential_scopes_preserve_row_and_reject_old_owner() {
        let row = Lifetime::new();
        row.reserve();
        row.set_flags(LIVE);
        let first = row.owner(7).unwrap();
        row.begin_detach(first);
        assert!(!row.renew_native_scope());
        assert!(!row.reserve());
        row.finish_detach(first);
        assert!(row.renew_native_scope());
        let second = row.owner(7).unwrap();
        assert_ne!(first, second);
        assert_eq!(row.status(first), OwnerStatus::Gone);
        assert!(!row.finish_detach(first));
        assert!(row.claim_collect().is_none());
        assert!(!row.reserve());
        row.begin_detach(second);
        row.finish_detach(second);
        assert!(row.claim_collect().is_none());
        row.add_flags(EXITED | RELEASED);
        assert!(row.claim_collect().is_some());
        row.free();
        assert!(row.reserve());
    }
    #[test]
    fn native_generation_exhaustion_keeps_resident_custody_until_end() {
        let row = Lifetime(AtomicU64::new(
            ((MAX_GENERATION - 1) << 6) | LIVE | DETACHED,
        ));
        assert!(!row.renew_native_scope());
        assert_eq!(row.flags(), LIVE | DETACHED);
        assert_eq!(row.token(5), None);
        assert!(!row.reserve());
        row.add_flags(EXITED | RELEASED);
        assert!(row.claim_collect().is_some());
        row.free();
        assert!(!row.reserve());
    }

    #[test]
    fn claim_gives_the_prior_word_and_unclaim_restores_it() {
        let row = Lifetime::new();
        assert!(row.reserve());
        row.set_flags(LIVE | EXITED | RELEASED | DETACHED);
        let before = row.load();
        let prior = row.claim_collect().expect("collectible");
        assert_eq!(prior, before);
        assert_eq!(row.flags(), MAKING | DETACHED);
        row.unclaim(prior);
        assert_eq!(row.load(), before);
        assert_eq!(before >> 6, 1, "the generation is the same");
        assert!(row.claim_collect().is_some());
    }

    #[test]
    #[should_panic(expected = "unclaim of a row that is not the collector's claim")]
    fn unclaim_of_a_foreign_word_panics() {
        let row = Lifetime::new();
        assert!(row.reserve());
        row.set_flags(LIVE | EXITED | RELEASED | DETACHED);
        let prior = row.claim_collect().unwrap();
        row.free();
        row.unclaim(prior);
    }

    #[test]
    fn a_pin_stops_the_claim_and_leaves_the_row_whole() {
        let row = Lifetime::new();
        assert!(row.reserve());
        row.set_flags(LIVE | EXITED | RELEASED | DETACHED);
        let pins = AtomicU32::new(0);
        let pin = row.try_pin(&pins, 0, |_| {}).expect("a live row");
        let before = row.load();
        let pinned = || pins.load(Ordering::SeqCst) != 0;
        assert_eq!(row.claim_collect_unpinned(pinned), Claim::Pinned);
        assert_eq!(row.load(), before);
        drop(pin);
        assert_eq!(pins.load(Ordering::SeqCst), 0);
        assert_eq!(row.claim_collect_unpinned(pinned), Claim::Taken);
        assert!(row.try_pin(&pins, 0, |_| {}).is_none());
        assert_eq!(
            pins.load(Ordering::SeqCst),
            0,
            "a refused pin is given back"
        );
    }

    #[test]
    fn a_pin_taken_between_the_looks_is_given_back_by_the_collector() {
        let row = Lifetime::new();
        assert!(row.reserve());
        row.set_flags(LIVE | EXITED | RELEASED | DETACHED);
        let pins = AtomicU32::new(0);
        let before = row.load();
        let looks = core::cell::Cell::new(0);
        // The first look finds no pin, the second finds one: the pin of a
        // sender that came between the two.
        let claim = row.claim_collect_unpinned(|| {
            looks.set(looks.get() + 1);
            if looks.get() == 2 {
                pins.store(1, Ordering::SeqCst);
            }
            pins.load(Ordering::SeqCst) != 0
        });
        assert_eq!(claim, Claim::Pinned);
        assert_eq!(row.load(), before);
    }

    #[test]
    fn the_last_release_runs_on_last_once() {
        use core::sync::atomic::AtomicUsize;
        static LAST: AtomicUsize = AtomicUsize::new(0);
        fn on_last(index: usize) {
            LAST.fetch_add(index + 1, Ordering::SeqCst);
        }
        let row = Lifetime::new();
        assert!(row.reserve());
        row.set_flags(LIVE);
        let pins = AtomicU32::new(0);
        let first = row.try_pin(&pins, 6, on_last).unwrap();
        let second = row.try_pin(&pins, 6, on_last).unwrap();
        drop(first);
        assert_eq!(LAST.load(Ordering::SeqCst), 0);
        drop(second);
        assert_eq!(LAST.load(Ordering::SeqCst), 7);
    }

    /// Senders pin a place and read its resource; the collector frees the
    /// resource only for a place it took, and then makes a new generation.
    /// No sender reads a freed resource.
    #[test]
    fn senders_never_read_a_resource_the_collector_freed() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        const FREED: u64 = u64::MAX;
        const ROUNDS: u64 = 100_000;
        struct Shared {
            row: Lifetime,
            pins: AtomicU32,
            resource: AtomicU64,
            done: AtomicBool,
            bad: AtomicU64,
            reads: AtomicU64,
        }
        let shared = Arc::new(Shared {
            row: Lifetime::new(),
            pins: AtomicU32::new(0),
            resource: AtomicU64::new(1),
            done: AtomicBool::new(false),
            bad: AtomicU64::new(0),
            reads: AtomicU64::new(0),
        });
        assert!(shared.row.reserve());
        shared.row.set_flags(LIVE);
        let senders: std::vec::Vec<_> = (0..4)
            .map(|_| {
                let shared = shared.clone();
                std::thread::spawn(move || {
                    while !shared.done.load(Ordering::Relaxed) {
                        if let Some(_pin) = shared.row.try_pin(&shared.pins, 0, |_| {}) {
                            if shared.resource.load(Ordering::Acquire) == FREED {
                                shared.bad.fetch_add(1, Ordering::SeqCst);
                            }
                            shared.reads.fetch_add(1, Ordering::Relaxed);
                        }
                        std::thread::yield_now();
                    }
                })
            })
            .collect();
        for round in 0..ROUNDS {
            // The thread ended and was released.
            shared.row.set_flags(LIVE | EXITED | RELEASED | DETACHED);
            while shared
                .row
                .claim_collect_unpinned(|| shared.pins.load(Ordering::SeqCst) != 0)
                != Claim::Taken
            {
                std::thread::yield_now();
            }
            shared.resource.store(FREED, Ordering::Release);
            shared.row.free();
            assert!(shared.row.reserve());
            shared.resource.store(round + 2, Ordering::Release);
            shared.row.set_flags(LIVE);
        }
        shared.done.store(true, Ordering::Relaxed);
        for sender in senders {
            sender.join().unwrap();
        }
        assert_eq!(
            shared.bad.load(Ordering::SeqCst),
            0,
            "a freed resource was read under a pin"
        );
        assert!(shared.reads.load(Ordering::SeqCst) > 0);
    }
}
