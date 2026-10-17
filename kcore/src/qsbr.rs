// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Quiescent-state reclamation (SMP stage 3, decision 1): what a CPU reads
//! without a lock, such as the binding that a line of interrupts names, may
//! go back only after every CPU has passed a quiescent point since the
//! change that made it unreachable. A CPU is quiescent where it holds no
//! pointer into shared objects: on the empty kernel stack at the top of the
//! way out of the kernel, and while it idles.
//!
//! The protocol: the change that unlinks an object retires it and gets an
//! epoch, the next of a counter (`retire`). A CPU that reaches a quiescent
//! point writes the epoch it sees (`quiesce`); an idle CPU writes `IDLE`,
//! which is past every epoch, and writes the epoch again when it wakes. An
//! object retired at epoch `e` may go once every CPU's mark is `e` or more
//! (`passed`): each of them was quiescent after the retirement. On one CPU
//! the period ends at that CPU's next quiescent point.

use core::sync::atomic::{AtomicU64, Ordering};

// Memory order: the marks and the epoch counter use SeqCst. A reader's
// "mark, then read LINES" has to be ordered against the writer's "change
// LINES, then read the marks": with only release stores and acquire loads
// the writer may read a stale mark while the reader reads the stale LINES,
// and the binding goes while the reader still holds it. In the Rust model
// only SeqCst orders that pair (a store, then a load of another location,
// on each side). On AArch64 SeqCst stores and loads are the `stlr` and
// `ldar` the release and acquire forms already use, so it costs nothing.

/// The mark of an idle CPU: past every epoch.
pub const IDLE: u64 = u64::MAX;

/// The epoch counter and the mark of each of `N` CPUs.
pub struct Grace<const N: usize> {
    epoch: AtomicU64,
    seen: [AtomicU64; N],
}

impl<const N: usize> Grace<N> {
    /// Epoch 1 and no CPU quiescent yet: a CPU that never reaches a
    /// quiescent point holds the period open.
    pub const fn new() -> Self {
        Self {
            epoch: AtomicU64::new(1),
            seen: [const { AtomicU64::new(0) }; N],
        }
    }

    /// The epoch of an object that was just unlinked: the counter moves on,
    /// so that every quiescent point after this call writes it or more.
    pub fn retire(&self) -> u64 {
        self.epoch.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// CPU `cpu` is quiescent: it holds no pointer to what was retired
    /// before now.
    pub fn quiesce(&self, cpu: usize) {
        self.seen[cpu].store(self.epoch.load(Ordering::SeqCst), Ordering::SeqCst);
    }

    /// CPU `cpu` goes idle: it holds nothing until `quiesce` marks it awake.
    pub fn idle(&self, cpu: usize) {
        self.seen[cpu].store(IDLE, Ordering::SeqCst);
    }

    /// Whether every one of the first `cpus` CPUs was quiescent after the
    /// retirement at `epoch`.
    pub fn passed(&self, epoch: u64, cpus: usize) -> bool {
        self.seen[..cpus]
            .iter()
            .all(|s| s.load(Ordering::SeqCst) >= epoch)
    }
}

impl<const N: usize> Default for Grace<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_cpu_ends_the_period_at_its_next_quiescent_point() {
        let g = Grace::<4>::new();
        g.quiesce(0);
        let e = g.retire();
        assert!(!g.passed(e, 1), "the CPU that retired is not quiescent yet");
        g.quiesce(0);
        assert!(g.passed(e, 1));
    }

    #[test]
    fn every_cpu_has_to_pass_a_point() {
        let g = Grace::<4>::new();
        for cpu in 0..4 {
            g.quiesce(cpu);
        }
        let e = g.retire();
        g.quiesce(0);
        g.quiesce(1);
        g.quiesce(2);
        assert!(!g.passed(e, 4), "CPU 3 has not passed a point");
        g.quiesce(3);
        assert!(g.passed(e, 4));
    }

    #[test]
    fn an_idle_cpu_is_past_every_period() {
        let g = Grace::<2>::new();
        g.quiesce(0);
        g.idle(1);
        let e = g.retire();
        g.quiesce(0);
        assert!(g.passed(e, 2));
        // It wakes into the epoch that is current: later retirements wait
        // for its next point again.
        g.quiesce(1);
        let later = g.retire();
        g.quiesce(0);
        assert!(!g.passed(later, 2));
        g.quiesce(1);
        assert!(g.passed(later, 2));
    }

    #[test]
    fn a_point_before_the_retirement_does_not_count() {
        let g = Grace::<2>::new();
        g.quiesce(0);
        g.quiesce(1);
        let e = g.retire();
        g.quiesce(0);
        assert!(
            !g.passed(e, 2),
            "CPU 1 passed its point before the retirement"
        );
    }

    /// Reader threads hold a pointer between two quiescent points; a writer
    /// retires a box and frees it once the period passed: no reader sees a
    /// freed value.
    #[test]
    fn readers_never_see_a_freed_value() {
        use std::sync::atomic::AtomicPtr;
        const READERS: usize = 3;
        let g = Grace::<{ READERS + 1 }>::new();
        let cell = AtomicPtr::new(Box::into_raw(Box::new(1u64)));
        let stop = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            for cpu in 1..=READERS {
                let (g, cell, stop) = (&g, &cell, &stop);
                scope.spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let p = cell.load(Ordering::Acquire);
                        // SAFETY: the value goes only after this thread's
                        // next quiescent point.
                        let v = unsafe { *p };
                        assert!(v != 0xdead, "a freed value was read");
                        g.quiesce(cpu);
                    }
                    g.idle(cpu);
                });
            }
            g.quiesce(0);
            for round in 2..200u64 {
                let old = cell.swap(Box::into_raw(Box::new(round)), Ordering::AcqRel);
                let epoch = g.retire();
                while !g.passed(epoch, READERS + 1) {
                    g.quiesce(0);
                    std::thread::yield_now();
                }
                // SAFETY: every reader passed a point after the swap.
                unsafe {
                    *old = 0xdead;
                    drop(Box::from_raw(old));
                }
            }
            stop.store(true, Ordering::Relaxed);
        });
        // SAFETY: the readers are done.
        drop(unsafe { Box::from_raw(cell.load(Ordering::Relaxed)) });
    }
}
