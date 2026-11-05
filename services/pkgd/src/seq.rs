// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The counter of changes of the published state (a sequence lock). The worker thread
//! makes the count odd before it changes what the main thread reads and even again after;
//! a reader takes the count before it reads, and after it has built its answer checks
//! that the count is the same and even. A reader that sees it changed throws its answer
//! away and says BUSY, so the main thread never sends what it read half way through a
//! change, on one CPU or on two.

use core::sync::atomic::{AtomicU32, Ordering, fence};

pub struct Seq(AtomicU32);

impl Default for Seq {
    fn default() -> Self {
        Self::new()
    }
}

impl Seq {
    pub const fn new() -> Seq {
        Seq(AtomicU32::new(0))
    }

    /// The count a read starts from; None while a change is under way.
    pub fn begin(&self) -> Option<u32> {
        let now = self.0.load(Ordering::Acquire);
        (now & 1 == 0).then_some(now)
    }

    /// Whether nothing changed since `begin` gave `start`: call after the last read.
    pub fn unchanged(&self, start: u32) -> bool {
        fence(Ordering::Acquire);
        self.0.load(Ordering::Relaxed) == start
    }

    /// The change `f`, between an odd count and the next even one. One writer.
    pub fn write<R>(&self, f: impl FnOnce() -> R) -> R {
        let now = self.0.load(Ordering::Relaxed);
        self.0.store(now.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        let out = f();
        self.0.store(now.wrapping_add(2), Ordering::Release);
        out
    }
}
