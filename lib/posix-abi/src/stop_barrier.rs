// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Decisions shared by the stop scan and post-publication scope barrier.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Stop publication and release share one lifecycle claim. The active owner
/// becomes zero before peers wake; the claim remains held through cleanup.
pub(crate) struct StopControl {
    lifecycle: AtomicUsize,
    active: AtomicUsize,
    channel: AtomicU64,
}

impl StopControl {
    pub(crate) const fn new() -> Self {
        Self {
            lifecycle: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            channel: AtomicU64::new(0),
        }
    }
    // The park channel publication uses the same sequentially consistent order.
    pub(crate) fn owner(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }
    pub(crate) fn channel(&self) -> u64 {
        self.channel.load(Ordering::Acquire)
    }
    pub(crate) fn try_begin(&self, owner: usize, channel: u64) -> bool {
        if owner == 0 || channel == 0 {
            return false;
        }
        if self
            .lifecycle
            .compare_exchange(0, owner, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        self.channel.store(channel, Ordering::Release);
        self.active.store(owner, Ordering::Release);
        true
    }
    pub(crate) fn release(
        &self,
        owner: usize,
        wake: impl FnOnce(),
        close: impl FnOnce(u64),
    ) -> bool {
        if owner == 0 || self.lifecycle.load(Ordering::Acquire) != owner {
            return false;
        }
        if self
            .active
            .compare_exchange(owner, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        wake();
        let channel = self.channel.swap(0, Ordering::AcqRel);
        close(channel);
        self.lifecycle.store(0, Ordering::Release);
        true
    }
    /// The sole fork child discards the copied parent stop and raw channel.
    pub(crate) fn reset_after_fork(&self) {
        self.active.store(0, Ordering::Release);
        self.channel.store(0, Ordering::Release);
        self.lifecycle.store(0, Ordering::Release);
    }
}

pub(crate) fn must_park(stopping: usize, own: usize) -> bool {
    stopping != 0 && stopping != own
}

#[derive(Clone, Copy)]
pub(crate) enum State {
    Unknown,
    Terminal,
    KernelWait,
    Running,
}

pub(crate) fn confirmed_terminal(state: State) -> bool {
    matches!(state, State::Terminal)
}

pub(crate) fn quiescent(
    resident: bool,
    state: State,
    depth: u32,
    holds_process: u64,
    returning: bool,
) -> bool {
    !resident
        && matches!(state, State::KernelWait)
        && depth == 0
        && holds_process == 0
        && !returning
}

/// Publication and TLS installation precede this ordered admission tail.
pub(crate) fn before_renew<R>(barrier: impl FnOnce(), renew: impl FnOnce() -> R) -> R {
    barrier();
    renew()
}
