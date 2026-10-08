// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Decisions shared by the stop scan and post-publication scope barrier.

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
