// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Bounded local owner retirement; wake runs after the borrowed step returns.

pub(crate) fn run(
    limit: usize,
    mut step: impl FnMut() -> Result<Option<Option<usize>>, ()>,
    mut wake: impl FnMut(usize),
) -> bool {
    for _ in 0..limit {
        match step() {
            Ok(None) => return true,
            Ok(Some(Some(address))) => wake(address),
            Ok(Some(None)) => {}
            Err(()) => return false,
        }
    }
    false
}

/// Busy callers retain their cursor and every recovery obligation.
pub(crate) fn when_available(probe: impl FnOnce() -> Result<(), ()>, run: impl FnOnce()) {
    if probe().is_ok() {
        run();
    }
}
