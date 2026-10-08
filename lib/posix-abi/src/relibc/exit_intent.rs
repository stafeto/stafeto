// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A successful common deferral survives libc retval publication until ThreadExit.

pub(super) fn hold<G, E>(deferred: Result<G, E>, publish: impl FnOnce()) -> bool {
    let Ok(guard) = deferred else {
        return false;
    };
    core::mem::forget(guard);
    publish();
    true
}

/// Managed exit keeps its existing IPC-interruptible cleanup path.
pub(super) fn hold_native<G, E>(
    resident: bool,
    defer: impl FnOnce() -> Result<G, E>,
    publish: impl FnOnce(),
) -> bool {
    if resident {
        hold(defer(), publish)
    } else {
        true
    }
}
