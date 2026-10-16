// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Coordinates genuine sleeping WAITs; never substitutes a service outcome.
use core::sync::atomic::{AtomicBool, Ordering};
use posix_abi::WaitProbe;

static ARMED: AtomicBool = AtomicBool::new(false);
unsafe extern "C" {
    fn deadlock_wait_sleeping();
}
fn hook(phase: WaitProbe, _: proto_fs::WaitKey) -> bool {
    if phase == WaitProbe::Receive && ARMED.swap(false, Ordering::AcqRel) {
        // SAFETY: lifetime.c includes the coordinating fixture; no FILES_LOCK is held.
        unsafe { deadlock_wait_sleeping() };
    }
    false
}
#[unsafe(no_mangle)]
pub extern "C" fn deadlock_probe_arm() {
    ARMED.store(true, Ordering::Release);
    posix_abi::probe_wait_hook(Some(hook));
}
#[unsafe(no_mangle)]
pub extern "C" fn deadlock_probe_disarm() {
    posix_abi::probe_wait_hook(None);
    ARMED.store(false, Ordering::Release);
}

/// 1 when the layer knows the process holds no record lock, else 0.
#[unsafe(no_mangle)]
pub extern "C" fn record_locks_none() -> i32 {
    i32::from(posix_abi::record_locks_none())
}
