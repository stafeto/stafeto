// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A genuine signal enters a thread between the reply of a lock request and
//! its return: the handler runs, may leave by a jump or end the thread, and
//! the thread's lock commands stay balanced.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static ARMED: AtomicBool = AtomicBool::new(false);
static MODE: AtomicU32 = AtomicU32::new(0);
static SEEN: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" {
    fn lock_probe_signal();
    fn lock_probe_signal_async();
}
fn hook() -> bool {
    if ARMED.swap(false, Ordering::AcqRel) {
        SEEN.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the dedicated C fixture supplies these genuine actions.
        unsafe {
            if MODE.load(Ordering::Acquire) == 4 {
                lock_probe_signal_async();
            } else {
                lock_probe_signal();
            }
        }
    }
    false
}

#[unsafe(no_mangle)]
pub extern "C" fn lock_driver_signal_arm(mode: u32) {
    SEEN.store(0, Ordering::Release);
    MODE.store(mode, Ordering::Release);
    ARMED.store(true, Ordering::Release);
    posix_abi::probe_lock_hook(Some(hook));
}
#[unsafe(no_mangle)]
pub extern "C" fn lock_driver_signal_disarm() -> u32 {
    posix_abi::probe_lock_hook(None);
    ARMED.store(false, Ordering::Release);
    let idle = posix_abi::shared::with_files(|files| Ok(files.no_lock_command())).unwrap_or(false);
    if idle {
        SEEN.load(Ordering::Acquire)
    } else {
        2
    }
}
