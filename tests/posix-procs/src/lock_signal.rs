// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Genuine signal and thread departure interrupt a registered public lock operation.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use posix_abi::LockProbe;
use posix_fs::change::ControlToken;

static ARMED: AtomicBool = AtomicBool::new(false);
static MODE: AtomicU32 = AtomicU32::new(0);
static SEEN: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" {
    fn lock_probe_signal();
    fn lock_probe_signal_async();
    fn lock_probe_exit();
}
fn hook(phase: LockProbe, _: ControlToken) -> bool {
    let mode = MODE.load(Ordering::Acquire);
    let expected = match mode {
        5 | 7 => LockProbe::Query,
        6 | 8 => LockProbe::Release,
        _ => LockProbe::Start,
    };
    if phase == expected && ARMED.swap(false, Ordering::AcqRel) {
        SEEN.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the dedicated C fixture supplies these genuine lifecycle actions.
        unsafe {
            if mode == 3 || mode == 9 {
                lock_probe_exit();
            } else if mode == 4 {
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
    SEEN.load(Ordering::Acquire)
}
