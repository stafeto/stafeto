// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Phase coordination after real WAIT replies, never a replacement service.
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use posix_abi::WaitProbe;
use posix_fs::wait::WaitToken;
static ARMED: AtomicBool = AtomicBool::new(false);
static MODE: AtomicU32 = AtomicU32::new(0);
unsafe extern "C" {
    fn wait_probe_stage(stage: u32);
}
fn hook(phase: WaitProbe, _: WaitToken) -> bool {
    if phase == WaitProbe::Receive && ARMED.swap(false, Ordering::AcqRel) {
        // SAFETY: the lifetime C fixture provides the coordination function.
        unsafe { wait_probe_stage(1) };
    }
    if phase == WaitProbe::Complete && MODE.load(Ordering::Acquire) == 5 {
        MODE.store(0, Ordering::Release);
        // SAFETY: no service handles or FILES_LOCK are held across the hook.
        unsafe { wait_probe_stage(2) };
    }
    false
}
#[unsafe(no_mangle)]
pub extern "C" fn wait_driver_arm(mode: u32) {
    MODE.store(mode, Ordering::Release);
    ARMED.store(true, Ordering::Release);
    posix_abi::probe_wait_hook(Some(hook));
}
#[unsafe(no_mangle)]
pub extern "C" fn wait_driver_disarm() {
    posix_abi::probe_wait_hook(None);
    ARMED.store(false, Ordering::Release);
    MODE.store(0, Ordering::Release);
}
