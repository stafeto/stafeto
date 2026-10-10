// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What names-volley.c reads of the layer in the steps mode: how many requests
//! one operation sent to the service (the hook of the driver counts them), the
//! counter, the restarts of the resolution an operation of a kind reported,
//! and the most repeats of a Start answered with JOBS_FULL.
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use posix_abi::change::{Probe, probe_hook, stats};

static REQUESTS: AtomicU32 = AtomicU32::new(0);
static TRACKED_TLS: AtomicU64 = AtomicU64::new(0);
static TRACKED_REQUESTS: AtomicU32 = AtomicU32::new(0);
fn caller_tls() -> u64 {
    let tls;
    // SAFETY: reads the current thread's TLS register without accessing memory.
    unsafe {
        core::arch::asm!("mrs {}, tpidr_el0", out(reg) tls, options(nomem, nostack, preserves_flags));
    }
    tls
}
/// Count only the calling thread while the interference thread also runs.
#[unsafe(no_mangle)]
pub extern "C" fn files_volley_thread_start() {
    TRACKED_REQUESTS.store(0, Relaxed);
    TRACKED_TLS.store(caller_tls(), Relaxed);
}
#[unsafe(no_mangle)]
pub extern "C" fn files_volley_thread_requests() -> u32 {
    TRACKED_REQUESTS.load(Relaxed)
}

fn count(_: Probe) -> bool {
    REQUESTS.fetch_add(1, Relaxed);
    if TRACKED_TLS.load(Relaxed) == caller_tls() {
        TRACKED_REQUESTS.fetch_add(1, Relaxed);
    }
    false
}

/// Starts counting the requests and the restarts afresh.
#[unsafe(no_mangle)]
pub extern "C" fn files_volley_start() {
    REQUESTS.store(0, Relaxed);
    stats::reset();
    probe_hook(Some(count));
}

/// No more hook.
#[unsafe(no_mangle)]
pub extern "C" fn files_volley_stop() {
    probe_hook(None);
}

/// The requests of Start, Second, Step and Release since the start. A Step
/// answered with the outcome and the Release count too: they are steps of the
/// service.
#[unsafe(no_mangle)]
pub extern "C" fn files_volley_requests() -> u32 {
    REQUESTS.load(Relaxed)
}

/// The counter of the virtual timer, in ticks.
#[unsafe(no_mangle)]
pub extern "C" fn files_volley_ticks() -> u64 {
    rt::time::now()
}

/// The frequency of the counter in Hz.
#[unsafe(no_mangle)]
pub extern "C" fn files_volley_frequency() -> u64 {
    rt::time::frequency()
}

/// The most restarts an operation of kind `op` (the number of ChangeOp)
/// reported since the start.
#[unsafe(no_mangle)]
pub extern "C" fn files_volley_restarts(op: i32) -> u32 {
    stats::RESTARTS
        .get(op as usize)
        .map_or(0, |restarts| restarts.load(Relaxed))
}

/// The most repeats of a refused Start (JOBS_FULL) one operation made since
/// the start.
#[unsafe(no_mangle)]
pub extern "C" fn files_volley_full_repeats() -> u32 {
    stats::FULL_REPEATS.load(Relaxed)
}

/// Entry `index` of the directory `path` by the call of the service that
/// counts the entries from the head of the list (the call of the tests of
/// the service, not used by the layer): the length of the name, 0 at the end
/// of the directory, or a negative number for a refusal.
///
/// # Safety
/// `path` is a live C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn files_volley_read_dir_index(
    path: *const core::ffi::c_char,
    index: u32,
) -> i32 {
    use core::mem::ManuallyDrop;
    use rt::fs::Files;
    use rt::handle::Handle;
    // SAFETY: the caller's promise.
    let Ok(path) = unsafe { core::ffi::CStr::from_ptr(path) }.to_str() else {
        return -1;
    };
    let Ok(raw) = posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())) else {
        return -2;
    };
    let files = ManuallyDrop::new(Files::from_sessions(Handle::from_raw(raw), None));
    let mut name = [0; 256];
    match files.read_dir(path, index, &mut name) {
        Ok(Some((length, _))) => length as i32,
        Ok(None) => 0,
        Err(_) => -3,
    }
}
