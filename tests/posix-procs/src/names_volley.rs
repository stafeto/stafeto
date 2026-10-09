// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What names-volley.c reads of the layer in the steps mode: how many requests
//! one operation sent to the service (the hook of the driver counts them), the
//! counter, the restarts of the resolution an operation of a kind reported,
//! and the most repeats of a Start answered with JOBS_FULL.
use core::sync::atomic::{AtomicU32, Ordering::Relaxed};
use posix_abi::change::{Probe, probe_hook, stats};

static REQUESTS: AtomicU32 = AtomicU32::new(0);

fn count(_: Probe) -> bool {
    REQUESTS.fetch_add(1, Relaxed);
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
