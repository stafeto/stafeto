// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The longest hold of TABLE_LOCK by the collector. `route` takes that lock
//! on every signal of the process, so the collector keeps under it only the
//! claim of a place (the closes of handles and the unmaps of the thread's
//! stack and TCB go after the lock, #191). The probe fills the table with 63
//! threads that send signals to the process while the main thread makes
//! and joins them, three rounds, and prints the longest hold the probe build
//! of the layer noted (`probe_collect_hold`), in counter ticks: the least of
//! the three rounds, so that a round which the host interrupted does not
//! count. The limit of the spec is 2 000 ticks (spec 2, E2 (g)), which `xtask` checks on the printed line; the probe fails above 10 000.
use super::*;
use crate::layer::signals::{self as api, SigAction};
use ffi::pthread_join;

static READY: AtomicU64 = AtomicU64::new(0);
static RELEASE: AtomicU64 = AtomicU64::new(0);
static HANDLED: AtomicUsize = AtomicUsize::new(0);
const CHILDREN: usize = PTHREAD_THREADS_MAX as usize - 1;
const ROUNDS: usize = 3;
/// Signals each thread sends to its process before it waits.
const SIGNALS: usize = 4;
/// The probe's own bound of one hold, in counter ticks: five times the limit
/// of the spec (2 000), since TCG on four CPUs showed 2 191 on a busy host;
/// putting the closes back under the lock gives about 19 000.
const HOLD_MAX_TICKS: u64 = 10_000;

unsafe extern "C" fn handler(_: c_int) {
    HANDLED.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn sender(_: *mut c_void) -> *mut c_void {
    let ready = Handle::<Channel>::borrowed(rt::abi::Handle(READY.load(Ordering::Acquire)));
    let release = Handle::<Channel>::borrowed(rt::abi::Handle(RELEASE.load(Ordering::Acquire)));
    for _ in 0..SIGNALS {
        let _ = abi::process::kill(abi::process::getpid(), SIGUSR1);
    }
    sys::notify(&ready, 1).expect("table-hold ready");
    // A handler of the signals above may interrupt the wait.
    loop {
        match sys::receive(&release) {
            Err(rt::abi::Error::Interrupted) => continue,
            result => {
                result.expect("table-hold release");
                break;
            }
        }
    }
    ptr::null_mut()
}

pub(super) fn run() -> bool {
    let ready = sys::channel_create(30).expect("table-hold ready channel");
    let release = sys::channel_create(30).expect("table-hold release channel");
    READY.store(ready.raw().0, Ordering::Release);
    RELEASE.store(release.raw().0, Ordering::Release);
    let action = SigAction {
        handler: handler as *const () as u64,
        mask: 0,
        flags: 0,
    };
    let mut old = posix_signals::INITIAL;
    if unsafe { api::sigaction(SIGUSR1, &action, &mut old) } != 0 || !crate::settled(1) {
        return failed(1901);
    }
    let mut least = u64::MAX;
    for _ in 0..ROUNDS {
        let _ = abi::relibc::probe_collect_hold();
        let mut children = [0; CHILDREN];
        for child in &mut children {
            if unsafe { ffi::pthread_create(child, ptr::null(), Some(sender), ptr::null_mut()) }
                != 0
            {
                return failed(1902);
            }
            while matches!(sys::receive(&ready), Err(rt::abi::Error::Interrupted)) {}
            // A wake that comes before the child waits would merge with the
            // next: each child is released once it waits.
            let native = unsafe { threads::probe_native(*child) }.expect("table-hold native");
            if !crate::capacity::receiving(&native) {
                return failed(1906);
            }
        }
        for _ in &children {
            sys::notify(&release, 1).expect("table-hold release one");
        }
        for child in children {
            if unsafe { pthread_join(child, ptr::null_mut()) } != 0 {
                return failed(1903);
            }
        }
        if !crate::settled(1) {
            return failed(1904);
        }
        least = least.min(abi::relibc::probe_collect_hold());
    }
    if unsafe { api::sigaction(SIGUSR1, &old, ptr::null_mut()) } != 0 {
        return failed(1905);
    }
    rt::println!(
        "table-hold: collect held TABLE_LOCK at most {least} ticks ({} signals handled, {ROUNDS} rounds of {CHILDREN} threads)",
        HANDLED.load(Ordering::SeqCst)
    );
    if least > HOLD_MAX_TICKS {
        return failed(1907);
    }
    true
}
