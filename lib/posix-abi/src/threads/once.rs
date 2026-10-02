// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Once initialization over waits by address (posix-sync). The word: 0
//! new, 1 running, 2 running with waiters, 3 done. Cancellation of the
//! routine rolls the word back to new and wakes the waiters, one of which
//! runs it then.

use super::cancel;
use crate::constants::EINVAL;
use core::{
    ffi::c_void,
    sync::atomic::{AtomicU32, Ordering},
};
use posix_sync::{CLOCK_MONOTONIC, futex_wait, futex_wake};

const NEW: u32 = 0;
const RUNNING: u32 = 1;
const WAITERS: u32 = 2;
const DONE: u32 = 3;
type Routine = unsafe extern "C" fn();

/// The C type is one aligned 64-bit word; the state is its low half.
#[repr(C, align(8))]
pub struct Control {
    state: AtomicU32,
    reserved: u32,
}
impl Control {
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(NEW),
            reserved: 0,
        }
    }
    /// The word waiters wait on, for the probes.
    pub fn word(&self) -> &AtomicU32 {
        &self.state
    }
}
impl Default for Control {
    fn default() -> Self {
        Self::new()
    }
}
const _: () = {
    assert!(core::mem::size_of::<Control>() == 8);
    assert!(core::mem::align_of::<Control>() == 8);
};

fn valid(address: u64) -> bool {
    address != 0 && address.is_multiple_of(core::mem::align_of::<Control>() as u64)
}

/// Gives the word `state` and wakes every waiter when there were any.
fn publish(control: &Control, state: u32) {
    if control.state.swap(state, Ordering::Release) == WAITERS {
        futex_wake(&control.state, u32::MAX);
    }
}

unsafe extern "C" fn rollback(argument: *mut c_void) {
    // SAFETY: the paired cleanup node keeps its live once object until exit.
    let control = unsafe { &*(argument as *const Control) };
    publish(control, NEW);
}

/// # Safety
/// control is a live, initialized static/extern once object shared only through
/// pthread_once. routine remains callable. Recursive calls on the same object
/// cannot complete; different nested objects are supported.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_once(control: *mut Control, routine: Option<Routine>) -> i32 {
    if !valid(control as u64) || routine.is_none() || posix_thread::block().is_null() {
        return EINVAL;
    }
    let routine = routine.expect("checked once callback");
    let object = unsafe { &*control };
    loop {
        match object.state.load(Ordering::Acquire) {
            DONE => return 0,
            NEW => {
                if object
                    .state
                    .compare_exchange(NEW, RUNNING, Ordering::Acquire, Ordering::Relaxed)
                    .is_err()
                {
                    continue;
                }
                let mut cleanup = cancel::Cleanup::new();
                unsafe {
                    cancel::__stafeto_cleanup_push(&mut cleanup, Some(rollback), control.cast());
                    routine();
                    cancel::__stafeto_cleanup_pop(&mut cleanup, 0);
                }
                publish(object, DONE);
                return 0;
            }
            RUNNING => {
                let _ = object.state.compare_exchange(
                    RUNNING,
                    WAITERS,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
            // pthread_once is no cancellation point: every outcome looks
            // at the word again.
            _ => {
                let _ = futex_wait(&object.state, WAITERS, CLOCK_MONOTONIC, None);
            }
        }
    }
}
