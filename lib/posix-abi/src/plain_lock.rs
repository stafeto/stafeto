//! A plain futex mutex for a long section of a layer (the devices of OpenWF
//! Composition and Display).

use crate::constants::*;
use core::sync::atomic::{AtomicU32, Ordering};
use posix_sync::{CLOCK_MONOTONIC, futex_wait, futex_wake};
use rt::sys;

/// A plain futex mutex. It is no `LayerLock`: its holder is in no critical
/// section, so a signal's handler runs while a call that holds it waits (a
/// critical section would keep the signal pending, and every wait would end
/// at once, interrupted). It is held for a whole call, a wait included, so it
/// serializes the calls on one device; the child of a fork makes it new (the
/// thread of the parent that held it is not there). A handler that jumps out
/// of a call leaves it held: the functions are not async-signal-safe.
pub(crate) struct Lock(AtomicU32);

pub(crate) struct Held<'a>(&'a Lock);

impl Lock {
    pub(crate) const fn new() -> Lock {
        Lock(AtomicU32::new(0))
    }

    pub(crate) fn lock(&self) -> Held<'_> {
        if self
            .0
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.0.swap(2, Ordering::Acquire) != 0 {
                if futex_wait(&self.0, 2, CLOCK_MONOTONIC, None) == Err(EINVAL) {
                    let _ = sys::yield_now();
                }
            }
        }
        Held(self)
    }

    pub(crate) fn reset(&self) {
        self.0.store(0, Ordering::Release);
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if self.0.0.swap(0, Ordering::Release) == 2 {
            futex_wake(&self.0.0, 1);
        }
    }
}
