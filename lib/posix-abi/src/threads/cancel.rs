// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Deferred cancellation at C ABI boundaries. Rust operations return and drop
//! their owned resources before cancellation invokes user cleanup handlers.
//! The request and the state live in the thread's block (posix-thread:
//! CANCEL_PENDING, CANCEL_DISABLED, EXITING); a point checks before it waits
//! and after a wait that ended by an entry or bit CANCEL of its channel.

use core::{
    ffi::c_void,
    sync::atomic::{AtomicU64, Ordering},
};
use posix_thread::flag;

pub const CANCELED: *mut c_void = usize::MAX as *mut c_void;

fn flags() -> Option<&'static core::sync::atomic::AtomicU32> {
    // SAFETY: a managed thread's block lives as long as the thread.
    unsafe { posix_thread::block().as_ref() }.map(|block| &block.flags)
}

/// The calling thread's word of its cancellation point (posix-thread).
fn point() -> Option<&'static AtomicU64> {
    // SAFETY: a managed thread's block lives as long as the thread.
    unsafe { posix_thread::block().as_ref() }.map(|block| &block.cancel_point)
}

/// Whether cancellation was asked for and is enabled.
pub fn requested() -> bool {
    flags().is_some_and(|flags| {
        flags.load(Ordering::SeqCst) & (flag::CANCEL_PENDING | flag::CANCEL_DISABLED)
            == flag::CANCEL_PENDING
    })
}

/// Stack-owned prior state for an interrupted caller's cancellation window.
struct Frame {
    point: &'static AtomicU64,
    previous: u64,
    #[cfg(feature = "thread-probe")]
    console: u64,
}
/// An explicit cancellation window: while it is open, the word
/// `cancel_point` of the thread's block is not 0 and a request of
/// cancellation interrupts the thread's wait. Close windows in nesting
/// order at the C boundary, after internal resources are dropped and
/// before taking cancellation.
pub(crate) struct Point(Option<Frame>);
impl Point {
    pub(crate) fn begin() -> Self {
        let frame = point().map(|point| {
            // A signal handler may enter another cancellation point on this
            // thread: its window has a value of its own, and its end gives
            // the interrupted caller's back.
            let previous = point
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    Some(n.wrapping_add(1).max(1))
                })
                .expect("the update always succeeds");
            #[cfg(feature = "thread-probe")]
            let console = console().map_or(0, |word| word.swap(0, Ordering::AcqRel));
            if requested() {
                terminate();
            }
            Frame {
                point,
                previous,
                #[cfg(feature = "thread-probe")]
                console,
            }
        });
        Self(frame)
    }
    pub(crate) fn end(self) {
        if let Some(frame) = self.0 {
            #[cfg(feature = "thread-probe")]
            if let Some(word) = console() {
                word.store(frame.console, Ordering::Release);
            }
            frame.point.store(frame.previous, Ordering::SeqCst);
        }
    }
    pub(crate) fn finish(self) {
        self.end();
        if requested() {
            terminate();
        }
    }
}

/// The value of the calling thread's cancellation window, 0 outside one.
#[cfg(feature = "thread-probe")]
pub(crate) fn window() -> u64 {
    point().map_or(0, |point| point.load(Ordering::SeqCst))
}

/// Cancellation at a point of the layer: relibc runs the cleanup handlers
/// and the destructors of the thread, which relibc made.
pub(crate) fn terminate() -> ! {
    unsafe extern "C" {
        fn pthread_exit(value: *mut c_void) -> !;
    }
    // SAFETY: relibc's pthread_exit, on a thread relibc started.
    unsafe { pthread_exit(CANCELED) }
}

/// The word that marks the console phase of a read, for the probes.
#[cfg(feature = "thread-probe")]
fn console() -> Option<&'static AtomicU64> {
    // SAFETY: a managed thread's block lives as long as the thread.
    unsafe { posix_thread::block().as_ref() }.map(|block| &block.probe)
}

/// Observe the console phase only in guest probes; regular builds contain no hook.
pub(crate) fn console_wait() {
    #[cfg(feature = "thread-probe")]
    if let Some(word) = console() {
        word.store(1, Ordering::Release);
    }
}
