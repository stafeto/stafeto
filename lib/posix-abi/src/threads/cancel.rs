// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Deferred cancellation at C ABI boundaries. Rust operations return and drop
//! their owned resources before cancellation invokes user cleanup handlers.
//! The request and the state live in the thread's block (posix-thread:
//! CANCEL_PENDING, CANCEL_DISABLED, EXITING); a point checks before it waits
//! and after a wait that ended by an entry or bit CANCEL of its channel.

use crate::constants::*;
use core::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicPtr, AtomicU64, Ordering},
};
use posix_thread::flag;

pub const CANCELED: *mut c_void = usize::MAX as *mut c_void;
type Routine = unsafe extern "C" fn(*mut c_void);

#[repr(C)]
pub struct Cleanup {
    next: *mut Cleanup,
    routine: Option<Routine>,
    argument: *mut c_void,
}
impl Cleanup {
    pub const fn new() -> Self {
        Self {
            next: ptr::null_mut(),
            routine: None,
            argument: ptr::null_mut(),
        }
    }
}
impl Default for Cleanup {
    fn default() -> Self {
        Self::new()
    }
}
const _: () = {
    assert!(core::mem::size_of::<Cleanup>() == 24);
    assert!(core::mem::align_of::<Cleanup>() == 8);
};

pub(super) struct State {
    cleanup: AtomicPtr<Cleanup>,
    #[cfg(feature = "thread-probe")]
    pub(super) console: core::sync::atomic::AtomicBool,
}
impl State {
    pub(super) const fn new() -> Self {
        Self {
            cleanup: AtomicPtr::new(ptr::null_mut()),
            #[cfg(feature = "thread-probe")]
            console: core::sync::atomic::AtomicBool::new(false),
        }
    }
    pub(super) fn reset(&self) {
        self.cleanup.store(ptr::null_mut(), Ordering::Relaxed);
        #[cfg(feature = "thread-probe")]
        self.console.store(false, Ordering::Relaxed);
    }
}

fn flags() -> Option<&'static core::sync::atomic::AtomicU32> {
    // SAFETY: a managed thread's block lives as long as the thread.
    unsafe { posix_thread::block().as_ref() }.map(|block| &block.flags)
}

/// The calling thread's word of its cancellation point (posix-thread).
fn point() -> Option<&'static AtomicU64> {
    // SAFETY: a managed thread's block lives as long as the thread.
    unsafe { posix_thread::block().as_ref() }.map(|block| &block.cancel_point)
}

fn state() -> Option<&'static State> {
    super::current_launch().map(|launch| &launch.cancel)
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
    console: Option<bool>,
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
            let console = state().map(|state| state.console.swap(false, Ordering::AcqRel));
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
    pub(crate) fn requested(&self) -> bool {
        self.0.is_some() && requested()
    }
    pub(crate) fn end(self) {
        if let Some(frame) = self.0 {
            #[cfg(feature = "thread-probe")]
            if let (Some(state), Some(console)) = (state(), frame.console) {
                state.console.store(console, Ordering::Release);
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

pub(crate) fn terminate() -> ! {
    // relibc runs the cleanup handlers and the destructors of a thread
    // that relibc made and attached.
    #[cfg(feature = "libc-backend")]
    {
        unsafe extern "C" {
            fn pthread_exit(value: *mut c_void) -> !;
        }
        // SAFETY: relibc's pthread_exit, on a thread relibc started.
        unsafe { pthread_exit(CANCELED) }
    }
    // SAFETY: the requesting state belongs to the current managed thread.
    #[cfg(not(feature = "libc-backend"))]
    unsafe {
        super::pthread_exit(CANCELED)
    }
}

/// Run exit handlers on their own thread with cancellation disabled.
///
/// # Safety
/// Every linked node and callback remains live until removed by this thread.
pub(super) unsafe fn exit_cleanup() {
    let state = state().expect("managed exit cleanup");
    flags()
        .expect("managed exit cleanup")
        .fetch_or(flag::CANCEL_DISABLED | flag::EXITING, Ordering::SeqCst);
    if let Some(point) = point() {
        point.store(0, Ordering::SeqCst);
    }
    loop {
        let node = state.cleanup.load(Ordering::Relaxed);
        if node.is_null() {
            break;
        }
        let routine = unsafe { (*node).routine.expect("cleanup routine") };
        let argument = unsafe { (*node).argument };
        state
            .cleanup
            .store(unsafe { (*node).next }, Ordering::Relaxed);
        // SAFETY: push registered this C callback with its live argument.
        unsafe { routine(argument) };
    }
}

/// # Safety
/// The current thread is initialized; old is null or writable for one int.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setcancelstate(value: i32, old: *mut i32) -> i32 {
    let Some(flags) = flags() else {
        return EINVAL;
    };
    if !matches!(value, PTHREAD_CANCEL_ENABLE | PTHREAD_CANCEL_DISABLE)
        || (value == PTHREAD_CANCEL_ENABLE && flags.load(Ordering::Acquire) & flag::EXITING != 0)
    {
        return EINVAL;
    }
    let was = if value == PTHREAD_CANCEL_ENABLE {
        flags.fetch_and(!flag::CANCEL_DISABLED, Ordering::SeqCst)
    } else {
        flags.fetch_or(flag::CANCEL_DISABLED, Ordering::SeqCst)
    };
    if !old.is_null() {
        unsafe {
            old.write(if was & flag::CANCEL_DISABLED == 0 {
                PTHREAD_CANCEL_ENABLE
            } else {
                PTHREAD_CANCEL_DISABLE
            })
        };
    }
    0
}

/// # Safety
/// The current thread is initialized; old is null or writable for one int.
/// Asynchronous cancellation needs future signal/trampoline support; it is
/// explicitly rejected instead of silently using deferred cancellation.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setcanceltype(value: i32, old: *mut i32) -> i32 {
    if state().is_none() {
        return EINVAL;
    }
    if value == PTHREAD_CANCEL_ASYNCHRONOUS {
        return ENOSYS;
    }
    if value != PTHREAD_CANCEL_DEFERRED {
        return EINVAL;
    }
    if !old.is_null() {
        unsafe { old.write(PTHREAD_CANCEL_DEFERRED) };
    }
    0
}

#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub extern "C" fn pthread_testcancel() {
    if requested() {
        terminate();
    }
}

/// # Safety
/// node is uniquely writable and remains at this address until pop or exit;
/// routine and argument remain valid while registered. Calls are lexically paired.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn __stafeto_cleanup_push(
    node: *mut Cleanup,
    routine: Option<Routine>,
    argument: *mut c_void,
) {
    assert!(
        !node.is_null() && routine.is_some(),
        "valid cleanup registration"
    );
    let state = state().expect("managed cleanup push");
    unsafe {
        node.write(Cleanup {
            next: state.cleanup.load(Ordering::Relaxed),
            routine,
            argument,
        })
    };
    state.cleanup.store(node, Ordering::Relaxed);
}

/// # Safety
/// node is the current thread's top live registered cleanup node.
#[cfg_attr(not(feature = "libc-backend"), unsafe(no_mangle))]
pub unsafe extern "C" fn __stafeto_cleanup_pop(node: *mut Cleanup, execute: i32) {
    let state = state().expect("managed cleanup pop");
    assert!(
        !node.is_null() && state.cleanup.load(Ordering::Relaxed) == node,
        "paired cleanup pop"
    );
    let routine = unsafe { (*node).routine.expect("registered cleanup routine") };
    let argument = unsafe { (*node).argument };
    state
        .cleanup
        .store(unsafe { (*node).next }, Ordering::Relaxed);
    if execute != 0 {
        unsafe { routine(argument) };
    }
}

/// Observe the console phase only in guest probes; regular builds contain no hook.
pub(crate) fn console_wait() {
    #[cfg(feature = "thread-probe")]
    if let Some(state) = state() {
        state.console.store(true, Ordering::Release);
    }
}
