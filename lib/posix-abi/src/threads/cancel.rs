// SPDX-License-Identifier: GPL-3.0-or-later
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
    pub(super) active: AtomicU64,
    generation: AtomicU64,
    cleanup: AtomicPtr<Cleanup>,
    #[cfg(feature = "thread-probe")]
    pub(super) console: core::sync::atomic::AtomicBool,
}
impl State {
    pub(super) const fn new() -> Self {
        Self {
            active: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            cleanup: AtomicPtr::new(ptr::null_mut()),
            #[cfg(feature = "thread-probe")]
            console: core::sync::atomic::AtomicBool::new(false),
        }
    }
    pub(super) fn reset(&self) {
        self.active.store(0, Ordering::Relaxed);
        self.generation.store(0, Ordering::Relaxed);
        self.cleanup.store(ptr::null_mut(), Ordering::Relaxed);
        #[cfg(feature = "thread-probe")]
        self.console.store(false, Ordering::Relaxed);
    }
    fn requested(&self) -> bool {
        requested()
    }
}

fn flags() -> Option<&'static core::sync::atomic::AtomicU32> {
    // SAFETY: a managed thread's block lives as long as the thread.
    unsafe { posix_thread::block().as_ref() }.map(|block| &block.flags)
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
    state: &'static State,
    previous: u64,
    #[cfg(feature = "thread-probe")]
    console: bool,
}
/// An explicit cancellation window. Close windows in nesting order at the C
/// boundary, after internal resources are dropped and before taking cancellation.
pub(crate) struct Point(Option<Frame>);
impl Point {
    pub(crate) fn begin() -> Self {
        let frame = state().map(|state| {
            let generation = state
                .generation
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .expect("cancellation generation exhausted")
                + 1;
            // A signal handler may enter another cancellation point on this
            // thread. Its return must retain the interrupted caller's window.
            let previous = state.active.swap(generation, Ordering::SeqCst);
            #[cfg(feature = "thread-probe")]
            let console = state.console.swap(false, Ordering::AcqRel);
            if state.requested() {
                terminate();
            }
            Frame {
                state,
                previous,
                #[cfg(feature = "thread-probe")]
                console,
            }
        });
        Self(frame)
    }
    pub(crate) fn requested(&self) -> bool {
        self.0.as_ref().is_some_and(|frame| frame.state.requested())
    }
    pub(crate) fn end(self) {
        if let Some(frame) = self.0 {
            #[cfg(feature = "thread-probe")]
            frame.state.console.store(frame.console, Ordering::Release);
            frame.state.active.store(frame.previous, Ordering::SeqCst);
        }
    }
    pub(crate) fn finish(self) {
        self.end();
        if requested() {
            terminate();
        }
    }
}

pub(super) fn terminate() -> ! {
    // SAFETY: the requesting state belongs to the current managed thread.
    unsafe { super::pthread_exit(CANCELED) }
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
    state.active.store(0, Ordering::SeqCst);
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
pub extern "C" fn pthread_testcancel() {
    if requested() {
        terminate();
    }
}

/// # Safety
/// node is uniquely writable and remains at this address until pop or exit;
/// routine and argument remain valid while registered. Calls are lexically paired.
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
