// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Deferred cancellation at C ABI boundaries. Rust operations return and drop
//! their owned resources before cancellation invokes user cleanup handlers.

use crate::constants::*;
use core::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering},
};

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
    pub(super) pending: AtomicBool,
    pub(super) enabled: AtomicBool,
    pub(super) active: AtomicU64,
    generation: AtomicU64,
    exiting: AtomicBool,
    cleanup: AtomicPtr<Cleanup>,
    #[cfg(feature = "transport-probe")]
    pub(super) console: AtomicBool,
}
impl State {
    pub(super) const fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
            enabled: AtomicBool::new(true),
            active: AtomicU64::new(0),
            generation: AtomicU64::new(0),
            exiting: AtomicBool::new(false),
            cleanup: AtomicPtr::new(ptr::null_mut()),
            #[cfg(feature = "transport-probe")]
            console: AtomicBool::new(false),
        }
    }
    pub(super) fn reset(&self) {
        self.pending.store(false, Ordering::Relaxed);
        self.enabled.store(true, Ordering::Relaxed);
        self.active.store(0, Ordering::Relaxed);
        self.generation.store(0, Ordering::Relaxed);
        self.exiting.store(false, Ordering::Relaxed);
        self.cleanup.store(ptr::null_mut(), Ordering::Relaxed);
        #[cfg(feature = "transport-probe")]
        self.console.store(false, Ordering::Relaxed);
    }
    fn requested(&self) -> bool {
        self.pending.load(Ordering::SeqCst) && self.enabled.load(Ordering::SeqCst)
    }
}

fn state() -> Option<&'static State> {
    super::current_launch().map(|launch| &launch.cancel)
}

pub(super) fn requested() -> bool {
    state().is_some_and(State::requested)
}

/// An explicit cancellation window. It must be closed at the C boundary,
/// after all internal Rust resources have been dropped, before taking cancellation.
pub(crate) struct Point(Option<&'static State>);
impl Point {
    pub(crate) fn begin() -> Self {
        let state = state();
        if let Some(state) = state {
            #[cfg(feature = "transport-probe")]
            state.console.store(false, Ordering::Relaxed);
            let generation = state
                .generation
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .expect("cancellation generation exhausted")
                + 1;
            state.active.store(generation, Ordering::SeqCst);
            if state.requested() {
                terminate();
            }
        }
        Self(state)
    }
    pub(crate) fn requested(&self) -> bool {
        self.0.is_some_and(State::requested)
    }
    pub(crate) fn end(self) {
        if let Some(state) = self.0 {
            state.active.store(0, Ordering::SeqCst);
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
    state.enabled.store(false, Ordering::SeqCst);
    state.active.store(0, Ordering::SeqCst);
    state.exiting.store(true, Ordering::Release);
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
    let Some(state) = state() else {
        return EINVAL;
    };
    if !matches!(value, PTHREAD_CANCEL_ENABLE | PTHREAD_CANCEL_DISABLE)
        || (value == PTHREAD_CANCEL_ENABLE && state.exiting.load(Ordering::Acquire))
    {
        return EINVAL;
    }
    let was = state
        .enabled
        .swap(value == PTHREAD_CANCEL_ENABLE, Ordering::SeqCst);
    if !old.is_null() {
        unsafe {
            old.write(if was {
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
    #[cfg(feature = "transport-probe")]
    if let Some(state) = state() {
        state.console.store(true, Ordering::Release);
    }
}
