// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! What each CPU owns (SMP stage 3, decision 1): its scheduler with the
//! ready queue and the quantum, the timers of programs, the queue of
//! cleanup, the log ring and the timing of its entries. Only the owner
//! reads or writes them, with interrupts masked, so no lock of `OBJ`'s
//! kind guards them: the `Lock` that wraps each only turns a second borrow
//! on the same CPU into a panic. `local` is the data of the CPU that calls
//! it; no function hands out the data of another CPU, and stage 4 reaches
//! another CPU's by a command it executes itself (obj.rs, rule 2).

use crate::arch::cpu;
use crate::cleanup::Item;
use crate::log::{LOG_RECORDS, Ring};
use crate::sched::Sched;
use crate::timer::{LEVELS, Timers};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};

/// A message copy waits (`Local::deferred`).
pub const COPY: u32 = 1;
/// The outbox holds commands (`Local::deferred`).
pub const OUTBOX: u32 = 2;

/// The data of one CPU, in its block (cpu::CpuBlock).
#[repr(C, align(64))]
pub struct Local {
    pub sched: Own<Sched>,
    pub timers: Own<Timers>,
    pub queue: Own<crate::cleanup::Queue>,
    pub ring: Own<Ring<LOG_RECORDS>>,
    /// The objects this CPU retired and has not freed (qsbr).
    pub retired: Own<crate::qsbr::Retired>,
    /// The copy of message bytes that waits for the end of a section
    /// (thread::copy_later).
    pub copy: Own<crate::thread::PendingCopy>,
    /// The commands for other CPUs that sections posted (cmd.rs).
    pub outbox: Own<crate::cmd::Outbox>,
    /// What the end of a call has still to do (`thread::flush_copy`): the
    /// bits `COPY` and `OUTBOX`, one load for both.
    pub deferred: core::sync::atomic::AtomicU32,
    /// The start of the open entry interval and the longest one (sched).
    pub entry: UnsafeCell<(u64, u64)>,
    /// The items of the cleanup queue for the firings of the levels of
    /// timers, level 1 first (timer). Zeros until `init`: an `Item` is not
    /// all zeros, and a `Local` of zeros lives in .bss, outside the image file.
    pub firings: [UnsafeCell<MaybeUninit<Item>>; LEVELS],
}

// SAFETY: a CPU reaches only its own `Local` (`local`), with interrupts
// masked; the other CPUs never name it.
unsafe impl Sync for Local {}

impl Local {
    pub const fn new() -> Local {
        Local {
            sched: Own::new(Sched::new()),
            timers: Own::new(Timers::new()),
            queue: Own::new(crate::cleanup::Queue::new()),
            ring: Own::new(Ring::new()),
            retired: Own::new(crate::qsbr::Retired::new()),
            copy: Own::new(crate::thread::PendingCopy::new()),
            outbox: Own::new(crate::cmd::Outbox::new()),
            deferred: core::sync::atomic::AtomicU32::new(0),
            entry: UnsafeCell::new((0, 0)),
            firings: [const { UnsafeCell::new(MaybeUninit::zeroed()) }; LEVELS],
        }
    }
}

/// Makes the items of a CPU's data, which has not started: runs from
/// `cpu::prepare`.
pub fn init(local: &Local) {
    for item in &local.firings {
        // SAFETY: the CPU has not started: nothing else reaches the item.
        unsafe { (*item.get()).write(Item::new()) };
    }
}

/// The data of the CPU that runs this.
#[inline(always)]
pub fn local() -> &'static Local {
    &cpu::this().local
}

/// A datum of one CPU: its owner borrows it with `lock`, which takes no
/// lock, since nothing else reaches it. Test builds count the borrow and
/// stop the kernel on a second one while the first lives, as the flag of the
/// lock of one CPU did; the build that ships has neither the count nor its
/// instructions.
pub struct Own<T> {
    value: UnsafeCell<T>,
    #[cfg(obj_checks)]
    busy: core::sync::atomic::AtomicBool,
}

// SAFETY: only the CPU that owns the datum reaches it (`local`), with
// interrupts masked.
unsafe impl<T: Send> Sync for Own<T> {}

impl<T> Own<T> {
    pub const fn new(value: T) -> Self {
        Self {
            value: UnsafeCell::new(value),
            #[cfg(obj_checks)]
            busy: core::sync::atomic::AtomicBool::new(false),
        }
    }

    #[inline(always)]
    pub fn lock(&self) -> OwnGuard<'_, T> {
        #[cfg(obj_checks)]
        assert!(
            !self.busy.swap(true, core::sync::atomic::Ordering::Relaxed),
            "a datum of a CPU borrowed twice"
        );
        OwnGuard(self)
    }

    /// The value's address, for the panic, which reads what a holder it
    /// interrupted may have left half written, and for the hints the
    /// decision reads without a borrow.
    pub fn as_ptr(&self) -> *const T {
        self.value.get()
    }
}

/// The borrow of an `Own` datum.
pub struct OwnGuard<'a, T>(&'a Own<T>);

impl<T> Deref for OwnGuard<'_, T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        // SAFETY: the guard is the only borrow, on the owner CPU.
        unsafe { &*self.0.value.get() }
    }
}

impl<T> DerefMut for OwnGuard<'_, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above.
        unsafe { &mut *self.0.value.get() }
    }
}

impl<T> Drop for OwnGuard<'_, T> {
    #[inline(always)]
    fn drop(&mut self) {
        #[cfg(obj_checks)]
        self.0
            .busy
            .store(false, core::sync::atomic::Ordering::Relaxed);
    }
}
