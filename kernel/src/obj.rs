// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The lock `OBJ` of the kernel objects (SMP stage 3, decision 1): one
//! ticket lock for every change to the links between objects: channels and
//! their queues, handle tables, mappings, processes and their threads,
//! thread numbers, the frames of memory (`FRAMES`) and the ASIDs. It is
//! taken for a section of a kernel call with interrupts masked and held
//! for at most `OBJ_HOLD_MAX` instructions (xtask).
//!
//! The order of locks is this module's: `OBJ` is the only lock CPUs share.
//! What a CPU alone owns (its scheduler, timers, cleanup queue and log
//! ring, `local`) has no lock, since nothing but that CPU reaches it, and
//! a section under `OBJ` reaches it freely. So no lock is taken while
//! `OBJ` is held, and none stands before it. The rules that keep it so:
//!
//! 1. `lock` takes `OBJ` unless this CPU holds it already, and a guard
//!    that took it gives it back when it drops. A section nests, then, and
//!    a call may lock as a whole and call code that locks too; the code
//!    that shares a datum (`Guarded`, `sched::locked`) locks for itself.
//! 2. A section waits for nothing but `OBJ` itself, and touches no datum
//!    of another CPU (stage 4 reaches another CPU by a command).
//! 3. Work on what no link reaches goes on outside the section: the bytes
//!    of a message past the registers, up to 960 of them, the zeroing of
//!    a frame, the teardown of a detached object (`outside`).
//!
//! Test builds check the places that change a link nobody else guards
//! (`assert_held`): inside an entry of the kernel (`production`), such a
//! change outside a section stops the kernel. The code of the tests
//! themselves, which calls the kernel's functions without an entry, and
//! the boot are exempt (`test_scope`).

use crate::arch::cpu;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
#[cfg(feature = "measure")]
use core::sync::atomic::AtomicU64;
use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use kcore::sync::Ticket;

static OBJ: Ticket = Ticket::new();

/// The block of the CPU that holds `OBJ`, 0 for none.
static OWNER: AtomicUsize = AtomicUsize::new(0);

/// The counter when the holder got `OBJ`, and the longest hold so far, in
/// ticks (instructions under `-icount`), written by the holder.
#[cfg(feature = "measure")]
static SINCE: AtomicU64 = AtomicU64::new(0);
/// What the section serves: a call's number, or an entry's tag (`ENTRY_*`).
#[cfg(feature = "measure")]
static SERVING: AtomicU64 = AtomicU64::new(0);
/// The longest hold of each kind of section, by what it served. A section
/// no entry named is the code of a test, and counts in kind 0 alone.
#[cfg(feature = "measure")]
static BY_KIND: [AtomicU64; KINDS] = [const { AtomicU64::new(0) }; KINDS];

/// The kinds: calls by number (below 40), then the entries other than a
/// call, as `serving` names them.
#[cfg(feature = "measure")]
pub const KINDS: usize = 54;
pub const ENTRY_INTERRUPT: u64 = 40;
pub const ENTRY_CLEANUP: u64 = 41;
pub const ENTRY_FAULT: u64 = 42;
pub const ENTRY_PARK: u64 = 44;
pub const ENTRY_ASID: u64 = 45;
/// The cleanup of each kind of object (cleanup.rs).
pub const CLEAN_THREAD: u64 = 46;
pub const CLEAN_CHANNEL: u64 = 47;
pub const CLEAN_SESSION: u64 = 48;
pub const CLEAN_TIMER: u64 = 49;
pub const CLEAN_IRQ: u64 = 50;
pub const CLEAN_FIRE: u64 = 51;
pub const CLEAN_MEMORY: u64 = 52;
pub const CLEAN_PROCESS: u64 = 53;

/// Names what the section being entered serves, for the longest hold's
/// report: only the images that measure keep it. A section that is not
/// named does not count toward `OBJ_HOLD_MAX`.
#[inline(always)]
pub fn serving(_what: u64) {
    #[cfg(feature = "measure")]
    SERVING.store(_what, Relaxed);
}

/// A section under `OBJ`: dropping the guard that took the lock gives it
/// back.
#[must_use = "the section ends when the guard drops"]
pub struct Section {
    took: bool,
    /// Turns off `Send`: the CPU that took the lock gives it back.
    _cpu: PhantomData<*mut ()>,
}

/// The id of this CPU's block, which names it as the holder.
#[inline(always)]
fn me() -> usize {
    cpu::this() as *const cpu::CpuBlock as usize
}

/// Enters a section under `OBJ` at an entry into the kernel, where this CPU
/// holds none: waits for the lock.
#[inline(always)]
pub fn enter() -> Section {
    #[cfg(obj_checks)]
    assert!(!held(), "OBJ entered inside a section");
    acquire(me());
    Section {
        took: true,
        _cpu: PhantomData,
    }
}

/// Enters a section under `OBJ`: waits for the lock, or joins the section
/// this CPU holds.
#[inline(always)]
pub fn lock() -> Section {
    let me = me();
    if OWNER.load(Relaxed) == me {
        return Section {
            took: false,
            _cpu: PhantomData,
        };
    }
    acquire(me);
    Section {
        took: true,
        _cpu: PhantomData,
    }
}

#[inline(always)]
fn acquire(me: usize) {
    OBJ.lock();
    OWNER.store(me, Relaxed);
    #[cfg(feature = "measure")]
    SINCE.store(crate::arch::timer::now_unordered(), Relaxed);
}

impl Drop for Section {
    #[inline(always)]
    fn drop(&mut self) {
        if self.took {
            release();
        }
    }
}

/// The end of the outermost section: the hold counts, and the next ticket
/// is served.
#[inline(always)]
fn release() {
    #[cfg(feature = "measure")]
    {
        let held = crate::arch::timer::now_unordered().wrapping_sub(SINCE.load(Relaxed));
        let kind = (SERVING.load(Relaxed) as usize).min(KINDS - 1);
        if held > BY_KIND[kind].load(Relaxed) {
            BY_KIND[kind].store(held, Relaxed);
        }
        SERVING.store(0, Relaxed);
    }
    OWNER.store(0, Relaxed);
    OBJ.unlock_held();
}

/// Ends the section the caller entered, for a call that never returns to
/// drop its guard: the kernel call that leaves for another thread or for the
/// way out (`sched::resume`, `thread::run`). The guard stays on the abandoned
/// stack.
#[inline(always)]
pub fn leave() {
    #[cfg(obj_checks)]
    assert!(held(), "OBJ left outside a section");
    release();
}

/// Runs `work` with `OBJ` given back, and takes it again: `work` touches
/// only what no link reaches, such as the bytes of a message between two
/// threads that do not run, or a frame no table maps. The caller's own
/// guard stays, and so does the section it keeps.
#[inline(always)]
pub fn outside<R>(work: impl FnOnce() -> R) -> R {
    let was = held();
    if was {
        release();
    }
    let r = work();
    if was {
        acquire(me());
    }
    r
}

/// The longest hold of `OBJ` so far, in ticks, and the kind that served it:
/// `OBJ_HOLD_MAX` of xtask bounds it.
#[cfg(feature = "measure")]
pub fn longest_hold() -> (u64, u64) {
    // Kind 0 is the code of a test, which no entry named.
    holds_by_kind()
        .iter()
        .enumerate()
        .skip(1)
        .map(|(kind, &held)| (held, kind as u64))
        .max()
        .unwrap_or((0, 0))
}

/// The longest hold of each kind of section (`KINDS`).
#[cfg(feature = "measure")]
pub fn holds_by_kind() -> [u64; KINDS] {
    core::array::from_fn(|i| BY_KIND[i].load(Relaxed))
}

/// Whether this CPU is inside a section under `OBJ`.
#[inline(always)]
pub fn held() -> bool {
    OWNER.load(Relaxed) == me()
}

/// Stops an EL0 test build when a link nobody else guards changes outside a
/// section: the places that change one call it. Nothing in the build that
/// ships.
#[inline(always)]
#[track_caller]
pub fn assert_held() {
    #[cfg(obj_checks)]
    assert!(
        held() || IN_TEST.load(Relaxed),
        "a link of objects changes outside OBJ"
    );
}

/// Stops a test build that works on what no link reaches while it holds
/// `OBJ` (rule 3): the copy of a message, which goes outside the section.
#[inline(always)]
#[track_caller]
pub fn assert_not_held() {
    #[cfg(obj_checks)]
    assert!(
        !held() || IN_TEST.load(Relaxed),
        "work on unlinked data inside OBJ"
    );
}

/// The code of a test runs inside: it calls the kernel's functions without
/// an entry.
#[cfg(obj_checks)]
pub struct TestScope(bool);

#[cfg(obj_checks)]
pub fn test_scope() -> TestScope {
    TestScope(IN_TEST.swap(true, Relaxed))
}

/// The way out of the kernel ends the code of a test that never returns.
#[cfg(obj_checks)]
pub fn end_test_scope() {
    IN_TEST.store(false, Relaxed);
}

#[cfg(obj_checks)]
impl Drop for TestScope {
    fn drop(&mut self) {
        IN_TEST.store(self.0, Relaxed);
    }
}

/// Whether the code that runs is a test's or the boot's: the checks of
/// `assert_held` leave it alone. True until the first entry of the kernel.
#[cfg(obj_checks)]
static IN_TEST: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);

/// An entry of the kernel runs inside: the checks apply to it, whoever
/// called it. The tests call `dispatch` with the checks on this way.
#[cfg(obj_checks)]
pub struct Production(bool);

#[cfg(obj_checks)]
pub fn production() -> Production {
    Production(IN_TEST.swap(false, Relaxed))
}

#[cfg(obj_checks)]
impl Drop for Production {
    fn drop(&mut self) {
        IN_TEST.store(self.0, Relaxed);
    }
}

#[cfg(not(obj_checks))]
pub struct Production;

#[cfg(not(obj_checks))]
pub fn production() -> Production {
    Production
}

/// The checks are off in the build that ships and in the images that count
/// instructions; the hooks of the tests stay.
#[cfg(all(feature = "ktest", not(obj_checks)))]
pub struct TestScope;

#[cfg(all(feature = "ktest", not(obj_checks)))]
pub fn test_scope() -> TestScope {
    TestScope
}

#[cfg(not(obj_checks))]
pub fn end_test_scope() {}

/// A datum that `OBJ` guards, such as the frames of memory: `lock` lends it
/// inside a section of its own, or of the caller's. A test build stops on a
/// second loan while the first lives.
pub struct Guarded<T> {
    value: UnsafeCell<T>,
    #[cfg(obj_checks)]
    lent: core::sync::atomic::AtomicBool,
}

// SAFETY: the value is reached only under OBJ, which one CPU holds at a time.
unsafe impl<T: Send> Sync for Guarded<T> {}

impl<T> Guarded<T> {
    pub const fn new(value: T) -> Self {
        Self {
            value: UnsafeCell::new(value),
            #[cfg(obj_checks)]
            lent: core::sync::atomic::AtomicBool::new(false),
        }
    }

    #[inline(always)]
    pub fn lock(&self) -> Loan<'_, T> {
        let section = lock();
        #[cfg(obj_checks)]
        assert!(!self.lent.swap(true, Relaxed), "a datum of OBJ lent twice");
        Loan {
            from: self,
            _section: section,
        }
    }
}

/// The loan of a `Guarded` datum.
pub struct Loan<'a, T> {
    from: &'a Guarded<T>,
    // Declared last: the datum goes back before the section ends.
    _section: Section,
}

impl<T> Deref for Loan<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the loan is the only one, inside a section under OBJ.
        unsafe { &*self.from.value.get() }
    }
}

impl<T> DerefMut for Loan<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above.
        unsafe { &mut *self.from.value.get() }
    }
}

impl<T> Drop for Loan<'_, T> {
    fn drop(&mut self) {
        #[cfg(obj_checks)]
        self.from.lent.store(false, Relaxed);
    }
}
