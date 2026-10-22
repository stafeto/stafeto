// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The lock `OBJ` of the kernel objects (SMP stage 3, decision 1): one
//! ticket lock for every change to the links between objects: channels and
//! their queues, handle tables, mappings, processes and their threads,
//! thread numbers, the frames of memory (`FRAMES`) and the ASIDs. It is
//! taken for a section of a kernel call with interrupts masked and held
//! for at most `OBJ_HOLD_MAX` instructions (xtask).
//!
//! The order of locks is this module's: `OBJ` first, then the ticket lock
//! of a CPU's cleanup queue (`Local::queue_spin`), the only other lock CPUs
//! share, which a section may take and whose holder takes nothing. What a
//! CPU alone owns (its scheduler, timers and log ring, `local`) has no
//! lock, since nothing but that CPU reaches it, and a section under `OBJ`
//! reaches it freely. The rules that keep it so:
//!
//! 1. `lock` is the one way to take `OBJ`, and the places that call it are
//!    the takes of the kernel (xtask lists them). It does not nest: a CPU
//!    that holds `OBJ` and calls it again stops a test build (`obj_checks`).
//!    Code that runs inside a section asserts it (`assert_held`) and leaves
//!    the take to its caller; the guard it returns ends the section when it
//!    drops, or goes by value to the call that leaves the stack
//!    (`sched::resume_from`, `thread::run_from`).
//! 2. A datum that `OBJ` guards (`Guarded`) is lent inside a section only:
//!    the loan asserts the section and never takes the lock. A section
//!    waits for nothing but `OBJ` itself, and touches no datum of another
//!    CPU (stage 4 reaches another CPU by a command).
//! 3. Work on what no link reaches goes on outside any section: the bytes
//!    of a message past the registers, up to 960 of them, the zeroing of
//!    a frame, the teardown of a detached object. A call that has such work
//!    between two steps takes a section for each step.
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
use core::sync::atomic::{AtomicU32, AtomicU64};
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
    {
        SERVING.store(_what, Relaxed);
        if _what != 0 {
            LAST_KIND.store(_what as u32, Relaxed);
        }
    }
}

/// A section under `OBJ`: dropping the guard gives the lock back.
#[must_use = "the section ends when the guard drops"]
pub struct Section {
    /// Turns off `Send`: the CPU that took the lock gives it back.
    _cpu: PhantomData<*mut ()>,
}

/// The id of this CPU's block, which names it as the holder.
#[inline(always)]
fn me() -> usize {
    cpu::this() as *const cpu::CpuBlock as usize
}

/// Enters a section under `OBJ`: waits for the lock. This CPU holds none
/// (a test build stops otherwise).
#[inline(always)]
#[track_caller]
pub fn lock() -> Section {
    #[cfg(obj_checks)]
    assert!(!held(), "OBJ taken inside a section");
    acquire(me());
    Section { _cpu: PhantomData }
}

#[inline(never)]
fn acquire(me: usize) {
    #[cfg(feature = "smp-measure")]
    let began = crate::arch::timer::now_unordered();
    OBJ.lock();
    #[cfg(feature = "smp-measure")]
    crate::smpm::waited(crate::arch::timer::now_unordered().wrapping_sub(began));
    OWNER.store(me, Relaxed);
    #[cfg(feature = "measure")]
    SINCE.store(crate::arch::timer::now_unordered(), Relaxed);
}

impl Drop for Section {
    #[inline(always)]
    fn drop(&mut self) {
        release();
    }
}

/// The end of a section: the hold counts, and the next ticket is served.
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

/// The number of the section a code has looked at a queue in (`mark`), which
/// the builds with `obj_checks` and the probe kernels of the window keep and
/// nothing else does. The number of a section is the ticket the lock serves
/// while it lasts (`Ticket::served`): each take adds one to it, under the
/// lock, so the section needs no counter of its own. The ticket has 16 bits,
/// which is enough: the lock is fair (first come, first served), so between
/// the two looks of a code that gave the lock back, at most one take of each
/// other CPU comes ahead of its new ticket, and the number moves on by at
/// most the number of CPUs; a gap cannot bring it round to the same value.
#[derive(Clone, Copy)]
pub struct Mark(#[cfg(section_marks)] u16);

/// Takes the number of the section now: `receive` and `send` do it at the
/// first look at a queue (spec 6.1), and `Mark::same_section` checks it where
/// the request is taken off.
#[inline(always)]
pub fn mark() -> Mark {
    Mark(
        #[cfg(section_marks)]
        OBJ.served(),
    )
}

impl Mark {
    /// Stops a test build that gave `OBJ` back and took it again since the
    /// mark: what was seen of the queue is no longer what it holds.
    #[inline(always)]
    #[track_caller]
    pub fn same_section(self) {
        #[cfg(section_marks)]
        assert!(
            self.0 == OBJ.served(),
            "OBJ was given back between the look at a queue and the take of its request"
        );
    }
}

/// The probe `break-one-section`: gives `OBJ` back and takes it again inside
/// the section of the caller's guard, as the second section of a receive
/// that looked at the head of a queue in the first would.
#[cfg(feature = "break-one-section")]
pub fn split_section() {
    assert!(held(), "no section to split");
    release();
    acquire(me());
}

/// Ends the section of a frame that is abandoned and never drops its
/// guard: init's end in a test build, which never returns.
#[cfg(feature = "ktest")]
pub fn abandon() {
    if held() {
        release();
    }
}

/// The takes of `OBJ` in a stretch of a CPU between two polls for an
/// interrupt: each may wait for (N-1) holds of the other CPUs, so xtask
/// bounds the blocking time of N CPUs by the longest stretch with k takes
/// plus k * (N-1) * OBJ_HOLD_MAX, over every k. A stretch begins at an entry
/// from EL0, at a poll, or on waking from `wfi`; it ends at a poll, at the
/// way to EL0, or at `wfi`. The last count holds `TAKES_KEPT` takes and more.
/// The takes are the tickets of the lock, which cost a take nothing: exact
/// on one CPU, and more than this CPU's own on several. The kernel tests
/// open a stretch for each call they make and close it when the call
/// returns, and drop the stretch of a test call from EL0 (`stretch_drop`):
/// the code of a test is in no stretch.
#[cfg(feature = "measure")]
pub const TAKES_KEPT: usize = 16;

/// What the last named section served, which names a stretch.
#[cfg(feature = "measure")]
static LAST_KIND: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "measure")]
struct Stretch {
    /// The counter when the stretch began, 0 when none is open.
    since: AtomicU64,
    /// The tickets of the lock when the stretch began.
    tickets: AtomicU32,
    /// The longest stretch so far with each count of takes, in ticks, and
    /// the kind of its last section.
    longest: [AtomicU64; TAKES_KEPT + 1],
    kind: [AtomicU32; TAKES_KEPT + 1],
}

/// Each CPU's own, written by that CPU alone.
#[cfg(feature = "measure")]
static STRETCH: [Stretch; crate::arch::cpu::MAX_CPUS] = [const {
    Stretch {
        since: AtomicU64::new(0),
        tickets: AtomicU32::new(0),
        longest: [const { AtomicU64::new(0) }; TAKES_KEPT + 1],
        kind: [const { AtomicU32::new(0) }; TAKES_KEPT + 1],
    }
}; crate::arch::cpu::MAX_CPUS];

/// The stretch open on this CPU ends at `now`, and counts with its takes.
#[cfg(feature = "measure")]
#[inline(always)]
pub fn stretch_ends(now: u64) {
    let s = &STRETCH[crate::arch::cpu::this().index()];
    let since = s.since.load(Relaxed);
    if since != 0 {
        let takes = OBJ.tickets().wrapping_sub(s.tickets.load(Relaxed) as u16);
        let k = usize::from(takes).min(TAKES_KEPT);
        let took = now.wrapping_sub(since);
        let kind = LAST_KIND.load(Relaxed);
        if took > s.longest[k].load(Relaxed) {
            s.longest[k].store(took, Relaxed);
            s.kind[k].store(kind, Relaxed);
        }
        // The most takes of a stretch of each kind, with its length.
        let worst = &TAKES_BY_KIND[(kind as usize).min(KINDS - 1)];
        let packed = (k as u64) << 48 | took.min(0xffff_ffff_ffff);
        if packed > worst.load(Relaxed) {
            worst.store(packed, Relaxed);
        }
        s.since.store(0, Relaxed);
    }
}

/// The most takes of a stretch by the kind of its last section, in bits
/// 48-63, and that stretch's length below.
#[cfg(feature = "measure")]
static TAKES_BY_KIND: [AtomicU64; KINDS] = [const { AtomicU64::new(0) }; KINDS];

/// The most takes in a stretch of each kind, and its length (TAKES_BY_KIND).
#[cfg(all(feature = "measure", feature = "ktest"))]
pub fn takes_by_kind() -> [(u64, u64); KINDS] {
    core::array::from_fn(|i| {
        let packed = TAKES_BY_KIND[i].load(Relaxed);
        (packed >> 48, packed & 0xffff_ffff_ffff)
    })
}

/// A stretch begins on this CPU at `now`, with no take yet.
#[cfg(feature = "measure")]
#[inline(always)]
pub fn stretch_begins(now: u64) {
    let s = &STRETCH[crate::arch::cpu::this().index()];
    s.since.store(now, Relaxed);
    s.tickets.store(u32::from(OBJ.tickets()), Relaxed);
    LAST_KIND.store(0, Relaxed);
}

/// The stretch open on this CPU counts for nothing: the code of a test runs
/// in it.
#[cfg(all(feature = "measure", feature = "ktest"))]
pub fn stretch_drop() {
    STRETCH[crate::arch::cpu::this().index()]
        .since
        .store(0, Relaxed);
}

/// The longest stretch with each count of takes over every CPU, in ticks,
/// with the kind of its last section: the lines `obj takes ticks: k=C` of
/// the measuring images.
#[cfg(all(feature = "measure", any(feature = "ktest", feature = "smp-measure")))]
pub fn stretches_by_takes() -> [(u64, u32); TAKES_KEPT + 1] {
    core::array::from_fn(|k| {
        STRETCH
            .iter()
            .map(|s| (s.longest[k].load(Relaxed), s.kind[k].load(Relaxed)))
            .max()
            .unwrap_or((0, 0))
    })
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

/// Forgets the stretches so far (`smpm::reset`).
#[cfg(feature = "smp-measure")]
pub fn reset_stretches() {
    for s in &STRETCH {
        for took in &s.longest {
            took.store(0, Relaxed);
        }
    }
}

/// Forgets the holds so far (`smpm::reset`).
#[cfg(feature = "smp-measure")]
pub fn reset_holds() {
    for held in &BY_KIND {
        held.store(0, Relaxed);
    }
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
    assert!(held() || in_test(), "a link of objects changes outside OBJ");
}

/// Stops a test build that works on what no link reaches while it holds
/// `OBJ` (rule 3): the copy of a message, which goes outside the section.
#[inline(always)]
#[track_caller]
pub fn assert_not_held() {
    #[cfg(obj_checks)]
    assert!(!held() || in_test(), "work on unlinked data inside OBJ");
}

/// The code of a test runs inside: it calls the kernel's functions without
/// an entry.
#[cfg(all(obj_checks, feature = "ktest"))]
pub struct TestScope(bool);

#[cfg(all(obj_checks, feature = "ktest"))]
pub fn test_scope() -> TestScope {
    TestScope(swap_in_test(true))
}

/// The way out of the kernel ends the code of a test that never returns.
#[cfg(obj_checks)]
pub fn end_test_scope() {
    set_in_test(false);
}

#[cfg(all(obj_checks, feature = "ktest"))]
impl Drop for TestScope {
    fn drop(&mut self) {
        set_in_test(self.0);
    }
}

/// Whether the code that runs on this CPU is a test's or the boot's: the
/// checks of `assert_held` leave it alone. True until the CPU's first way out
/// of the kernel. The flag lives in the CPU's block, so that a test scope on
/// one CPU leaves the checks of the others on. The block keeps it inverted
/// (`checked`), so that it starts as zero and the blocks stay in the bss.
#[cfg(obj_checks)]
#[inline(always)]
fn in_test() -> bool {
    !cpu::this().checked.load(Relaxed)
}

#[cfg(obj_checks)]
#[inline(always)]
fn set_in_test(now: bool) {
    cpu::this().checked.store(!now, Relaxed);
}

/// Sets the flag and returns what it was.
#[cfg(obj_checks)]
#[inline(always)]
fn swap_in_test(now: bool) -> bool {
    !cpu::this().checked.swap(!now, Relaxed)
}

/// An entry of the kernel runs inside: the checks apply to it, whoever
/// called it. The tests call `dispatch` with the checks on this way.
#[cfg(obj_checks)]
pub struct Production(bool);

#[cfg(obj_checks)]
pub fn production() -> Production {
    Production(swap_in_test(false))
}

#[cfg(obj_checks)]
impl Drop for Production {
    fn drop(&mut self) {
        set_in_test(self.0);
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
/// inside a section, which the caller holds. A test build stops on a loan
/// outside a section and on a second loan while the first lives.
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

    /// The loan of the datum, inside the caller's section.
    #[inline(always)]
    #[track_caller]
    pub fn lock(&self) -> Loan<'_, T> {
        assert_held();
        #[cfg(obj_checks)]
        assert!(!self.lent.swap(true, Relaxed), "a datum of OBJ lent twice");
        Loan { from: self }
    }
}

/// The loan of a `Guarded` datum.
pub struct Loan<'a, T> {
    from: &'a Guarded<T>,
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
