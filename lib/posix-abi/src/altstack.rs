// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The alternate signal stack of each thread (XSH sigaltstack, SA_ONSTACK).
//!
//! The kernel keeps the range (`rt::upcall::set_stack`): an entry that
//! interrupts code with its stack pointer outside the range starts at the
//! top of it, with the dispatcher's frame there. Everything else is here:
//! which handler runs on which stack, the account of "on the alternate
//! stack", the check that an overflow of the alternate stack ends the
//! process, and what the longjmp hook needs to compare frames on two
//! stacks (`entries::call_frame`).
//!
//! A handler with SA_ONSTACK runs on the alternate stack, a handler
//! without it on the interrupted stack. When the entry came to the top of
//! the alternate stack and the handler leaves for the interrupted stack,
//! the dispatcher's frame stays live there: the kernel's range is cut to end
//! below that frame while the handler runs, so that a nested entry of the
//! handler (with SA_ONSTACK) starts under the frame and does not tread
//! on it.

use crate::constants::*;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use posix_types::constants::{SS_DISABLE, SS_ONSTACK};

/// The smallest alternate stack (MINSIGSTKSZ of the headers): the
/// dispatcher's frame (`rt::upcall::FRAME_SIZE`), the layer's delivery with
/// the ucontext of an SA_SIGINFO handler, and room for the handler.
pub const MINSIGSTKSZ: u64 = 12_288;

const _: () = assert!(MINSIGSTKSZ >= rt::upcall::FRAME_SIZE as u64 + 8192);

/// The alternate stack of one thread place.
struct Alt {
    /// What the program gave: base and size.
    base: AtomicU64,
    size: AtomicU64,
    /// The range the kernel holds, aligned to 16: `low` to `high`, 0 and 0
    /// without a stack.
    low: AtomicU64,
    high: AtomicU64,
    /// A handler that started on the alternate stack is running.
    active: AtomicBool,
    /// The stack pointer a handler without SA_ONSTACK started with while
    /// the dispatcher's frame is at the top of the alternate stack, else 0.
    floor: AtomicU64,
    /// Where the kernel's range ends while a handler off the stack runs
    /// (below the live frame); 0 when it ends at `high`.
    cut: AtomicU64,
}

impl Alt {
    const fn new() -> Self {
        Self {
            base: AtomicU64::new(0),
            size: AtomicU64::new(0),
            low: AtomicU64::new(0),
            high: AtomicU64::new(0),
            active: AtomicBool::new(false),
            floor: AtomicU64::new(0),
            cut: AtomicU64::new(0),
        }
    }
    fn clear(&self) {
        self.cut.store(0, Ordering::Relaxed);
        self.base.store(0, Ordering::Relaxed);
        self.size.store(0, Ordering::Relaxed);
        self.low.store(0, Ordering::Relaxed);
        self.high.store(0, Ordering::Relaxed);
        self.active.store(false, Ordering::Relaxed);
        self.floor.store(0, Ordering::Relaxed);
    }
}

/// Some thread set an alternate stack once: until then no thread has one, and
/// the path of every signal skips the table (the flag never goes back).
static EVER: AtomicBool = AtomicBool::new(false);

static ALT: [Alt; crate::relibc::PLACES + 1] = [const { Alt::new() }; crate::relibc::PLACES + 1];

/// A thread with no block (before its attachment) has no stack: its row is
/// a spare one that nothing writes.
static NONE: Alt = Alt::new();

fn row() -> &'static Alt {
    // SAFETY: a published block lives as long as its thread.
    match unsafe { posix_thread::block().as_ref() } {
        Some(block) => &ALT[usize::try_from(block.thread_id).expect("a bounded thread place")],
        None => &NONE,
    }
}

/// A reused place has no alternate stack.
pub(crate) fn reset(place: u64) {
    ALT[place as usize].clear();
}

/// In a forked child only the calling thread exists: the other places lose
/// their stacks; the caller's goes on.
pub(crate) fn after_fork() {
    let mine = row() as *const Alt;
    for alt in &ALT {
        if !core::ptr::eq(alt, mine) {
            alt.clear();
        }
    }
}

/// Whether the calling thread has an alternate stack: one load.
#[inline(always)]
pub(crate) fn has_stack() -> bool {
    if !EVER.load(Ordering::Relaxed) {
        return false;
    }
    // SAFETY: a published block lives as long as its thread.
    match unsafe { posix_thread::block().as_ref() } {
        Some(block) => ALT[block.thread_id as usize].high.load(Ordering::Relaxed) != 0,
        None => false,
    }
}

/// The range the kernel holds for the calling thread.
pub(crate) fn range() -> Option<(u64, u64)> {
    let alt = row();
    let high = alt.high.load(Ordering::Relaxed);
    (high != 0).then(|| (alt.low.load(Ordering::Relaxed), high))
}

/// The stack pointer of the caller.
#[inline(always)]
fn stack_pointer() -> u64 {
    let sp: u64;
    // SAFETY: reads the stack pointer, and nothing else.
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack, preserves_flags));
    }
    sp
}

/// Whether the caller runs on the alternate stack (SS_ONSTACK).
pub(crate) fn on_alternate() -> bool {
    range().is_some_and(|(low, high)| (low..high).contains(&stack_pointer()))
}

/// The state of the stack for a handler's `uc_stack`: the base the program
/// gave, its size and `ss_flags` as sigaltstack gives them.
#[inline(always)]
pub(crate) fn state() -> (u64, u64, i32) {
    if !has_stack() {
        return (0, 0, SS_DISABLE);
    }
    state_on_stack()
}

#[inline(never)]
fn state_on_stack() -> (u64, u64, i32) {
    let alt = row();
    let flags = if on_alternate() { SS_ONSTACK } else { 0 };
    (
        alt.base.load(Ordering::Relaxed),
        alt.size.load(Ordering::Relaxed),
        flags,
    )
}

/// Gives the kernel the range of the calling thread, if it has one: after a
/// new binding of the entry (a child of `fork`).
pub(crate) fn reinstate() -> Result<(), i32> {
    match range() {
        Some((low, high)) => rt::upcall::set_stack(low, high - low).map_err(|_| EIO),
        None => Ok(()),
    }
}

/// sigaltstack: sets the stack of the calling thread to `new` (base, size,
/// flags) when given; the stack before. EINVAL for flags other than 0 and
/// SS_DISABLE or for a range outside user space, EPERM while the thread runs
/// on the stack, ENOMEM for a stack smaller than MINSIGSTKSZ.
pub fn sigaltstack(new: Option<(u64, u64, i32)>) -> Result<(u64, u64, i32), i32> {
    let before = state();
    let Some((base, size, flags)) = new else {
        return Ok(before);
    };
    if flags & !SS_DISABLE != 0 {
        return Err(EINVAL);
    }
    if on_alternate() {
        return Err(EPERM);
    }
    let alt = row();
    if flags & SS_DISABLE != 0 {
        rt::upcall::set_stack(0, 0).map_err(|_| EINVAL)?;
        alt.clear_stack();
        return Ok(before);
    }
    if size < MINSIGSTKSZ {
        return Err(ENOMEM);
    }
    let end = base.checked_add(size).ok_or(EINVAL)?;
    let low = base.checked_add(15).ok_or(EINVAL)? & !15;
    let high = end & !15;
    // The aligned range loses 30 bytes at most, which MINSIGSTKSZ has to spare.
    rt::upcall::set_stack(low, high - low).map_err(|_| EINVAL)?;
    EVER.store(true, Ordering::Relaxed);
    alt.base.store(base, Ordering::Relaxed);
    alt.size.store(size, Ordering::Relaxed);
    alt.low.store(low, Ordering::Relaxed);
    alt.high.store(high, Ordering::Relaxed);
    Ok(before)
}

impl Alt {
    fn clear_stack(&self) {
        self.base.store(0, Ordering::Relaxed);
        self.size.store(0, Ordering::Relaxed);
        self.low.store(0, Ordering::Relaxed);
        self.high.store(0, Ordering::Relaxed);
    }
}

/// Whether the interrupted code `sp` ran on the alternate stack and ran out
/// of it: a handler of the stack is live and the pointer lies below its
/// range. The kernel put the new frame at the top, over the live ones, so
/// the process ends (the caller has no handler to run).
pub(crate) fn overflowed(sp: u64) -> bool {
    let alt = row();
    alt.active.load(Ordering::Relaxed)
        && range().is_some_and(|(low, high)| !(low..=high).contains(&sp))
}

/// Where a handler runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Place {
    /// On the stack of the caller; the thread has no alternate stack.
    Plain,
    /// On the stack of the caller.
    Here,
    /// On the alternate stack, from its top (a delivery with no entry).
    Alternate { top: u64 },
    /// On the interrupted stack from `sp`, while the dispatcher's frame
    /// at `frame` stays at the top of the alternate stack.
    Interrupted { sp: u64, frame: u64 },
}

/// The place of a handler with SA_ONSTACK set or not (`on_stack`) for the
/// delivery with the entry frame `frame` (0 without an entry), whose
/// interrupted stack pointer is `sp`.
pub(crate) fn place(on_stack: bool, frame: u64, sp: u64) -> Place {
    let Some((low, high)) = range() else {
        return Place::Plain;
    };
    let here = on_alternate();
    if on_stack {
        if here {
            Place::Here
        } else {
            // Under the live frames while a handler off the stack runs.
            let cut = row().cut.load(Ordering::Relaxed);
            Place::Alternate {
                top: if cut != 0 { cut } else { high },
            }
        }
    } else if frame != 0 && here && !(low..=high).contains(&sp) {
        // The dispatcher's frame is at the top and the interrupted code is
        // elsewhere: the handler goes back there.
        Place::Interrupted {
            sp: sp & !15,
            frame,
        }
    } else {
        Place::Here
    }
}

/// Runs `body` at `place`.
#[inline(always)]
pub(crate) fn run(place: Place, body: impl FnOnce()) {
    if place == Place::Plain {
        // The path of every signal of a thread with no alternate stack.
        return body();
    }
    run_placed(place, body)
}

fn run_placed(place: Place, body: impl FnOnce()) {
    let alt = row();
    match place {
        Place::Plain => body(),
        Place::Here => {
            if on_alternate() {
                let before = alt.active.swap(true, Ordering::Relaxed);
                body();
                alt.active.store(before, Ordering::Relaxed);
            } else {
                body();
            }
        }
        Place::Alternate { top } => {
            let before = alt.active.swap(true, Ordering::Relaxed);
            on_stack(top, body);
            alt.active.store(before, Ordering::Relaxed);
        }
        Place::Interrupted { sp, frame } => {
            let (low, high) = range().expect("a range for an interrupted place");
            // The range ends below everything live on the alternate stack
            // while the handler runs: the dispatcher's frame at the top and
            // the delivery of the layer under it, down to this frame.
            let _ = frame;
            // The frames of `on_stack` and of the switch lie under this frame: 512
            // bytes keep a nested entry off them.
            let end = (stack_pointer() & !15).saturating_sub(512);
            let cut = alt.cut.swap(end, Ordering::Relaxed);
            let _ = rt::upcall::set_stack(low, end.saturating_sub(low));
            let before = alt.floor.swap(sp, Ordering::Relaxed);
            on_stack(sp, body);
            alt.floor.store(before, Ordering::Relaxed);
            alt.cut.store(cut, Ordering::Relaxed);
            let back = if cut == 0 { high } else { cut };
            let _ = rt::upcall::set_stack(low, back - low);
        }
    }
}

/// The stack pointer a handler without SA_ONSTACK started with, 0 when none.
pub(crate) fn floor() -> u64 {
    row().floor.load(Ordering::Relaxed)
}

/// A long jump to the stack pointer `target`: the frame of the live resident
/// call whose entry frame is `outer`, and whether the jump leaves it. The
/// bookkeeping the jump ends goes with it: the cut range comes back and the
/// account of a handler on the alternate stack ends when the target lies
/// outside the stack.
pub(crate) fn jump(outer: u64, target: u64) -> bool {
    let alt = row();
    let range = range();
    let call = entries::call_frame(outer, floor(), range);
    let leaves = entries::jump_clears_frames(outer, call, entries::frame_in(target, range));
    if let Some((low, high)) = range {
        // A handler off the stack is left by a jump to a target outside the
        // range and above its start (a target on the alternate stack is a
        // handler under it, whose address says nothing of `floor`); relibc's threads keep `outer` at 0, so
        // this does not depend on `leaves`.
        let floor = alt.floor.load(Ordering::Relaxed);
        if floor != 0 && !(low..high).contains(&target) && target > floor {
            alt.floor.store(0, Ordering::Relaxed);
            alt.cut.store(0, Ordering::Relaxed);
            let _ = rt::upcall::set_stack(low, high - low);
        }
        if !(low..high).contains(&target) {
            alt.active.store(false, Ordering::Relaxed);
        }
    }
    leaves
}

/// Calls `body` with the stack pointer at `sp` (16-aligned), then goes
/// back to the caller's stack.
fn on_stack<F: FnOnce()>(sp: u64, body: F) {
    let mut slot = Some(body);
    // SAFETY: `thunk` runs the closure once, on the new stack; `stafeto_call_on`
    // restores the old stack pointer. A body that leaves by a long jump
    // never returns here.
    unsafe {
        stafeto_call_on(
            sp & !15,
            thunk::<F> as *const () as usize,
            core::ptr::from_mut(&mut slot) as usize,
        )
    }
}

unsafe extern "C" fn thunk<F: FnOnce()>(slot: *mut Option<F>) {
    // SAFETY: `on_stack` passes its own live slot.
    if let Some(body) = unsafe { (*slot).take() } {
        body();
    }
}

#[cfg(target_os = "none")]
unsafe extern "C" {
    /// Runs `function(argument)` with the stack pointer at `sp` and
    /// returns to the caller's stack afterwards.
    fn stafeto_call_on(sp: u64, function: usize, argument: usize);
}

/// On a host the stack is not switched (the tests do not run handlers).
#[cfg(not(target_os = "none"))]
unsafe fn stafeto_call_on(_sp: u64, function: usize, argument: usize) {
    // SAFETY: `function` is a `thunk`.
    let function: unsafe extern "C" fn(usize) = unsafe { core::mem::transmute(function) };
    unsafe { function(argument) }
}

#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".text",
    ".global stafeto_call_on",
    ".type stafeto_call_on,%function",
    "stafeto_call_on:",
    "stp x29, x30, [sp, #-16]!",
    "mov x29, sp",
    "mov x9, sp",
    "mov sp, x0",
    "stp x9, xzr, [sp, #-16]!",
    "mov x10, x1",
    "mov x0, x2",
    "blr x10",
    "ldp x9, xzr, [sp], #16",
    "mov sp, x9",
    "ldp x29, x30, [sp], #16",
    "ret",
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_smallest_stack_holds_the_dispatcher_frame_and_a_handler() {
        assert!(MINSIGSTKSZ > rt::upcall::FRAME_SIZE as u64);
    }
}
