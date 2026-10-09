// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Generic current-thread entries. Signal policy belongs to a higher-level library.
//!
//! A thread has one entry in the kernel: the distributor, `entry` below. It
//! calls up to two handlers, kept in the thread's entry record (abi::msgbuf::ENTRIES):
//! the resident handler of a library such as the POSIX layer, which runs
//! with its own TLS, and then the handler of the program. The decisions are
//! in the `entries` package, which the host tests run.
use crate::handle::{Handle, Thread};
use crate::{msgbuf, sys};
use abi::{Call, Error, UpcallControl, msgbuf::ENTRIES, msgbuf::ENTRIES_SIZE};
use core::sync::atomic::{AtomicU64, Ordering};
use entries::{
    ENTRY_FLAGS, ENTRY_HOOK, ENTRY_OUTER, ENTRY_OWED, ENTRY_OWN, ENTRY_RESIDENT, ENTRY_THREAD,
    ENTRY_TLS, ENTRY_WORDS_END,
};

/// Saved AArch64 execution state passed by a context-aware entry trampoline.
/// The frame is live only until the dispatcher returns. The kernel validates
/// SP, PC, user PSTATE and the IPC address before restoring it.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Context {
    pub registers: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub tls: u64,
    pub ipc: u64,
    pub vectors: [u128; 32],
    pub fpcr: u64,
    pub fpsr: u64,
}
const _: () = {
    assert!(core::mem::size_of::<Context>() == abi::UPCALL_CONTEXT_SIZE);
    assert!(core::mem::offset_of!(Context, sp) == 248);
    assert!(core::mem::offset_of!(Context, pc) == 256);
    assert!(core::mem::offset_of!(Context, vectors) == 288);
    assert!(core::mem::offset_of!(Context, fpcr) == 800);
};

/// A handler of an entry: it gets the saved context of the interrupted
/// code, live until it returns.
pub type Dispatch = unsafe extern "C" fn(*mut Context);

// The record fills its eight words.
const _: () = assert!(ENTRY_WORDS_END <= ENTRIES_SIZE);

/// The flag of the entry record that says the kernel entry is bound.
const KERNEL_BOUND: u64 = 1;

fn word(offset: usize) -> &'static AtomicU64 {
    // SAFETY: the record is eight aligned words in the calling thread's
    // buffer, which lives as long as the thread; only this thread and the
    // entries running on it touch it, and atomics order the two.
    unsafe { &*((msgbuf::address() + ENTRIES + offset) as *const AtomicU64) }
}

fn control(operation: UpcallControl) -> Result<bool, Error> {
    // SAFETY: control touches only current-thread delivery state.
    let result = unsafe {
        sys::raw::<{ Call::ThreadUpcallControl.number() }>([
            operation.raw(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
    };
    match Error::from_code(result[0]) {
        Some(error) => Err(error),
        None => Ok(result[1] != 0),
    }
}

/// Binds the distributor in the kernel. The kernel keeps the thread's
/// deferral count across the binding, so a thread under `defer_entries`
/// binds as it is.
fn kernel_bind(entry: u64) -> Result<(), Error> {
    // SAFETY: the caller answers for entries at this address.
    let result = unsafe {
        sys::raw::<{ Call::ThreadUpcallBind.number() }>([entry, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    };
    Error::from_code(result[0]).map_or(Ok(()), Err)
}

fn bind_kernel_once() -> Result<(), Error> {
    let flags = word(ENTRY_FLAGS);
    if flags.load(Ordering::Relaxed) & KERNEL_BOUND == 0 {
        kernel_bind(entry as *const () as u64)?;
        flags.fetch_or(KERNEL_BOUND, Ordering::Relaxed);
    }
    Ok(())
}

/// Whether the record names no handler.
fn empty() -> bool {
    word(ENTRY_OWN).load(Ordering::Relaxed) == 0
        && word(ENTRY_RESIDENT).load(Ordering::Relaxed) == 0
}

/// Once the last handler is gone the entry stays bound in the kernel and is
/// masked: the distributor is bound once for the thread's life, and no
/// state of the kernel decides whether a handler may be removed.
fn mask_if_empty() -> Result<(), Error> {
    if empty() {
        mask()?;
    }
    Ok(())
}

/// Register the handler of the program on the current thread, replacing
/// the one it had; the entry is masked until `enable`. The mask is common
/// to both handlers: until the program enables, the signals of the layer on
/// this thread wait too, and the layer does not enable an entry whose
/// handler the program bound (`bind_resident`).
///
/// A child of a `fork` made inside a handler does not return from that
/// handler: it makes `_exit` or `exec` (its thread has depth 0 and no
/// entry record, while its stack holds the frames of the parent's handlers).
/// # Safety
/// `dispatch` must be safe at every point where delivery is enabled,
/// including reentry into interrupted Rust code. The handler of the program
/// runs only when no resident call is live, so a long jump out of it changes
/// nothing in the record; `abandon` serves a jump that leaves a resident
/// call without relibc's `longjmp`. The caller owns the handler's full
/// lifetime.
pub unsafe fn bind(dispatch: Dispatch) -> Result<(), Error> {
    let bound = word(ENTRY_FLAGS).load(Ordering::Relaxed) & KERNEL_BOUND != 0;
    bind_kernel_once()?;
    if bound {
        // A binding on an entry that exists (the layer's handler of a
        // thread, or the resident handler of a native one) starts masked
        // too: the program enables when its policy is set.
        mask()?;
    }
    // The last write: an entry on this thread between the writes sees the
    // handler only after everything else is in place.
    word(ENTRY_OWN).store(dispatch as usize as u64, Ordering::Release);
    Ok(())
}

/// Remove the handler of the program. The distributor stays bound in the
/// kernel for the thread's life; with no handler left the entry is masked,
/// and a request made later interrupts a wait for nothing until the next
/// `bind` and `enable`. Removing the last handler from inside a handler takes
/// effect for the next entries; the return of that handler lets the entry in
/// again (the return of an entry always does), so requests interrupt waits
/// until the next `mask`.
pub fn unbind() -> Result<(), Error> {
    word(ENTRY_OWN).store(0, Ordering::Release);
    mask_if_empty()
}

/// Register the resident handler of a library on the current thread: it
/// runs first in each entry, with `tls` in TPIDR_EL0, and TPIDR_EL0 comes
/// back to the interrupted value when it returns. Returns whether the
/// record had no handler before: then the entry is masked and the caller
/// owns the mask state and may `enable`; otherwise the program bound a
/// handler and owns it, and the caller leaves the mask alone.
/// # Safety
/// `tls` names a resident ABI word whose TCB and block remain valid until
/// this thread ends or the handler is removed; `dispatch` is safe as for
/// `bind`. `thread` is a handle of the calling thread with MANAGE, valid
/// as long as the resident handler: the distributor gives a request back to
/// the kernel through it (see `abandon`).
pub unsafe fn bind_resident(
    dispatch: Dispatch,
    tls: usize,
    thread: abi::Handle,
) -> Result<bool, Error> {
    if tls == 0 || thread.0 == 0 {
        return Err(Error::InvalidArgs);
    }
    let was_empty = empty();
    bind_kernel_once()?;
    word(ENTRY_TLS).store(tls as u64, Ordering::Relaxed);
    word(ENTRY_THREAD).store(thread.0, Ordering::Relaxed);
    word(ENTRY_RESIDENT).store(dispatch as usize as u64, Ordering::Release);
    Ok(was_empty)
}

/// Remove the resident handler; the rules of `unbind` apply.
pub fn unbind_resident() -> Result<(), Error> {
    word(ENTRY_RESIDENT).store(0, Ordering::Release);
    mask_if_empty()
}

/// Stop entries until enable, for both handlers; returns whether they were
/// already masked.
pub fn mask() -> Result<bool, Error> {
    control(UpcallControl::Mask)
}
/// Allow entries, including immediately pending requests. A thread with no
/// handler stays masked: a request would interrupt its waits for nothing.
/// # Safety
/// The bound handlers may run before this call returns; all interrupted code
/// and live resources must permit this asynchronous reentry.
pub unsafe fn enable() -> Result<bool, Error> {
    if empty() {
        return Ok(true);
    }
    control(UpcallControl::Enable)
}

/// Tells the entry record that the program is about to leave a resident
/// call by a long jump to the stack pointer `target_sp`: a resident call
/// whose frame lies below the target is abandoned, and the next entry may
/// call the handler of the program again. When a nested entry spent a
/// request and left the handler of the program to the abandoned entry, the
/// request goes back to the kernel (`entries::jump_returns`). relibc's
/// `longjmp` does the same; only a jump that leaves a resident call by other
/// means calls this first.
/// # Safety
/// The jump to `target_sp` follows at once.
pub unsafe fn abandon(target_sp: usize) {
    let outer = word(ENTRY_OUTER);
    let (live, owed) = (
        outer.load(Ordering::Relaxed),
        word(ENTRY_OWED).load(Ordering::Relaxed),
    );
    let target = target_sp as u64;
    let returns = entries::jump_returns(live, owed, target);
    outer.store(entries::after_jump(live, target), Ordering::Relaxed);
    if returns {
        word(ENTRY_OWED).store(0, Ordering::Relaxed);
        let thread =
            Handle::<Thread>::borrowed(abi::Handle(word(ENTRY_THREAD).load(Ordering::Relaxed)));
        // A refused request leaves nothing to repair: the thread ends.
        let _ = sys::thread_upcall_request(&thread);
    }
}

/// Sets or removes the hook `sys::thread_exit` runs, once, before its call.
/// The POSIX layer hands its role on there.
pub fn set_exit_hook(hook: Option<fn()>) {
    word(ENTRY_HOOK).store(hook.map_or(0, |f| f as usize as u64), Ordering::Relaxed);
}

/// Runs and clears the exit hook of this thread.
pub(crate) fn run_exit_hook() {
    let hook = word(ENTRY_HOOK).swap(0, Ordering::Relaxed);
    if hook != 0 {
        // SAFETY: the word holds an `fn()` that `set_exit_hook` stored.
        let hook: fn() = unsafe { core::mem::transmute(hook as usize) };
        hook();
    }
}

/// Writes word `index` of the saved context in the thread's buffer, for a
/// probe that tests the kernel's validation of the return.
#[cfg(feature = "count-calls")]
pub fn write_context_word(index: usize, value: u64) {
    assert!(index < abi::UPCALL_CONTEXT_SIZE / 8, "past the context");
    // SAFETY: the word lies in the context of the calling thread's buffer.
    unsafe {
        core::ptr::write_volatile(
            (msgbuf::address() + abi::UPCALL_CONTEXT_OFFSET + 8 * index) as *mut u64,
            value,
        )
    };
}

/// Stop handlers entering until all guards drop; enabled IPC waits stay
/// interruptible. Drop releases one nesting level; it can immediately enter
/// a pending handler. The guard must outlive all exclusive borrows it
/// protects and remain on its creating thread. It neither changes nor
/// restores the application's mask.
#[must_use = "keep the guard until all protected references have ended"]
pub struct DeferredEntry(core::marker::PhantomData<*mut ()>);
pub fn defer_entries() -> Result<DeferredEntry, Error> {
    control(UpcallControl::Defer)?;
    Ok(DeferredEntry(core::marker::PhantomData))
}
impl Drop for DeferredEntry {
    fn drop(&mut self) {
        control(UpcallControl::Resume).expect("balanced current-thread entry deferral");
    }
}

/// Define the adapter that makes a C dispatcher a handler for `bind` and
/// `bind_resident`.
/// `upcall_entry!(name, dispatch)` uses a no-argument dispatcher.
/// `upcall_entry!(name, dispatch, context)` passes a live `*mut Context`.
/// Context changes are restored on return, subject to kernel validation.
/// The handler runs with entries masked; it may enable nested entries after
/// setting policy.
#[macro_export]
macro_rules! upcall_entry {
    ($visibility:vis $name:ident, $dispatch:path) => {
        $visibility unsafe extern "C" fn $name(_context: *mut $crate::upcall::Context) {
            // SAFETY: the distributor calls this adapter on the thread's stack.
            unsafe { $dispatch() }
        }
    };
    ($visibility:vis $name:ident, $dispatch:path, context) => {
        $visibility unsafe extern "C" fn $name(context: *mut $crate::upcall::Context) {
            // SAFETY: as above; the context is the live frame of the entry.
            unsafe { $dispatch(context) }
        }
    };
}

/// The distributor: the one entry a thread binds in the kernel. Stack use is
/// 1904 bytes plus the handlers. It saves the interrupted state, calls the
/// resident handler and then the handler of the program (see the `entries`
/// package for the rules), and returns. IPC data and handle metadata survive.
///
/// No `#[thread_local]` anywhere on this path (the handlers included, as far as
/// they run with the resident TLS): the register holds the resident TLS there.
/// TPIDR_EL0 is switched only here, in plain assembly: Rust code could keep
/// the old thread pointer across a write to the register. The register is
/// back at the interrupted value (word 34 of the frame) after the resident
/// call, whatever the handler did with it.
#[unsafe(naked)]
unsafe extern "C" fn entry() {
    core::arch::naked_asm!(
        "sub sp, sp, #1904",
        "stp x0, x1, [sp, #0]", "stp x2, x3, [sp, #16]",
        "stp x4, x5, [sp, #32]", "stp x6, x7, [sp, #48]",
        "stp x8, x9, [sp, #64]", "stp x10, x11, [sp, #80]",
        "stp x12, x13, [sp, #96]", "stp x14, x15, [sp, #112]",
        "stp x16, x17, [sp, #128]", "stp x18, x19, [sp, #144]",
        "stp x20, x21, [sp, #160]", "stp x22, x23, [sp, #176]",
        "stp x24, x25, [sp, #192]", "stp x26, x27, [sp, #208]",
        "stp x28, x29, [sp, #224]", "str x30, [sp, #240]",
        "add x9, sp, #1904", "str x9, [sp, #248]",
        "mrs x9, nzcv", "str x9, [sp, #264]",
        "mrs x9, tpidr_el0", "str x9, [sp, #272]",
        "mrs x9, tpidrro_el0", "str x9, [sp, #280]",
        "stp q0, q1, [sp, #288]", "stp q2, q3, [sp, #320]",
        "stp q4, q5, [sp, #352]", "stp q6, q7, [sp, #384]",
        "stp q8, q9, [sp, #416]", "stp q10, q11, [sp, #448]",
        "stp q12, q13, [sp, #480]", "stp q14, q15, [sp, #512]",
        "stp q16, q17, [sp, #544]", "stp q18, q19, [sp, #576]",
        "stp q20, q21, [sp, #608]", "stp q22, q23, [sp, #640]",
        "stp q24, q25, [sp, #672]", "stp q26, q27, [sp, #704]",
        "stp q28, q29, [sp, #736]", "stp q30, q31, [sp, #768]",
        "mrs x10, fpcr", "str x10, [sp, #800]",
        "mrs x10, fpsr", "str x10, [sp, #808]",
        "add x10, sp, #816", "mov x11, #1088",
        "2:", "ldp x12, x13, [x9], #16", "stp x12, x13, [x10], #16",
        "subs x11, x11, #16", "b.ne 2b",
        "mov x0, #{take}", "svc #{control}", "cbnz x0, 9f",
        "str x2, [sp, #256]", "str x3, [sp, #264]",
        // x20: the entry record; x21: a handler; x22: the frame this entry
        // recorded in `outer`, or 0. Callee-saved, so the handlers keep them.
        "mrs x20, tpidrro_el0", "add x20, x20, #{entries}",
        "mov x22, #0",
        "ldr x21, [x20, #{resident}]", "cbz x21, 5f",
        "ldr x9, [x20, #{outer}]", "cbnz x9, 4f",
        "mov x22, sp", "str x22, [x20, #{outer}]",
        "4:",
        "ldr x9, [x20, #{tls}]", "msr tpidr_el0, x9",
        "mov x0, sp", "blr x21",
        "ldr x9, [sp, #272]", "msr tpidr_el0, x9",
        "cbz x22, 5f",
        "ldr x9, [x20, #{outer}]", "cmp x9, x22", "b.ne 5f",
        "str xzr, [x20, #{outer}]",
        "5:",
        "ldr x21, [x20, #{own}]", "cbz x21, 6f",
        "ldr x9, [x20, #{outer}]", "cbnz x9, 8f",
        "str xzr, [x20, #{owed}]",
        "mov x0, sp", "blr x21",
        "b 6f",
        // A resident call is live: the entry that made it calls the handler
        // of the program, and owes it the request this entry spent.
        "8:", "mov x9, #1", "str x9, [x20, #{owed}]",
        "6:",
        "mov x0, #{mask}", "svc #{control}", "cbnz x0, 9f",
        "mrs x9, tpidrro_el0", "add x10, sp, #816", "mov x11, #1088",
        "3:", "ldp x12, x13, [x10], #16", "stp x12, x13, [x9], #16",
        "subs x11, x11, #16", "b.ne 3b",
        "mrs x9, tpidrro_el0", "add x9, x9, #{offset}",
        "mov x10, sp", "mov x11, #{size}",
        "7:", "ldp x12, x13, [x10], #16", "stp x12, x13, [x9], #16",
        "subs x11, x11, #16", "b.ne 7b",
        "svc #{restore}",
        "9:", "brk #0",
        control = const Call::ThreadUpcallControl.number(),
        take = const UpcallControl::Take.raw(),
        mask = const UpcallControl::Mask.raw(),
        restore = const Call::ThreadUpcallReturn.number(),
        offset = const abi::UPCALL_CONTEXT_OFFSET,
        size = const abi::UPCALL_CONTEXT_SIZE,
        entries = const ENTRIES,
        own = const ENTRY_OWN,
        resident = const ENTRY_RESIDENT,
        tls = const ENTRY_TLS,
        outer = const ENTRY_OUTER,
        owed = const ENTRY_OWED,
    );
}
