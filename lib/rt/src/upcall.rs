// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Generic current-thread entries. Signal policy belongs to a higher-level library.
use crate::sys;
use abi::{Call, Error, UpcallControl};

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
/// Register one entry on the current thread, initially masked.
/// # Safety
/// entry must use upcall_entry! or an equivalent context-preserving trampoline.
/// Its dispatcher must be safe at every point where delivery is enabled, including
/// reentry into interrupted Rust code. The caller owns the handler's full lifetime.
pub unsafe fn bind(entry: unsafe extern "C" fn()) -> Result<(), Error> {
    // SAFETY: the caller answers for future asynchronous entries at this address.
    let result = unsafe {
        sys::raw::<{ Call::ThreadUpcallBind.number() }>([
            entry as usize as u64,
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
    Error::from_code(result[0]).map_or(Ok(()), Err)
}
/// Stop entries until enable; returns whether they were already masked.
pub fn mask() -> Result<bool, Error> {
    control(UpcallControl::Mask)
}
/// Allow entries, including immediately pending requests.
/// # Safety
/// The bound dispatcher may run before this call returns; all interrupted code
/// and live resources must permit this asynchronous reentry.
pub unsafe fn enable() -> Result<bool, Error> {
    control(UpcallControl::Enable)
}
/// Remove the entry after all handlers have returned.
pub fn unbind() -> Result<(), Error> {
    // SAFETY: removing an inactive entry starts no user code.
    let result = unsafe { sys::raw::<{ Call::ThreadUpcallBind.number() }>([0; 10]) };
    Error::from_code(result[0]).map_or(Ok(()), Err)
}

/// Defer handler execution while keeping enabled IPC waits interruptible.
/// Drop releases one nesting level; it can immediately enter a pending handler.
/// The guard must outlive all exclusive borrows it protects and remain on its
/// creating thread. It neither changes nor restores the application's mask.
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

/// Define a complete native entry around a C dispatcher.
/// `upcall_entry!(name, dispatch)` uses a no-argument dispatcher.
/// `upcall_entry!(name, dispatch, context)` passes a live `*mut Context`.
/// Context changes are restored on return, subject to kernel validation.
/// It starts masked; the dispatcher may enable nested entries after setting policy.
/// Stack use is 1904 bytes plus the dispatcher. IPC data and handle metadata survive.
#[macro_export]
macro_rules! upcall_entry {
    ($visibility:vis $name:ident, $dispatch:path) => {
        $crate::upcall_entry!(@frame $visibility $name, $dispatch, "");
    };
    ($visibility:vis $name:ident, $dispatch:path, context) => {
        $crate::upcall_entry!(@frame $visibility $name, $dispatch, "mov x0, sp");
    };
    (@frame $visibility:vis $name:ident, $dispatch:path, $argument:literal) => {
        #[unsafe(naked)]
        $visibility unsafe extern "C" fn $name() {
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
                $argument, "bl {dispatch}",
                "mov x0, #{mask}", "svc #{control}", "cbnz x0, 9f",
                "mrs x9, tpidrro_el0", "add x10, sp, #816", "mov x11, #1088",
                "3:", "ldp x12, x13, [x10], #16", "stp x12, x13, [x9], #16",
                "subs x11, x11, #16", "b.ne 3b",
                "mrs x9, tpidrro_el0", "add x9, x9, #{offset}",
                "mov x10, sp", "mov x11, #{size}",
                "4:", "ldp x12, x13, [x10], #16", "stp x12, x13, [x9], #16",
                "subs x11, x11, #16", "b.ne 4b",
                "svc #{restore}",
                "9:", "brk #0",
                dispatch = sym $dispatch,
                control = const $crate::abi::Call::ThreadUpcallControl.number(),
                take = const $crate::abi::UpcallControl::Take.raw(),
                mask = const $crate::abi::UpcallControl::Mask.raw(),
                restore = const $crate::abi::Call::ThreadUpcallReturn.number(),
                offset = const $crate::abi::UPCALL_CONTEXT_OFFSET,
                size = const $crate::abi::UPCALL_CONTEXT_SIZE,
            );
        }
    };
}
