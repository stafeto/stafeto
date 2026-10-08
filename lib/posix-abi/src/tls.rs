// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calling thread's block of the layer, in its TCB (posix-thread):
//! `TPIDR_EL0`, the ABI word, the TCB, the block 32 bytes on. relibc
//! builds a thread's TCB; the layer attaches the thread to its block once
//! (`attach_installed` for the main thread, crate::relibc for the others),
//! and the register stays as it is for the thread's life. A thread the
//! layer did not attach (a call of the platform before relibc attached
//! the main thread, or a native thread of a test) gets a TCB on its stack
//! for its outermost `with_process` scope, the register naming it until
//! the scope ends; a nested scope keeps the thread's block.

use core::ptr;
use posix_thread::{Block, Tcb};

/// The ABI word and a TCB on the stack of a thread the layer did not
/// attach, for its outermost scope.
#[repr(C, align(16))]
struct Transient {
    abi: [usize; 2],
    tcb: Tcb,
}

/// Makes the calling thread thread `id` in the block of `tcb`, the TCB the
/// register already names (relibc's).
///
/// # Safety
/// `tcb` is the calling thread's installed TCB for its life.
pub unsafe fn attach_installed(tcb: *mut Tcb, id: u64) {
    let _guard = rt::upcall::defer_entries().expect("TCB install deferral");
    // SAFETY: the caller's promise.
    unsafe { (*tcb).block.thread_id = id };
}

/// A long jump out of a handler of the layer does not cross the boundary of
/// this scope: the `sigsetjmp` it jumps to lies inside the same scope, since
/// the jump skips the end of the scope and leaves the resident TLS in place.
///
/// Runs `run` with a block of the layer: the thread's own, or a transient
/// one on this stack for a thread that has none, which goes when `run`
/// returns.
pub fn with_process<R>(run: impl FnOnce() -> R) -> R {
    if let Some(block) = unsafe { posix_thread::block().as_ref() } {
        if crate::relibc::native::is_resident(block) {
            let deferred = rt::upcall::defer_entries().expect("native scope entry deferral");
            let before = block.scope.load(core::sync::atomic::Ordering::Acquire)
                & posix_thread::scope::DEPTH_MASK;
            let _ = crate::signals::native_scope_barrier(block);
            drop(deferred);
            let result = run();
            let _deferred = rt::upcall::defer_entries().expect("native scope exit deferral");
            if before != posix_thread::scope::DEPTH_MASK {
                crate::relibc::native::end_scope(block);
            }
            return result;
        }
        return run();
    }
    let admission = crate::relibc::native::enter();
    if let Ok(page) = admission {
        let deferred = rt::upcall::defer_entries().expect("native TLS install deferral");
        // SAFETY: genuine CURRENT/admission proves this resident page belongs to this Thread.
        unsafe { posix_thread::activate(page) };
        let block = unsafe { &*posix_thread::block() };
        let _ = crate::signals::native_scope_barrier(block);
        drop(deferred);
        let result = run();
        let _deferred = rt::upcall::defer_entries().expect("native scope exit deferral");
        crate::relibc::native::end_scope(block);
        return result;
    }
    let error = admission.unwrap_err();
    let mut transient = Transient {
        abi: [0; 2],
        tcb: Tcb {
            generic: posix_thread::GenericTcb {
                tls_end: ptr::null_mut(),
                tls_len: 0,
                tcb_ptr: ptr::null_mut(),
                tcb_len: 0,
            },
            block: Block::new(),
        },
    };
    let page = (&raw mut transient).cast::<u8>();
    {
        let _guard = rt::upcall::defer_entries().expect("TCB install deferral");
        // SAFETY: the transient TCB lives on this stack until the register
        // goes back to 0 below.
        unsafe {
            posix_thread::build(page, core::mem::size_of::<Transient>());
            crate::relibc::native::fallback(&transient.tcb.block, error);
            posix_thread::activate(page);
        }
    }
    let result = run();
    let _guard = rt::upcall::defer_entries().expect("TCB restore deferral");
    // SAFETY: the thread had no TCB before this scope.
    unsafe { posix_thread::activate(ptr::null_mut()) };
    core::hint::black_box(&transient);
    result
}
