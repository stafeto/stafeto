// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! AArch64 thread state for the initial C ABI. The first two words are
//! reserved for an eventual ELF TLS control block. General C TLS templates
//! are not loaded yet. Each scope exclusively borrows its file context.

use core::arch::asm;
use core::ptr;
use posix_fs::PosixFs;

#[repr(C, align(16))]
struct Block {
    reserved: [usize; 2],
    errno: i32,
    files: *mut PosixFs,
}

const _: () = {
    assert!(core::mem::offset_of!(Block, errno) == crate::constants::STAFETO_ERRNO_OFFSET as usize);
    assert!(core::mem::size_of::<Block>() == 32);
};

fn pointer() -> *mut Block {
    let pointer: *mut Block;
    // SAFETY: reading this thread's writable TLS register changes no memory.
    unsafe {
        asm!("mrs {}, tpidr_el0", out(reg) pointer, options(nomem, nostack, preserves_flags))
    };
    pointer
}

unsafe fn install(pointer: *mut Block) {
    // SAFETY: the caller keeps the block live and exclusively owned by this thread.
    unsafe { asm!("msr tpidr_el0, {}", in(reg) pointer, options(nostack, preserves_flags)) };
}

struct Restore(*mut Block);

impl Drop for Restore {
    fn drop(&mut self) {
        // SAFETY: restore the register's exact previous value before the block dies.
        unsafe { install(self.0) };
    }
}

fn scope<R>(files: *mut PosixFs, run: impl FnOnce() -> R) -> R {
    let mut block = Block {
        reserved: [0; 2],
        errno: 0,
        files,
    };
    let restore = Restore(pointer());
    // SAFETY: block remains at this stack address until after register restoration.
    unsafe { install(&mut block) };
    let result = run();
    drop(restore);
    result
}

/// Run C code with a file context exclusively borrowed on the current thread.
/// The context is not inherited by other threads. Their errno can be initialized
/// with `with_errno`; sharing process descriptors needs the POSIX service.
pub fn with_files<R>(files: &mut PosixFs, run: impl FnOnce() -> R) -> R {
    scope(files, run)
}

/// Give the current thread its own errno without a file context.
pub fn with_errno<R>(run: impl FnOnce() -> R) -> R {
    scope(ptr::null_mut(), run)
}

fn block() -> *mut Block {
    let block = pointer();
    assert!(
        !block.is_null(),
        "C ABI called without thread initialization"
    );
    block
}

pub(crate) fn errno() -> *mut i32 {
    // SAFETY: ABI entry points are called in a live scope on this thread.
    unsafe { ptr::addr_of_mut!((*block()).errno) }
}

pub(crate) fn files() -> *mut PosixFs {
    // SAFETY: a scope holds the unique file-context borrow on this thread.
    unsafe { (*block()).files }
}
