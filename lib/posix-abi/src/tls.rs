// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! AArch64 thread state for the initial C ABI. The first two words are
//! reserved for an eventual ELF TLS control block. General C TLS templates
//! are not loaded yet. A scope uses a local file owner or the shared process owner.

use crate::directory::Streams;
use core::ptr;
use core::{arch::asm, cell::UnsafeCell};
use posix_fs::PosixFs;

#[repr(C, align(16))]
struct Block {
    reserved: [usize; 2],
    errno: i32,
    process_files: u32,
    files: *mut PosixFs,
    directories: *mut Streams,
    thread_id: u64,
}

const _: () = {
    assert!(core::mem::offset_of!(Block, errno) == crate::constants::STAFETO_ERRNO_OFFSET as usize);
    assert!(core::mem::size_of::<Block>() == 48);
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

struct Restore<'a> {
    previous: *mut Block,
    current: &'a UnsafeCell<Block>,
}

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        let _guard = rt::upcall::defer_entries().expect("TLS restore deferral");
        // SAFETY: the old scope is still live; defer entries until it is installed.
        unsafe { install(self.previous) };
        core::hint::black_box(self.current);
    }
}

fn scope<R>(
    files: *mut PosixFs,
    directories: *mut Streams,
    process_files: bool,
    thread_id: u64,
    run: impl FnOnce() -> R,
) -> R {
    let block = UnsafeCell::new(Block {
        reserved: [0; 2],
        errno: 0,
        process_files: u32::from(process_files),
        files,
        directories,
        thread_id,
    });
    let guard = rt::upcall::defer_entries().expect("TLS install deferral");
    let restore = Restore {
        previous: pointer(),
        current: &block,
    };
    // SAFETY: block remains at this stack address until after register restoration.
    unsafe { install(block.get()) };
    drop(guard);
    let result = run();
    drop(restore);
    result
}

fn inherited_id() -> u64 {
    let old = pointer();
    if old.is_null() {
        0
    } else {
        // SAFETY: a non-null current register belongs to a still-live scope.
        unsafe { (*old).thread_id }
    }
}

/// Run C code with a file context exclusively borrowed on the current thread.
/// The context is not inherited by other threads. Their errno can be initialized
/// with `with_errno`; `with_process` uses the initialized shared process owner.
/// Nested file and errno scopes preserve the managed thread identity.
pub fn with_files<R>(files: &mut PosixFs, run: impl FnOnce() -> R) -> R {
    let mut directories = Streams::new();
    let result = scope(files, &mut directories, false, inherited_id(), run);
    directories.close_all(files);
    result
}

/// Give the current thread its own errno without a file context.
pub fn with_errno<R>(run: impl FnOnce() -> R) -> R {
    scope(ptr::null_mut(), ptr::null_mut(), false, inherited_id(), run)
}

/// Give this thread its own errno while using the initialized process file owner.
/// Leaving this scope leaves the process's descriptors and streams live.
pub fn with_process<R>(run: impl FnOnce() -> R) -> R {
    scope(ptr::null_mut(), ptr::null_mut(), true, inherited_id(), run)
}

pub(crate) fn process_files() -> bool {
    // SAFETY: each ABI call has a live current-thread scope.
    unsafe { (*block()).process_files != 0 }
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

pub(crate) fn directories() -> *mut Streams {
    // SAFETY: the current scope uniquely owns its live directory registry.
    unsafe { (*block()).directories }
}

/// Run a managed POSIX thread with its own errno and shared process files.
pub fn with_thread<R>(id: u64, run: impl FnOnce() -> R) -> R {
    scope(ptr::null_mut(), ptr::null_mut(), true, id, || {
        crate::signals::attach().expect("managed signal entry initialization");
        run()
    })
}

pub(crate) fn thread_id() -> u64 {
    // SAFETY: pthread entry points require a live current-thread scope.
    unsafe { (*block()).thread_id }
}
