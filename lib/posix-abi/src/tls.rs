// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calling thread's block of the layer, in its TCB (posix-thread):
//! `TPIDR_EL0`, the ABI word, the TCB, the block 32 bytes on. A POSIX
//! thread gets its TCB once (`posix_thread_attach`): the main thread in a
//! page of `.bss`, another pthread in the page above its stack; the
//! register then stays as it is for the thread's life. A scope
//! (`with_files`, `with_errno`, `with_process`) on such a thread changes
//! the fields of its block for the scope and gives them back after. A
//! thread the layer did not attach (a helper of the layer or a thread of a
//! test) gets a TCB on its stack for its outermost scope, the register
//! naming it until the scope ends. General C TLS templates are not loaded
//! yet.

use crate::directory::Streams;
use core::cell::UnsafeCell;
use core::ptr;
use posix_fs::PosixFs;
use posix_thread::{Block, Page, Tcb};

struct MainPage(UnsafeCell<Page>);
// SAFETY: only the main thread uses its page, once startup attached it.
unsafe impl Sync for MainPage {}
static MAIN: MainPage = MainPage(UnsafeCell::new(Page::new()));

/// The page of the main thread's TCB.
pub fn main_page() -> *mut u8 {
    MAIN.0.get().cast()
}

/// The ABI word and a TCB on the stack of a thread the layer did not
/// attach, for its outermost scope.
#[repr(C, align(16))]
struct Transient {
    abi: [usize; 2],
    tcb: Tcb,
}

/// Gives the calling thread a TCB in `page`, `len` bytes from its ABI
/// word on, with pthread number `id`, using the process's files; the
/// register names it from now on.
///
/// # Safety
/// `page` is writable for `len` bytes (at least the word and the TCB),
/// aligned to 16, and the thread's alone for its life.
pub unsafe fn attach(page: *mut u8, len: usize, id: u64) {
    let _guard = rt::upcall::defer_entries().expect("TCB install deferral");
    // SAFETY: the caller's promise.
    let tcb = unsafe { posix_thread::build(page, len) };
    // SAFETY: `build` made the block; the thread is not attached yet.
    unsafe {
        (*tcb).block.process_files = 1;
        (*tcb).block.thread_id = id;
        posix_thread::activate(page);
    }
}

/// Gives the calling thread the TCB its creator built in `page` with
/// posix_thread::build (so that signals sent before it ran wait in its
/// block), as pthread `id` with the process's files.
///
/// # Safety
/// `page` holds a TCB `build` made, the thread's alone for its life.
pub unsafe fn attach_built(page: *mut u8, id: u64) {
    let _guard = rt::upcall::defer_entries().expect("TCB install deferral");
    // SAFETY: the caller's promise.
    unsafe {
        let tcb = page.add(posix_thread::TCB_OFFSET).cast::<Tcb>();
        (*tcb).block.process_files = 1;
        (*tcb).block.thread_id = id;
        posix_thread::activate(page);
    }
}

/// The fields of a block a scope changes.
#[derive(Clone, Copy)]
struct Fields {
    errno: i32,
    process_files: u32,
    files: *mut PosixFs,
    directories: *mut Streams,
}

/// Swaps `fields` with those of `block`.
///
/// # Safety
/// `block` is the calling thread's.
unsafe fn swap(block: *mut Block, fields: &mut Fields) {
    // SAFETY: the caller's promise; only this thread uses these fields.
    unsafe {
        let old = Fields {
            errno: (*block).errno,
            process_files: (*block).process_files,
            files: (*block).files.cast(),
            directories: (*block).directories.cast(),
        };
        (*block).errno = fields.errno;
        (*block).process_files = fields.process_files;
        (*block).files = fields.files.cast();
        (*block).directories = fields.directories.cast();
        *fields = old;
    }
}

fn scope<R>(
    files: *mut PosixFs,
    directories: *mut Streams,
    process_files: bool,
    run: impl FnOnce() -> R,
) -> R {
    let mut fields = Fields {
        errno: 0,
        process_files: u32::from(process_files),
        files,
        directories,
    };
    let block = posix_thread::block();
    if !block.is_null() {
        // The scope's errno starts at 0; the outer fields, errno among
        // them, come back when it ends. An entry waits while the four
        // fields change, so that it never sees them half changed.
        {
            let _guard = rt::upcall::defer_entries().expect("scope entry deferral");
            // SAFETY: the block is this thread's.
            unsafe { swap(block, &mut fields) };
        }
        let result = run();
        let _guard = rt::upcall::defer_entries().expect("scope entry deferral");
        // SAFETY: as above.
        unsafe { swap(block, &mut fields) };
        return result;
    }
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
            let tcb = posix_thread::build(page, core::mem::size_of::<Transient>());
            swap(&raw mut (*tcb).block, &mut fields);
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

/// Run C code with a file context exclusively borrowed on the current thread.
/// The context is not inherited by other threads. Their errno can be initialized
/// with `with_errno`; `with_process` uses the initialized shared process owner.
/// Nested scopes keep the thread's pthread number and give the outer errno back.
pub fn with_files<R>(files: &mut PosixFs, run: impl FnOnce() -> R) -> R {
    let mut directories = Streams::new();
    let result = scope(files, &mut directories, false, run);
    directories.close_all(files);
    result
}

/// Give the current thread an errno without a file context; a nested scope
/// gives the outer value back when it ends.
pub fn with_errno<R>(run: impl FnOnce() -> R) -> R {
    scope(ptr::null_mut(), ptr::null_mut(), false, run)
}

/// Give this thread an errno while using the initialized process file owner.
/// Leaving this scope leaves the process's descriptors and streams live.
pub fn with_process<R>(run: impl FnOnce() -> R) -> R {
    scope(ptr::null_mut(), ptr::null_mut(), true, run)
}

fn block() -> *mut Block {
    let block = posix_thread::block();
    assert!(
        !block.is_null(),
        "C ABI called without thread initialization"
    );
    block
}

pub(crate) fn process_files() -> bool {
    // SAFETY: each ABI call runs on a thread with a block.
    unsafe { (*block()).process_files != 0 }
}

pub(crate) fn errno() -> *mut i32 {
    // SAFETY: ABI entry points run on a thread with a block.
    unsafe { ptr::addr_of_mut!((*block()).errno) }
}

pub(crate) fn files() -> *mut PosixFs {
    // SAFETY: a scope holds the unique file-context borrow on this thread.
    unsafe { (*block()).files.cast() }
}

pub(crate) fn directories() -> *mut Streams {
    // SAFETY: the current scope uniquely owns its live directory registry.
    unsafe { (*block()).directories.cast() }
}

pub(crate) fn thread_id() -> u64 {
    // SAFETY: pthread entry points run on a thread with a block.
    unsafe { (*block()).thread_id }
}
