// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The thread control block (TCB) of a POSIX thread in relibc's layout
//! (spec 2, 3.5), and the block of the POSIX layer in it.
//!
//! `TPIDR_EL0` holds the address of a word, and the word the address of
//! the TCB: relibc's ABI word on AArch64, 16 bytes before the static TLS,
//! whose end the TCB starts at (relibc `Tcb::os_new`, `os_arch_activate`).
//! The TCB starts with relibc's `GenericTcb` (`tls_end`, `tls_len`,
//! `tcb_ptr`, `tcb_len`, 32 bytes), and its `os_specific` is the layer's
//! `Block`, 192 bytes aligned to 16, which relibc sees as `[u64; 24]`.
//! The layer finds its block with two loads and an add, and never writes
//! the register around its calls.
//!
//! Until relibc builds the TCB (5a′), the layer builds it in a page of its
//! own (`Page`): the ABI word at its start, the TCB 16 bytes on, the TLS
//! empty between them, as relibc's layout gives with a TLS of 0 bytes.
//! The main thread's page is in `.bss`, another thread's above its stack.

#![no_std]

use core::arch::asm;
use core::ffi::c_void;
use core::mem::{offset_of, size_of};
use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize};

/// relibc's `GenericTcb` without its `os_specific` (relibc generic-rt).
#[repr(C)]
pub struct GenericTcb {
    /// The end of the static TLS, where the TCB starts.
    pub tls_end: *mut u8,
    /// The bytes of the static TLS: none before relibc.
    pub tls_len: usize,
    /// This TCB.
    pub tcb_ptr: *mut Tcb,
    /// The bytes given to the TCB: its page.
    pub tcb_len: usize,
}

/// Bits of `Block::flags`; the depth of the thread's critical sections
/// (posix-sync) takes the bits from DEPTH_SHIFT up.
pub mod flag {
    /// The thread waits in sigwait for the signals of `Block::wait_set`.
    pub const SIGNAL_WAIT: u32 = 1 << 0;
    /// The thread holds the lock of a bucket (one at most).
    pub const BUCKET: u32 = 1 << 1;
    /// An entry came inside a critical section and waits for its end.
    pub const ENTRY_DEFERRED: u32 = 1 << 2;
    /// Cancellation was asked for.
    pub const CANCEL_PENDING: u32 = 1 << 3;
    /// Cancellation is disabled.
    pub const CANCEL_DISABLED: u32 = 1 << 4;
    /// The type of cancellation is asynchronous.
    pub const CANCEL_ASYNCHRONOUS: u32 = 1 << 5;
    /// The thread runs its cleanup and destructors on its way out.
    pub const EXITING: u32 = 1 << 6;
    /// The entry of signals is bound and enabled.
    pub const SIGNALS_READY: u32 = 1 << 7;
    /// The depth of the critical sections: a section adds DEPTH_ONE.
    pub const DEPTH_SHIFT: u32 = 16;
    pub const DEPTH_ONE: u32 = 1 << DEPTH_SHIFT;
}

/// The block of the POSIX layer for one thread: relibc's `os_specific`.
/// The fields before `errno` are the thread's state of the transport of
/// 5a (its signals, cancellation, its channel and timer, its node in the
/// table of waits by address, its end); from `errno` on they leave for
/// relibc in 5a′.
#[repr(C, align(16))]
pub struct Block {
    /// The thread's signal mask and its pending signals.
    pub mask: AtomicU64,
    pub pending: AtomicU64,
    /// The signals sigwait takes while `flag::SIGNAL_WAIT` is set.
    pub wait_set: AtomicU64,
    /// `flag` bits.
    pub flags: AtomicU32,
    /// The thread's own base level.
    pub base_level: AtomicU32,
    /// Handles: the thread with MANAGE, its channel, its timer, and a copy
    /// of its channel with label 0 and NOTIFY for those who wake it.
    pub thread: AtomicU64,
    pub channel: AtomicU64,
    pub timer: AtomicU64,
    pub waker: AtomicU64,
    /// The node of a wait by address: its neighbours in its bucket, the
    /// address it waits on and the level it waits at.
    pub previous: AtomicUsize,
    pub next: AtomicUsize,
    pub address: AtomicUsize,
    pub level: AtomicU32,
    /// Nonzero once the thread ended; `result` is its value.
    pub end: AtomicU32,
    pub result: AtomicUsize,
    /// The thread's errno.
    pub errno: i32,
    /// Nonzero when the calls of the thread use the process's file owner.
    pub process_files: u32,
    /// The file context and directory streams of a thread with its own
    /// files (the file owner and tests); null with the process's.
    pub files: *mut c_void,
    pub directories: *mut c_void,
    /// The pthread number of the thread; 0 for a thread pthread does not
    /// know.
    pub thread_id: u64,
    reserved: [u64; 7],
}

/// The TCB: relibc's `Tcb` starts so, its `os_specific` the block.
#[repr(C)]
pub struct Tcb {
    pub generic: GenericTcb,
    pub block: Block,
}

/// The offset of the block in the TCB and its size: relibc's
/// `OsSpecific` must have this size (5a′ checks it).
pub const BLOCK_OFFSET: usize = 32;
pub const BLOCK_SIZE: usize = 192;
/// The offset of the TCB in a `Page`: the ABI word and its padding.
pub const TCB_OFFSET: usize = 16;
pub const PAGE_SIZE: usize = 4096;

const _: () = {
    assert!(size_of::<GenericTcb>() == BLOCK_OFFSET);
    assert!(offset_of!(Tcb, block) == BLOCK_OFFSET);
    assert!(size_of::<Block>() == BLOCK_SIZE);
    assert!(core::mem::align_of::<Block>() == 16);
    assert!(offset_of!(Block, flags) == 24);
    assert!(offset_of!(Block, thread) == 32);
    assert!(offset_of!(Block, previous) == 64);
    assert!(offset_of!(Block, end) == 92);
    assert!(offset_of!(Block, result) == 96);
    assert!(offset_of!(Block, errno) == 104);
    assert!(offset_of!(Block, files) == 112);
    assert!(offset_of!(Block, thread_id) == 128);
    assert!(offset_of!(Page, tcb) == TCB_OFFSET);
    assert!(size_of::<Page>() == PAGE_SIZE);
};

/// The page the layer builds a TCB in before relibc: the ABI word, the TCB
/// after it (the TLS between them is empty). relibc puts the word at the
/// end of a page of its own and starts the TCB on the next page, with
/// `tcb_len` the size of the page; here the TCB is 16 bytes into the page
/// and `tcb_len` is the rest of it. Nothing reads these until relibc builds
/// its own TCB (5a').
#[repr(C, align(4096))]
pub struct Page {
    abi: [usize; 2],
    tcb: Tcb,
    rest: [u8; PAGE_SIZE - TCB_OFFSET - size_of::<Tcb>()],
}

impl Page {
    /// A page of zeros, for a static.
    pub const fn new() -> Self {
        Page {
            abi: [0; 2],
            tcb: Tcb {
                generic: GenericTcb {
                    tls_end: ptr::null_mut(),
                    tls_len: 0,
                    tcb_ptr: ptr::null_mut(),
                    tcb_len: 0,
                },
                block: Block::new(),
            },
            rest: [0; PAGE_SIZE - TCB_OFFSET - size_of::<Tcb>()],
        }
    }
}

impl Default for Page {
    fn default() -> Self {
        Self::new()
    }
}

impl Block {
    pub const fn new() -> Self {
        Block {
            mask: AtomicU64::new(0),
            pending: AtomicU64::new(0),
            wait_set: AtomicU64::new(0),
            flags: AtomicU32::new(0),
            base_level: AtomicU32::new(0),
            thread: AtomicU64::new(0),
            channel: AtomicU64::new(0),
            timer: AtomicU64::new(0),
            waker: AtomicU64::new(0),
            previous: AtomicUsize::new(0),
            next: AtomicUsize::new(0),
            address: AtomicUsize::new(0),
            level: AtomicU32::new(0),
            end: AtomicU32::new(0),
            result: AtomicUsize::new(0),
            errno: 0,
            process_files: 0,
            files: ptr::null_mut(),
            directories: ptr::null_mut(),
            thread_id: 0,
            reserved: [0; 7],
        }
    }
}

impl Default for Block {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a TCB with an empty block in `page`, `len` bytes from the ABI
/// word on, which `activate` installs; returns the TCB.
///
/// # Safety
/// `page` is aligned to 16, writable for `TCB_OFFSET + size_of::<Tcb>()`
/// bytes, and nothing else uses them while a thread runs on the TCB.
pub unsafe fn build(page: *mut u8, len: usize) -> *mut Tcb {
    // SAFETY: the caller's promise covers the word and the TCB.
    unsafe {
        let tcb = page.add(TCB_OFFSET).cast::<Tcb>();
        tcb.write(Tcb {
            generic: GenericTcb {
                // The TLS is empty: it ends where the TCB starts.
                tls_end: tcb.cast(),
                tls_len: 0,
                tcb_ptr: tcb,
                tcb_len: len - TCB_OFFSET,
            },
            block: Block::new(),
        });
        // relibc's ABI word: the end of the TLS, which is the TCB.
        page.cast::<*mut Tcb>().write(tcb);
        tcb
    }
}

/// `TPIDR_EL0` of the calling thread: the address of its ABI word, or 0.
pub fn thread_pointer() -> usize {
    let pointer: usize;
    // SAFETY: reading the thread's own register changes no memory.
    unsafe {
        asm!("mrs {}, tpidr_el0", out(reg) pointer, options(nomem, nostack, preserves_flags))
    };
    pointer
}

/// The register names the ABI word of `page` from now on (0: none).
///
/// # Safety
/// `page` is 0, or holds a TCB `build` made that lives while the register
/// names it.
pub unsafe fn activate(page: *mut u8) {
    // SAFETY: the caller's promise.
    unsafe { asm!("msr tpidr_el0, {}", in(reg) page, options(nostack, preserves_flags)) };
}

/// The calling thread's TCB through the register and the ABI word; null
/// for a thread without one.
pub fn tcb() -> *mut Tcb {
    let word = thread_pointer();
    if word == 0 {
        return ptr::null_mut();
    }
    // SAFETY: a register that is not 0 names a live ABI word (`activate`).
    unsafe { *(word as *const *mut Tcb) }
}

/// The calling thread's block: its TCB plus BLOCK_OFFSET; null for a
/// thread without a TCB.
pub fn block() -> *mut Block {
    let tcb = tcb();
    if tcb.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the block lies inside the TCB.
    unsafe { tcb.cast::<u8>().add(BLOCK_OFFSET).cast() }
}
