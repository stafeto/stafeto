// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The layer's side of relibc's stafeto platform (spec 2, 3.10): the C
//! functions `stafeto_*` that the module `src/platform/stafeto` of the
//! fork stafeto/relibc calls instead of Linux system calls. Each returns a
//! value or a negated errno; numbers and structures are those of Linux
//! AArch64 as relibc sees them.
//!
//! relibc builds the TCB of the main thread from `PT_TLS` and installs it
//! (`TPIDR_EL0`); the layer's block is its `os_specific`, 32 bytes on
//! (posix-thread). Its start checks `STAFETO_PLATFORM_ABI` and calls
//! `stafeto_init`, which attaches the thread. Calls before that run with
//! a TCB of the layer on the stack (posix_abi::tls).

#![no_std]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use posix_abi::constants::EINVAL;
use posix_types::Timespec;

/// The version of the interface of the functions `stafeto_*`; relibc
/// expects the same.
pub const PLATFORM_INTERFACE: u64 = 1;

/// The ABI word relibc checks at start: the size of the block in bits 0
/// to 15, its offset in the TCB in bits 16 to 31, the interface in bits 32
/// to 63.
#[unsafe(no_mangle)]
pub static STAFETO_PLATFORM_ABI: u64 = posix_thread::BLOCK_SIZE as u64
    | (posix_thread::BLOCK_OFFSET as u64) << 16
    | PLATFORM_INTERFACE << 32;

/// Runs one call of the layer with the process's files and an errno of
/// its own; a negative result becomes the negated errno.
fn call(run: impl FnOnce() -> i64) -> i64 {
    posix_abi::tls::with_process(|| {
        let value = run();
        if value < 0 {
            // SAFETY: the scope gives this thread an errno.
            -i64::from(unsafe { *posix_abi::__errno_location() })
        } else {
            value
        }
    })
}

/// Attaches the main thread, whose TCB relibc built and installed, to the
/// layer: its block, channel, timer and entry of signals.
///
/// # Safety
/// relibc's start calls it once, on the main thread, with its TCB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_init(tcb: *mut c_void) -> c_int {
    // SAFETY: the caller's promise.
    match unsafe { posix_abi::threads::attach_installed(tcb.cast(), 1) } {
        Ok(()) => 0,
        Err(errno) => -errno,
    }
}

/// # Safety
/// `buf` is readable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_write(fd: c_int, buf: *const u8, len: usize) -> isize {
    // SAFETY: the caller's promise.
    call(|| unsafe { posix_abi::write(fd, buf, len) } as i64) as isize
}

/// # Safety
/// `buf` is writable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_read(fd: c_int, buf: *mut u8, len: usize) -> isize {
    // SAFETY: the caller's promise.
    call(|| unsafe { posix_abi::read(fd, buf, len) } as i64) as isize
}

/// Linux AArch64 values relibc passes (asm-generic fcntl.h).
const AT_FDCWD: c_int = -100;
const O_ACCMODE: c_int = 0o3;
const O_DIRECTORY: c_int = 0o40000;
const O_LARGEFILE: c_int = 0o400000;
const O_CLOEXEC: c_int = 0o2000000;

/// Opens `path` relative to the current directory. The layer opens files
/// of the RAM file service for reading; other flags, and a directory
/// other than `AT_FDCWD`, answer EINVAL until the layer takes Linux's
/// numbers (later in 5a′).
///
/// # Safety
/// `path` is a live C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_openat(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    _mode: u32,
) -> c_int {
    let known = O_ACCMODE | O_DIRECTORY | O_LARGEFILE | O_CLOEXEC;
    if dirfd != AT_FDCWD || flags & !known != 0 {
        return -EINVAL;
    }
    let mut ours = flags & O_ACCMODE;
    if flags & O_DIRECTORY != 0 {
        ours |= posix_abi::constants::O_DIRECTORY;
    }
    if flags & O_CLOEXEC != 0 {
        ours |= posix_abi::constants::O_CLOEXEC;
    }
    // SAFETY: the caller's promise.
    call(|| i64::from(unsafe { posix_abi::open(path, ours) })) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_close(fd: c_int) -> c_int {
    // SAFETY: closing a number touches only the layer's table.
    call(|| i64::from(unsafe { posix_abi::close(fd) })) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    // SAFETY: seeking touches only the layer's table.
    call(|| unsafe { posix_abi::lseek(fd, offset, whence) })
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_exit(status: c_int) -> ! {
    // SAFETY: the process ends here.
    unsafe { posix_abi::_exit(status) }
}

/// # Safety
/// `out` is writable for a timespec, whose layout is Linux's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_clock_gettime(clock: c_int, out: *mut Timespec) -> c_int {
    // SAFETY: the caller's promise.
    call(|| i64::from(unsafe { posix_abi::clock::clock_gettime(clock, out) })) as c_int
}

/// # Safety
/// `out` is null or writable for a timespec.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_clock_getres(clock: c_int, out: *mut Timespec) -> c_int {
    // SAFETY: the caller's promise.
    call(|| i64::from(unsafe { posix_abi::clock::clock_getres(clock, out) })) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_getpid() -> c_int {
    posix_abi::process::getpid()
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_getppid() -> c_int {
    posix_abi::process::getppid()
}

const PAGE: usize = 4096;
/// The anonymous mappings: their addresses (0 for a free slot) and sizes.
/// The heap frees whole blocks only, so a part of a mapping is not
/// unmapped (EINVAL); dlmalloc keeps such a part. Later in 5a′ the heap
/// becomes a source of pages.
const MAPPINGS: usize = 64;
static ADDRESSES: [AtomicUsize; MAPPINGS] = [const { AtomicUsize::new(0) }; MAPPINGS];
static SIZES: [AtomicUsize; MAPPINGS] = [const { AtomicUsize::new(0) }; MAPPINGS];
/// The address of a slot `stafeto_munmap` holds: no page is at 1.
const BUSY: usize = 1;

/// Zeroed, page-aligned memory for `len` bytes from the layer's heap, or
/// null, which relibc reports as ENOMEM.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_mmap_anonymous(len: usize) -> *mut c_void {
    let Some(size) = len.checked_next_multiple_of(PAGE).filter(|&size| size != 0) else {
        return ptr::null_mut();
    };
    let mut pointer = ptr::null_mut::<u8>();
    call(|| {
        // SAFETY: the heap returns `size` writable bytes or null.
        pointer = unsafe { posix_abi::allocation::aligned_alloc(PAGE, size) };
        if pointer.is_null() {
            return -1;
        }
        // SAFETY: as above.
        unsafe { ptr::write_bytes(pointer, 0, size) };
        0
    });
    if pointer.is_null() {
        return ptr::null_mut();
    }
    for (address, length) in ADDRESSES.iter().zip(&SIZES) {
        if address
            .compare_exchange(0, pointer as usize, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            length.store(size, Ordering::Release);
            return pointer.cast();
        }
    }
    // SAFETY: the block came from aligned_alloc and nobody else has it.
    call(|| {
        unsafe { posix_abi::allocation::free(pointer) };
        0
    });
    ptr::null_mut()
}

/// Unmaps a whole mapping of `stafeto_mmap_anonymous`; EINVAL for any
/// other range.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_munmap(addr: *mut c_void, len: usize) -> c_int {
    let size = len.next_multiple_of(PAGE);
    for (address, length) in ADDRESSES.iter().zip(&SIZES) {
        // The slot is taken while its address is BUSY.
        if address
            .compare_exchange(addr as usize, BUSY, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            continue;
        }
        if length.load(Ordering::Acquire) != size {
            address.store(addr as usize, Ordering::Release);
            return -EINVAL;
        }
        length.store(0, Ordering::Relaxed);
        address.store(0, Ordering::Release);
        // SAFETY: the block came from aligned_alloc and is freed once.
        return call(|| {
            unsafe { posix_abi::allocation::free(addr.cast()) };
            0
        }) as c_int;
    }
    -EINVAL
}
