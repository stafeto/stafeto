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

mod files;
mod signals;

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::AtomicU32;
use posix_abi::constants::{EINVAL, ENOMEM};
use posix_types::Timespec;

/// The version of the interface of the functions `stafeto_*`; relibc
/// expects the same.
pub const PLATFORM_INTERFACE: u64 = 4;

/// The ABI word relibc checks at start: the size of the block in bits 0
/// to 15, its offset in the TCB in bits 16 to 31, the interface in bits 32
/// to 63.
#[unsafe(no_mangle)]
pub static STAFETO_PLATFORM_ABI: u64 = posix_thread::BLOCK_SIZE as u64
    | (posix_thread::BLOCK_OFFSET as u64) << 16
    | PLATFORM_INTERFACE << 32;

/// Runs one call of the layer with the process's files and an errno of
/// its own; a negative result becomes the negated errno. A thread the
/// layer attached already uses the process's files: its errno is saved and
/// given back around the call, with no call of the kernel. Before that
/// (relibc's start) the call runs in a scope of the layer (posix_abi::tls).
fn call(run: impl FnOnce() -> i64) -> i64 {
    // SAFETY: a block lives while its thread runs.
    if let Some(block) = unsafe { posix_thread::block().as_mut() }
        && block.process_files != 0
    {
        let saved = core::mem::replace(&mut block.errno, 0);
        let value = run();
        // The block is the calling thread's: no entry changes its errno
        // across the call without giving it back.
        let errno = core::mem::replace(&mut block.errno, saved);
        return if value < 0 { -i64::from(errno) } else { value };
    }
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
    posix_abi::relibc::configure(unmap);
    // SAFETY: the caller's promise.
    match unsafe { posix_abi::threads::attach_installed(tcb.cast(), 1) } {
        Ok(()) => {
            // SAFETY: the main thread's block lies 32 bytes into its TCB.
            unsafe {
                posix_abi::relibc::attach_main(
                    tcb.cast::<u8>().add(posix_thread::BLOCK_OFFSET).cast(),
                )
            };
            0
        }
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

/// relibc's open flags (its headers for AArch64 Linux, asm/fcntl.h).
const AT_FDCWD: c_int = -100;
const O_ACCMODE: c_int = 0o3;
const O_NOCTTY: c_int = 0o400;
const O_DIRECTORY: c_int = 0o40000;
const O_NOFOLLOW: c_int = 0o100000;
const O_LARGEFILE: c_int = 0o400000;
const O_CLOEXEC: c_int = 0o2000000;

/// Opens `path`, relative to the current directory or absolute (any
/// `dirfd` then). The layer opens files of the RAM file service: the
/// access mode, O_DIRECTORY and O_CLOEXEC; O_NOCTTY, O_NOFOLLOW (no
/// symbolic links yet) and O_LARGEFILE change nothing; other flags, and a
/// relative path from a directory other than `AT_FDCWD`, answer EINVAL.
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
    let known = O_ACCMODE | O_NOCTTY | O_DIRECTORY | O_NOFOLLOW | O_LARGEFILE | O_CLOEXEC;
    // SAFETY: the caller's promise.
    let absolute = !path.is_null() && unsafe { *path } == b'/' as c_char;
    if (dirfd != AT_FDCWD && !absolute) || flags & !known != 0 {
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

/// CLOCK_MONOTONIC from the counter, CLOCK_REALTIME from the clock
/// service's page: no call of the kernel.
///
/// # Safety
/// `out` is writable for a timespec, whose layout is Linux's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_clock_gettime(clock: c_int, out: *mut Timespec) -> c_int {
    match posix_abi::clock::gettime(clock) {
        Ok(time) => {
            // SAFETY: the caller's promise.
            unsafe {
                out.write(Timespec {
                    tv_sec: time.seconds,
                    tv_nsec: time.nanos,
                })
            };
            0
        }
        Err(errno) => -errno,
    }
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

/// The anonymous mappings relibc holds: (first page, pages) of each, in
/// pages of the address space (32 bits each reach 16 TiB), 0 pages for a
/// free record. The pages come from the layer's heap (no header), so
/// munmap gives back the whole mapping, pages from either edge, or pages
/// from the middle, which splits the record in two.
const MAPPINGS: usize = 256;
type Records = [(u32, u32); MAPPINGS];
struct Mappings(UnsafeCell<Records>);
// SAFETY: only `mappings` borrows the records, under MAPPINGS_LOCK.
unsafe impl Sync for Mappings {}
static MAPS: Mappings = Mappings(UnsafeCell::new([(0, 0); MAPPINGS]));
static MAPPINGS_LOCK: posix_sync::LayerLock = posix_sync::LayerLock::new();

/// A record of the bytes from `start` to `end`, both page-aligned.
fn record(start: usize, end: usize) -> (u32, u32) {
    ((start / PAGE) as u32, ((end - start) / PAGE) as u32)
}

/// The bytes a record holds: its start and end.
fn bounds((page, pages): (u32, u32)) -> (usize, usize) {
    let start = page as usize * PAGE;
    (start, start + pages as usize * PAGE)
}

fn mappings<R>(f: impl FnOnce(&mut Records) -> R) -> R {
    let _guard = MAPPINGS_LOCK.lock();
    // SAFETY: the lock gives this borrow alone.
    f(unsafe { &mut *MAPS.0.get() })
}

/// Zeroed, page-aligned memory for `len` bytes from the layer's heap, or
/// null, which relibc reports as ENOMEM.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_mmap_anonymous(len: usize) -> *mut c_void {
    let Some(size) = len.checked_next_multiple_of(PAGE).filter(|&size| size != 0) else {
        return ptr::null_mut();
    };
    let Ok(pointer) = posix_abi::allocation::map_pages(size) else {
        return ptr::null_mut();
    };
    let start = pointer.as_ptr() as usize;
    let recorded = mappings(|maps| {
        maps.iter_mut()
            .find(|free| free.1 == 0)
            .map(|free| *free = record(start, start + size))
            .is_some()
    });
    if !recorded {
        // SAFETY: the pages are this call's, and nobody saw them.
        unsafe { posix_abi::allocation::unmap_pages(pointer, size) };
        return ptr::null_mut();
    }
    pointer.as_ptr().cast()
}

/// Unmaps whole pages of a mapping of `stafeto_mmap_anonymous`: all of it,
/// pages from an edge, or pages from the middle. EINVAL for a range that
/// is not inside one mapping, ENOMEM when a split finds no free record.
#[unsafe(no_mangle)]
pub extern "C" fn stafeto_munmap(addr: *mut c_void, len: usize) -> c_int {
    let start = addr as usize;
    let Some(size) = len.checked_next_multiple_of(PAGE).filter(|&size| size != 0) else {
        return -EINVAL;
    };
    let Some(end) = start
        .checked_add(size)
        .filter(|_| start.is_multiple_of(PAGE))
    else {
        return -EINVAL;
    };
    let result: Result<(), c_int> = mappings(|maps| {
        let index = maps
            .iter()
            .position(|&held| {
                let (first, last) = bounds(held);
                held.1 != 0 && first <= start && end <= last
            })
            .ok_or(EINVAL)?;
        let (first, last) = bounds(maps[index]);
        match (start == first, end == last) {
            (true, true) => maps[index] = (0, 0),
            (true, false) => maps[index] = record(end, last),
            (false, true) => maps[index] = record(first, start),
            (false, false) => {
                let free = maps.iter().position(|free| free.1 == 0).ok_or(ENOMEM)?;
                maps[index] = record(first, start);
                maps[free] = record(end, last);
            }
        }
        Ok(())
    });
    match result {
        Ok(()) => {
            // SAFETY: the pages left the records: relibc gave them up.
            unsafe {
                posix_abi::allocation::unmap_pages(
                    core::ptr::NonNull::new_unchecked(addr.cast()),
                    size,
                )
            };
            0
        }
        Err(errno) => -errno,
    }
}

/// Takes back one of relibc's mappings for the thread table.
fn unmap(address: usize, length: usize) {
    let _ = stafeto_munmap(address as *mut c_void, length);
}

/// A new thread's first instructions: the stack holds what relibc pushed
/// for its clone (the shim, then its arguments, 64 bytes); the shim never
/// returns.
#[unsafe(naked)]
extern "C" fn thread_entry(_id: u64) -> ! {
    core::arch::naked_asm!(
        "ldp x8, x0, [sp], #16",
        "ldp x1, x2, [sp], #16",
        "ldp x3, x4, [sp], #16",
        "ldr x5, [sp], #16",
        "mov x29, xzr",
        "mov x30, xzr",
        "br x8",
    )
}

/// # Safety
/// `stack` is the new thread's, prepared by relibc; `block` is the block of
/// the TCB relibc made for it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_thread_create(stack: *mut usize, block: *mut c_void) -> c_int {
    // SAFETY: the caller's promise.
    match unsafe { posix_abi::relibc::create(thread_entry, stack as usize, block.cast()) } {
        Ok(id) => id as c_int,
        Err(errno) => -errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_thread_id() -> c_int {
    posix_abi::relibc::current() as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_thread_started() -> c_int {
    match posix_abi::relibc::started() {
        Ok(()) => 0,
        Err(errno) => -errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_thread_leaving() {
    posix_abi::relibc::leaving();
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_thread_release(id: c_int) {
    posix_abi::relibc::release(id as u64);
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_exit_thread(stack: *mut c_void, size: usize) -> ! {
    posix_abi::relibc::exit_thread(stack as usize, size)
}

/// # Safety
/// `addr` is a live aligned word of the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_futex_wait(addr: *mut u32, val: u32, deadline: u64) -> c_int {
    // SAFETY: the caller's promise.
    let word = unsafe { &*addr.cast::<AtomicU32>() };
    let deadline = (deadline != u64::MAX).then_some(deadline);
    match posix_sync::futex_wait(word, val, posix_sync::CLOCK_MONOTONIC, deadline) {
        Ok(_) => 0,
        Err(errno) => -errno,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_futex_wake(addr: *mut u32, count: u32) -> u32 {
    posix_sync::futex_wake(addr.cast::<AtomicU32>(), count)
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_sched_yield() -> c_int {
    let _ = rt::sys::yield_now();
    0
}

/// # Safety
/// `request` is a readable timespec; `remaining` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_nanosleep(
    request: *const Timespec,
    remaining: *mut Timespec,
) -> c_int {
    // SAFETY: the caller's promise; the layouts are Linux's.
    call(|| i64::from(unsafe { posix_abi::threads::sleep::nanosleep(request, remaining) })) as c_int
}

/// clock_nanosleep: 0 or an error number.
///
/// # Safety
/// `request` is a readable timespec; `remaining` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_clock_nanosleep(
    clock: c_int,
    flags: c_int,
    request: *const Timespec,
    remaining: *mut Timespec,
) -> c_int {
    // SAFETY: the caller's promise; the clocks and TIMER_ABSTIME are
    // Linux's numbers in both.
    unsafe { posix_abi::threads::sleep::clock_nanosleep(clock, flags, request, remaining) }
}

/// relibc's cancellation states and types (its pthread.h).
const PTHREAD_CANCEL_ASYNCHRONOUS: c_int = 0;
const PTHREAD_CANCEL_ENABLE: c_int = 1;
const PTHREAD_CANCEL_DEFERRED: c_int = 2;
const PTHREAD_CANCEL_DISABLE: c_int = 3;

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_cancel(id: c_int) -> c_int {
    -posix_abi::relibc::cancel(id as u64)
}

#[unsafe(no_mangle)]
pub extern "C" fn stafeto_testcancel() -> c_int {
    c_int::from(posix_abi::relibc::testcancel())
}

/// # Safety
/// `old` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_setcancelstate(state: c_int, old: *mut c_int) -> c_int {
    let enabled = match state {
        PTHREAD_CANCEL_ENABLE => true,
        PTHREAD_CANCEL_DISABLE => false,
        _ => return -EINVAL,
    };
    match posix_abi::relibc::set_cancel_enabled(enabled) {
        Ok(was) => {
            let value = if was {
                PTHREAD_CANCEL_ENABLE
            } else {
                PTHREAD_CANCEL_DISABLE
            };
            // SAFETY: the caller's promise.
            unsafe { old.write(value) };
            0
        }
        Err(errno) => -errno,
    }
}

/// # Safety
/// `old` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_setcanceltype(kind: c_int, old: *mut c_int) -> c_int {
    let asynchronous = match kind {
        PTHREAD_CANCEL_ASYNCHRONOUS => true,
        PTHREAD_CANCEL_DEFERRED => false,
        _ => return -EINVAL,
    };
    let was = posix_abi::relibc::set_cancel_asynchronous(asynchronous);
    let value = if was {
        PTHREAD_CANCEL_ASYNCHRONOUS
    } else {
        PTHREAD_CANCEL_DEFERRED
    };
    // SAFETY: the caller's promise.
    unsafe { old.write(value) };
    0
}
