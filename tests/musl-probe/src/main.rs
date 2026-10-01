// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Probe: a C program on musl whose `__syscall` goes to one function,
//! `__stafeto_syscall`, that switches on Linux system call numbers and calls
//! the Rust POSIX layer. Startup as in the relibc probe: the layer starts,
//! then musl's `__libc_start_main` runs on a Linux-style argv/envp/auxv.
//! Unknown numbers are printed once and fail with ENOSYS.

#![no_std]
#![no_main]

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use posix_abi::constants::{EINVAL, ENOSYS};
use posix_fs::PosixFs;
use posix_types::Timespec;
use rt::handle::Resource;

type Main = unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) -> c_int;

unsafe extern "C" {
    fn main(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) -> c_int;
    fn __libc_start_main(
        main: Main,
        argc: c_int,
        argv: *mut *mut c_char,
        init: usize,
        fini: usize,
        ldso: usize,
    ) -> c_int;
    static __ehdr_start: [u8; 64];
}

/// The layer's thread block, saved before musl installs its thread pointer.
static LAYER_TP: AtomicUsize = AtomicUsize::new(0);

fn tp() -> usize {
    let value: usize;
    // SAFETY: reading this thread's TLS register changes no memory.
    unsafe { asm!("mrs {}, tpidr_el0", out(reg) value, options(nomem, nostack)) };
    value
}

fn set_tp(value: usize) {
    // SAFETY: callers install either the layer's live block or relibc's TCB.
    unsafe { asm!("msr tpidr_el0, {}", in(reg) value, options(nostack)) };
}

/// Run one call of the layer with its own thread block installed; return
/// the result or a negated errno, as the relibc platform expects.
fn layer(run: impl FnOnce() -> i64) -> i64 {
    let relibc = tp();
    set_tp(LAYER_TP.load(Ordering::Relaxed));
    let value = run();
    // SAFETY: the layer's block is installed, so its errno slot is live.
    let value = if value < 0 {
        -i64::from(unsafe { *posix_abi::__errno_location() })
    } else {
        value
    };
    set_tp(relibc);
    value
}

fn stafeto_write(fd: c_int, buf: *const u8, len: usize) -> isize {
    // SAFETY: relibc passes a live buffer of len bytes.
    layer(|| unsafe { posix_abi::write(fd, buf, len) } as i64) as isize
}

fn stafeto_read(fd: c_int, buf: *mut u8, len: usize) -> isize {
    // SAFETY: relibc passes a live buffer of len bytes.
    layer(|| unsafe { posix_abi::read(fd, buf, len) } as i64) as isize
}

const LINUX_AT_FDCWD: c_int = -100;
const LINUX_O_ACCMODE: c_int = 3;
const LINUX_O_DIRECTORY: c_int = 0o40000;
const LINUX_O_LARGEFILE: c_int = 0o400000;
const LINUX_O_CLOEXEC: c_int = 0o2000000;

fn stafeto_openat(dirfd: c_int, path: *const c_char, flags: c_int, _mode: u32) -> c_int {
    // relibc uses the Linux flag values; the layer has its own.
    let known = LINUX_O_ACCMODE | LINUX_O_DIRECTORY | LINUX_O_LARGEFILE | LINUX_O_CLOEXEC;
    if dirfd != LINUX_AT_FDCWD || flags & !known != 0 {
        return -EINVAL;
    }
    let mut ours = flags & LINUX_O_ACCMODE;
    if flags & LINUX_O_DIRECTORY != 0 {
        ours |= posix_abi::constants::O_DIRECTORY;
    }
    if flags & LINUX_O_CLOEXEC != 0 {
        ours |= posix_abi::constants::O_CLOEXEC;
    }
    // SAFETY: relibc passes a live C string.
    layer(|| i64::from(unsafe { posix_abi::open(path, ours) })) as c_int
}

fn stafeto_close(fd: c_int) -> c_int {
    // SAFETY: closing a number touches only the layer's table.
    layer(|| i64::from(unsafe { posix_abi::close(fd) })) as c_int
}

fn stafeto_lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    // SAFETY: seeking touches only the layer's table.
    layer(|| unsafe { posix_abi::lseek(fd, offset, whence) })
}

#[allow(dead_code)]
fn stafeto_fstat(_fd: c_int, _out: *mut c_void) -> c_int {
    // The Linux stat layout differs from the layer's; not needed yet.
    -ENOSYS
}

fn stafeto_exit(status: c_int) -> ! {
    set_tp(LAYER_TP.load(Ordering::Relaxed));
    // SAFETY: the process ends here.
    unsafe { posix_abi::_exit(status) }
}

fn stafeto_clock_gettime(clock: c_int, out: *mut Timespec) -> c_int {
    // SAFETY: relibc passes a live timespec; the layouts match.
    layer(|| i64::from(unsafe { posix_abi::clock::clock_gettime(clock, out) })) as c_int
}

fn stafeto_clock_getres(clock: c_int, out: *mut Timespec) -> c_int {
    // SAFETY: relibc passes a live timespec or null.
    layer(|| i64::from(unsafe { posix_abi::clock::clock_getres(clock, out) })) as c_int
}

fn stafeto_getpid() -> c_int {
    posix_abi::process::getpid()
}

fn stafeto_getppid() -> c_int {
    posix_abi::process::getppid()
}

/// Anonymous mappings come from the layer's heap. The heap frees whole
/// blocks only, so the probe remembers each block to refuse partial unmaps.
struct Mappings(UnsafeCell<[(usize, usize); 64]>);
// SAFETY: the probe is single-threaded.
unsafe impl Sync for Mappings {}
static MAPPINGS: Mappings = Mappings(UnsafeCell::new([(0, 0); 64]));

fn stafeto_map_anonymous(len: usize) -> *mut c_void {
    let size = len.div_ceil(4096) * 4096;
    // SAFETY: single-threaded probe owns the table.
    let table = unsafe { &mut *MAPPINGS.0.get() };
    let Some(slot) = table.iter_mut().find(|entry| entry.0 == 0) else {
        return ptr::null_mut();
    };
    let mut pointer = ptr::null_mut();
    // SAFETY: the heap returns size writable bytes or null.
    layer(|| {
        pointer = unsafe { posix_abi::allocation::aligned_alloc(4096, size) };
        if pointer.is_null() {
            return -1;
        }
        unsafe { ptr::write_bytes(pointer, 0, size) };
        0
    });
    if !pointer.is_null() {
        *slot = (pointer as usize, size);
    }
    pointer.cast()
}

fn stafeto_unmap(addr: *mut c_void, len: usize) -> c_int {
    let size = len.div_ceil(4096) * 4096;
    // SAFETY: single-threaded probe owns the table.
    let table = unsafe { &mut *MAPPINGS.0.get() };
    let Some(slot) = table
        .iter_mut()
        .find(|entry| entry.0 == addr as usize && entry.1 == size)
    else {
        return -EINVAL;
    };
    *slot = (0, 0);
    // SAFETY: addr came from aligned_alloc and is freed once.
    layer(|| {
        unsafe { posix_abi::allocation::free(addr.cast()) };
        0
    }) as c_int
}

/// The Linux initial stack relibc's start reads: argc, argv, NULL, envp
/// NULL, then the auxiliary vector with the program headers for TLS.
struct InitialStack(UnsafeCell<[usize; 32]>);
// SAFETY: written once by startup before relibc runs.
unsafe impl Sync for InitialStack {}
static STACK: InitialStack = InitialStack(UnsafeCell::new([0; 32]));
static mut NAME: [u8; 16] = *b"musl-probe\0\0\0\0\0\0";

const AT_NULL: usize = 0;
const AT_PHDR: usize = 3;
const AT_PHENT: usize = 4;
const AT_PHNUM: usize = 5;
const AT_PAGESZ: usize = 6;

fn start_libc() -> ! {
    // SAFETY: lld defines __ehdr_start at the mapped ELF header.
    let header = ptr::addr_of!(__ehdr_start).cast::<u8>();
    // SAFETY: the header is 64 readable bytes.
    let (phoff, phent, phnum) = unsafe {
        (
            ptr::read_unaligned(header.add(32).cast::<u64>()) as usize,
            usize::from(ptr::read_unaligned(header.add(54).cast::<u16>())),
            usize::from(ptr::read_unaligned(header.add(56).cast::<u16>())),
        )
    };
    // SAFETY: startup is single-threaded and writes the stack once.
    let stack = unsafe { &mut *STACK.0.get() };
    let words = [
        1,
        ptr::addr_of!(NAME) as usize,
        0,
        0,
        AT_PHDR,
        header as usize + phoff,
        AT_PHENT,
        phent,
        AT_PHNUM,
        phnum,
        AT_PAGESZ,
        4096,
        AT_NULL,
        0,
    ];
    stack[..words.len()].copy_from_slice(&words);
    LAYER_TP.store(tp(), Ordering::Relaxed);
    // SAFETY: argv points into the Linux-style vector musl's start reads.
    unsafe {
        __libc_start_main(main, 1, stack.as_mut_ptr().add(1).cast(), 0, 0, 0);
    }
    stafeto_exit(126)
}

#[unsafe(export_name = "__rt_main")]
pub extern "C" fn probe_main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 125;
    };
    if let Ok(console) = start.take::<Resource>("console") {
        rt::console::set(console);
    }
    // SAFETY: startup runs once, before application threads and clock calls.
    if unsafe { posix_abi::process::init(&start.parent, &start.process) }.is_err() {
        rt::println!("relibc-probe: process registration failed");
        return 125;
    }
    // SAFETY: as above.
    if unsafe { posix_abi::clock::init(&start.parent) }.is_err() {
        rt::println!("relibc-probe: clock connection failed");
        return 125;
    }
    let Ok(files) = PosixFs::connect(&start.parent) else {
        rt::println!("relibc-probe: file connection failed");
        return 125;
    };
    // SAFETY: only startup owns file initialization.
    if unsafe { posix_abi::shared::init(&start.process, files) }.is_err() {
        rt::println!("relibc-probe: file worker failed");
        return 125;
    }
    // SAFETY: startup is single-threaded and its layout reserves the heap ranges.
    if unsafe { posix_abi::allocation::init(start.process) }.is_err() {
        rt::println!("relibc-probe: heap worker failed");
        return 125;
    }
    // SAFETY: startup owns initialization.
    if unsafe { posix_abi::threads::init(start.thread) }.is_err() {
        rt::println!("relibc-probe: thread worker failed");
        return 125;
    }
    posix_abi::tls::with_thread(1, || start_libc())
}

#[repr(C)]
struct Iovec {
    base: *mut u8,
    len: usize,
}

static mut REPORTED: [bool; 512] = [false; 512];
static mut SEEN: [bool; 512] = [false; 512];

/// musl's single system call entry, Linux AArch64 numbers.
#[unsafe(no_mangle)]
extern "C" fn __stafeto_syscall(n: i64, a: i64, b: i64, c: i64, d: i64, _e: i64, _f: i64) -> i64 {
    // Print each number the first time, to measure the surface used.
    // SAFETY: single-threaded probe.
    unsafe {
        if (0..512).contains(&n) && !SEEN[n as usize] {
            SEEN[n as usize] = true;
            let libc = tp();
            set_tp(LAYER_TP.load(Ordering::Relaxed));
            rt::println!("musl-probe: system call {}", n);
            set_tp(libc);
        }
    }
    const ENOTTY: c_int = 25;
    const EAGAIN: c_int = 11;
    const ENOMEM: c_int = 12;
    match n {
        29 => -i64::from(ENOTTY), // ioctl
        56 => i64::from(stafeto_openat(a as c_int, b as _, c as c_int, d as u32)), // openat
        57 => i64::from(stafeto_close(a as c_int)), // close
        62 => stafeto_lseek(a as c_int, b, c as c_int), // lseek
        63 => stafeto_read(a as c_int, b as _, c as usize) as i64, // read
        64 => stafeto_write(a as c_int, b as _, c as usize) as i64, // write
        65 | 66 => {
            // readv, writev
            let vectors = b as *const Iovec;
            let mut total = 0i64;
            for index in 0..c as usize {
                // SAFETY: musl passes c live iovecs.
                let v = unsafe { &*vectors.add(index) };
                if v.len == 0 {
                    continue;
                }
                let done = if n == 65 {
                    stafeto_read(a as c_int, v.base, v.len) as i64
                } else {
                    stafeto_write(a as c_int, v.base, v.len) as i64
                };
                if done < 0 {
                    return if total > 0 { total } else { done };
                }
                total += done;
                if (done as usize) < v.len {
                    break;
                }
            }
            total
        }
        93 | 94 => stafeto_exit(a as c_int), // exit, exit_group
        96 | 178 => 1,                       // set_tid_address, gettid
        98 => {
            // futex: one thread, nobody waits
            if b & 127 == 0 { -i64::from(EAGAIN) } else { 0 }
        }
        113 => i64::from(stafeto_clock_gettime(a as c_int, b as _)), // clock_gettime
        114 => i64::from(stafeto_clock_getres(a as c_int, b as _)),  // clock_getres
        134 | 135 => 0,                                              // rt_sigaction, rt_sigprocmask
        172 => i64::from(stafeto_getpid()),                          // getpid
        173 => i64::from(stafeto_getppid()),                         // getppid
        214 => -i64::from(ENOMEM),                                   // brk
        215 => i64::from(stafeto_unmap(a as _, b as usize)),         // munmap
        216 => -i64::from(ENOMEM),                                   // mremap
        222 => {
            // mmap: anonymous only
            if e_is_fd(_e) || a != 0 {
                return -i64::from(ENOSYS);
            }
            let p = stafeto_map_anonymous(b as usize);
            if p.is_null() {
                -i64::from(ENOMEM)
            } else {
                p as i64
            }
        }
        226 | 233 => 0, // mprotect, madvise
        _ => {
            // SAFETY: single-threaded probe.
            unsafe {
                if (0..512).contains(&n) && !REPORTED[n as usize] {
                    REPORTED[n as usize] = true;
                    let relibc = tp();
                    set_tp(LAYER_TP.load(Ordering::Relaxed));
                    rt::println!("musl-probe: unhandled system call {}", n);
                    set_tp(relibc);
                }
            }
            -i64::from(ENOSYS)
        }
    }
}

fn e_is_fd(fd: i64) -> bool {
    fd as c_int != -1
}
