// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Probe: a C program on relibc whose "stafeto" platform calls the Rust
//! POSIX layer. The layer starts as in posix-crt, then hands the thread to
//! relibc's own start with a Linux-style initial stack (argc, argv, envp,
//! auxv) so relibc sets up its static TLS from the program headers.
//!
//! Both sides want TPIDR_EL0: relibc points it at its TCB, the layer at its
//! thread block. The probe swaps the register around each forwarded call;
//! a real port would keep the layer's block inside relibc's TCB.

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

type Main = unsafe extern "C" fn(isize, *mut *mut c_char, *mut *mut c_char) -> c_int;

unsafe extern "C" {
    fn main(argc: isize, argv: *mut *mut c_char, envp: *mut *mut c_char) -> c_int;
    fn relibc_start_v1(stack: *const usize, main: Main) -> !;
    static __ehdr_start: [u8; 64];
}

/// The layer's thread block, saved before relibc installs its TCB.
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

#[unsafe(no_mangle)]
extern "C" fn stafeto_write(fd: c_int, buf: *const u8, len: usize) -> isize {
    // SAFETY: relibc passes a live buffer of len bytes.
    layer(|| unsafe { posix_abi::write(fd, buf, len) } as i64) as isize
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_read(fd: c_int, buf: *mut u8, len: usize) -> isize {
    // SAFETY: relibc passes a live buffer of len bytes.
    layer(|| unsafe { posix_abi::read(fd, buf, len) } as i64) as isize
}

const LINUX_AT_FDCWD: c_int = -100;
const LINUX_O_ACCMODE: c_int = 3;
const LINUX_O_DIRECTORY: c_int = 0o40000;
const LINUX_O_LARGEFILE: c_int = 0o400000;
const LINUX_O_CLOEXEC: c_int = 0o2000000;

#[unsafe(no_mangle)]
extern "C" fn stafeto_openat(dirfd: c_int, path: *const c_char, flags: c_int, _mode: u32) -> c_int {
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

#[unsafe(no_mangle)]
extern "C" fn stafeto_close(fd: c_int) -> c_int {
    // SAFETY: closing a number touches only the layer's table.
    layer(|| i64::from(unsafe { posix_abi::close(fd) })) as c_int
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    // SAFETY: seeking touches only the layer's table.
    layer(|| unsafe { posix_abi::lseek(fd, offset, whence) })
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_fstat(_fd: c_int, _out: *mut c_void) -> c_int {
    // The Linux stat layout differs from the layer's; not needed yet.
    -ENOSYS
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_exit(status: c_int) -> ! {
    set_tp(LAYER_TP.load(Ordering::Relaxed));
    // SAFETY: the process ends here.
    unsafe { posix_abi::_exit(status) }
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_clock_gettime(clock: c_int, out: *mut Timespec) -> c_int {
    // SAFETY: relibc passes a live timespec; the layouts match.
    layer(|| i64::from(unsafe { posix_abi::clock::clock_gettime(clock, out) })) as c_int
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_clock_getres(clock: c_int, out: *mut Timespec) -> c_int {
    // SAFETY: relibc passes a live timespec or null.
    layer(|| i64::from(unsafe { posix_abi::clock::clock_getres(clock, out) })) as c_int
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_getpid() -> c_int {
    posix_abi::process::getpid()
}

#[unsafe(no_mangle)]
extern "C" fn stafeto_getppid() -> c_int {
    posix_abi::process::getppid()
}

/// Anonymous mappings come from the layer's heap. The heap frees whole
/// blocks only, so the probe remembers each block to refuse partial unmaps.
struct Mappings(UnsafeCell<[(usize, usize); 64]>);
// SAFETY: the probe is single-threaded.
unsafe impl Sync for Mappings {}
static MAPPINGS: Mappings = Mappings(UnsafeCell::new([(0, 0); 64]));

#[unsafe(no_mangle)]
extern "C" fn stafeto_map_anonymous(len: usize) -> *mut c_void {
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

#[unsafe(no_mangle)]
extern "C" fn stafeto_unmap(addr: *mut c_void, len: usize) -> c_int {
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
static mut NAME: [u8; 16] = *b"relibc-probe\0\0\0\0";

const AT_NULL: usize = 0;
const AT_PHDR: usize = 3;
const AT_PHENT: usize = 4;
const AT_PHNUM: usize = 5;
const AT_PAGESZ: usize = 6;

fn start_relibc() -> ! {
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
    // relibc's start builds its static TLS only when TPIDR_EL0 is zero.
    set_tp(0);
    // SAFETY: the stack and main follow relibc's start contract.
    unsafe { relibc_start_v1(stack.as_ptr(), main) }
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
    posix_abi::tls::with_thread(1, || start_relibc())
}
