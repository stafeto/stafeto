// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The heap and the descriptor table under the layer's locks, with no
//! helper thread: eight threads malloc, free, dup and close while signals
//! come; a signal raised inside the heap's section is delivered at its end,
//! where the handler finds itself outside it; a thread that waits for the
//! files' lock takes its signal after the holder left; a thread with the
//! least stack (PTHREAD_STACK_MIN) makes file requests with a signal
//! inside the files' section, and the peak of its stack is measured.
use super::*;
use crate::layer::signals::{self as api, SigAction};
use abi::metadata::Timespec;

const THREADS: usize = 8;
const ROUNDS: usize = 1500;
static FD: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static HANDLED: AtomicUsize = AtomicUsize::new(0);
static INSIDE: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn counted(_: i32) {
    HANDLED.fetch_add(1, Ordering::SeqCst);
    if abi::allocation::probe_inside() {
        INSIDE.fetch_add(1, Ordering::SeqCst);
    }
}

unsafe extern "C" fn churner(argument: *mut c_void) -> *mut c_void {
    let seed = argument as usize;
    let fd = FD.load(Ordering::SeqCst) as i32;
    // Below main, which wakes to signal them while they churn.
    if threads::set_level(20).is_err() {
        ERRORS.fetch_add(1, Ordering::SeqCst);
    }
    for round in 0..ROUNDS {
        let size = 16 + (round * 37 + seed * 101) % 700;
        let block = unsafe { ffi::malloc(size) };
        if block.is_null() {
            ERRORS.fetch_add(1, Ordering::SeqCst);
            break;
        }
        // SAFETY: the block holds `size` bytes.
        unsafe { block.write_bytes(seed as u8, size) };
        let copy = unsafe { ffi::dup(fd) };
        if copy < 0 || unsafe { ffi::close(copy) } != 0 {
            ERRORS.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: as above; nobody else has the block.
        if unsafe { *block.add(size - 1) } != seed as u8 {
            ERRORS.fetch_add(1, Ordering::SeqCst);
        }
        unsafe { ffi::free(block) };
    }
    DONE.fetch_add(1, Ordering::SeqCst);
    ptr::null_mut()
}

static HOLDING: AtomicUsize = AtomicUsize::new(0);
static DUPED: AtomicUsize = AtomicUsize::new(0);
static CAUGHT_HOLDING: AtomicUsize = AtomicUsize::new(usize::MAX);
static PEAK: AtomicUsize = AtomicUsize::new(0);
const PAINT: u8 = 0xa5;

unsafe extern "C" fn seen_holding(_: i32) {
    CAUGHT_HOLDING.store(HOLDING.load(Ordering::SeqCst), Ordering::SeqCst);
}

/// dup while main holds the lock of the files.
unsafe extern "C" fn dupper(_: *mut c_void) -> *mut c_void {
    let fd = FD.load(Ordering::SeqCst) as i32;
    let copy = unsafe { ffi::dup(fd) };
    if copy >= 0 && unsafe { ffi::close(copy) } == 0 {
        DUPED.store(1, Ordering::SeqCst);
    }
    ptr::null_mut()
}

/// On a stack of PTHREAD_STACK_MIN: paints the stack below its frame,
/// makes file requests with a signal raised inside the files' section,
/// and finds the deepest painted byte that changed.
unsafe extern "C" fn small_stack(_: *mut c_void) -> *mut c_void {
    let Some(block) = threads::probe_block(ffi::pthread_self()) else {
        return ptr::null_mut();
    };
    // The stack lies right below the page of the TCB.
    let top = ptr::from_ref(block) as usize & !0xfff;
    let bottom = top - PTHREAD_STACK_MIN;
    let marker = 0u8;
    let here = ptr::from_ref(&marker) as usize;
    let painted = here - 512;
    // SAFETY: the bytes from the bottom of this thread's stack to below
    // its live frames are its own and unused.
    unsafe { ptr::write_bytes(bottom as *mut u8, PAINT, painted - bottom) };
    let mut ok = true;
    let fd = unsafe { ffi::open(c"/etc/motd".as_ptr(), O_RDONLY) };
    let mut buffer = [0u8; 64];
    ok &= fd >= 0 && unsafe { ffi::read(fd, buffer.as_mut_ptr(), buffer.len()) } > 0;
    abi::shared::probe_hold(|| {
        let _ = api::raise(SIGUSR1);
    });
    let mut status = ffi::Stat::new();
    ok &= unsafe { ffi::fstat(fd, &mut status) } == 0;
    ok &= unsafe { ffi::write(1, b"\n".as_ptr(), 1) } == 1;
    ok &= unsafe { ffi::close(fd) } == 0;
    let first = (bottom..painted)
        // SAFETY: as above.
        .find(|&a| unsafe { *(a as *const u8) } != PAINT)
        .unwrap_or(painted);
    PEAK.store(top - first, Ordering::SeqCst);
    usize::from(ok) as *mut c_void
}

/// The two probes of the files' lock and of the least stack.
fn files_lock_and_stack(fd: i32) -> bool {
    FD.store(fd as usize, Ordering::SeqCst);
    let action = SigAction {
        handler: seen_holding as *const () as u64,
        mask: 0,
        flags: 0,
    };
    if unsafe { api::sigaction(SIGUSR1, &action, ptr::null_mut()) } != 0 {
        return failed(696);
    }
    let pause = Timespec {
        tv_sec: 0,
        tv_nsec: 5_000_000,
    };
    let mut id = 0;
    let mut created = false;
    abi::shared::probe_hold(|| {
        HOLDING.store(1, Ordering::SeqCst);
        created =
            unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(dupper), ptr::null_mut()) }
                == 0;
        // The dupper runs while main sleeps and waits for the lock; the
        // signal comes then.
        let _ = unsafe { crate::layer::sleep::nanosleep(&pause, ptr::null_mut()) };
        let _ = ffi::pthread_kill(id, SIGUSR1);
        let _ = unsafe { crate::layer::sleep::nanosleep(&pause, ptr::null_mut()) };
        HOLDING.store(0, Ordering::SeqCst);
    });
    if !created
        || unsafe { ffi::pthread_join(id, ptr::null_mut()) } != 0
        || DUPED.load(Ordering::SeqCst) != 1
        || CAUGHT_HOLDING.load(Ordering::SeqCst) != 0
    {
        rt::println!(
            "heap-lock-probe: dup {}, handler saw the holder {}",
            DUPED.load(Ordering::SeqCst),
            CAUGHT_HOLDING.load(Ordering::SeqCst)
        );
        return failed(697);
    }
    let mut attr = core::mem::MaybeUninit::uninit();
    let mut value = ptr::null_mut();
    if unsafe { ffi::pthread_attr_init(attr.as_mut_ptr()) } != 0
        || unsafe { ffi::pthread_attr_setstacksize(attr.as_mut_ptr(), PTHREAD_STACK_MIN) } != 0
        || unsafe {
            ffi::pthread_create(&mut id, attr.as_ptr(), Some(small_stack), ptr::null_mut())
        } != 0
        || unsafe { ffi::pthread_join(id, &mut value) } != 0
        || value as usize != 1
    {
        return failed(698);
    }
    rt::println!(
        "heap-lock-probe: a waiter for the files' lock takes its signal after the holder; file requests with a signal in the section peak at {} of {} bytes of stack",
        PEAK.load(Ordering::SeqCst),
        PTHREAD_STACK_MIN
    );
    true
}

pub(super) fn run() -> bool {
    let action = SigAction {
        handler: counted as *const () as u64,
        mask: 0,
        flags: 0,
    };
    let mut old = action;
    if unsafe { api::sigaction(SIGUSR1, &action, &mut old) } != 0 {
        return failed(690);
    }
    // A signal raised inside the heap's section waits for its end.
    let before = HANDLED.load(Ordering::SeqCst);
    let mut inside = usize::MAX;
    abi::allocation::probe_hold(|| {
        let _ = api::raise(SIGUSR1);
        inside = HANDLED.load(Ordering::SeqCst);
    });
    if inside != before
        || HANDLED.load(Ordering::SeqCst) != before + 1
        || INSIDE.load(Ordering::SeqCst) != 0
    {
        return failed(691);
    }
    let fd = unsafe { ffi::open(c"/etc/motd".as_ptr(), O_RDONLY) };
    if fd < 0 {
        return failed(692);
    }
    FD.store(fd as usize, Ordering::SeqCst);
    let mut ids = [0u64; THREADS];
    for (seed, id) in ids.iter_mut().enumerate() {
        let made =
            unsafe { ffi::pthread_create(id, ptr::null(), Some(churner), seed as *mut c_void) };
        if made != 0 {
            return failed(693);
        }
    }
    let pause = Timespec {
        tv_sec: 0,
        tv_nsec: 200_000,
    };
    let mut sent = 0;
    while DONE.load(Ordering::SeqCst) < THREADS {
        for &id in &ids {
            if ffi::pthread_kill(id, SIGUSR1) == 0 {
                sent += 1;
            }
        }
        let _ = unsafe { crate::layer::sleep::nanosleep(&pause, ptr::null_mut()) };
    }
    for id in ids {
        if unsafe { ffi::pthread_join(id, ptr::null_mut()) } != 0 {
            return failed(694);
        }
    }
    if !files_lock_and_stack(fd) {
        return false;
    }
    if ERRORS.load(Ordering::SeqCst) != 0
        || INSIDE.load(Ordering::SeqCst) != 0
        || sent < 64
        || unsafe { ffi::close(fd) } != 0
        || unsafe { api::sigaction(SIGUSR1, &old, ptr::null_mut()) } != 0
    {
        rt::println!(
            "heap-lock-probe: {} errors, {} handlers inside the heap",
            ERRORS.load(Ordering::SeqCst),
            INSIDE.load(Ordering::SeqCst)
        );
        return failed(695);
    }
    rt::println!(
        "heap-lock-probe: eight threads malloc/free/dup/close under {} signals ({} handled); a signal inside the heap's section comes at its end",
        sent,
        HANDLED.load(Ordering::SeqCst)
    );
    true
}
