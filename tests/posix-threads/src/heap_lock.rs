// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The heap and the descriptor table under the layer's locks, with no
//! helper thread: eight threads malloc, free, dup and close while signals
//! come; a signal raised inside the heap's section is delivered at its end,
//! where the handler finds itself outside it.
use super::*;
use abi::metadata::Timespec;
use abi::signals::{self as api, SigAction};

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
        let block = unsafe { abi::allocation::malloc(size) };
        if block.is_null() {
            ERRORS.fetch_add(1, Ordering::SeqCst);
            break;
        }
        // SAFETY: the block holds `size` bytes.
        unsafe { block.write_bytes(seed as u8, size) };
        let copy = unsafe { abi::dup(fd) };
        if copy < 0 || unsafe { abi::close(copy) } != 0 {
            ERRORS.fetch_add(1, Ordering::SeqCst);
        }
        // SAFETY: as above; nobody else has the block.
        if unsafe { *block.add(size - 1) } != seed as u8 {
            ERRORS.fetch_add(1, Ordering::SeqCst);
        }
        unsafe { abi::allocation::free(block) };
    }
    DONE.fetch_add(1, Ordering::SeqCst);
    ptr::null_mut()
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
    let fd = unsafe { abi::open(c"/etc/motd".as_ptr(), O_RDONLY) };
    if fd < 0 {
        return failed(692);
    }
    FD.store(fd as usize, Ordering::SeqCst);
    let mut ids = [0u64; THREADS];
    for (seed, id) in ids.iter_mut().enumerate() {
        if unsafe { threads::pthread_create(id, ptr::null(), Some(churner), seed as *mut c_void) }
            != 0
        {
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
            if api::pthread_kill(id, SIGUSR1) == 0 {
                sent += 1;
            }
        }
        let _ = unsafe { threads::sleep::nanosleep(&pause, ptr::null_mut()) };
    }
    for id in ids {
        if unsafe { threads::pthread_join(id, ptr::null_mut()) } != 0 {
            return failed(694);
        }
    }
    if ERRORS.load(Ordering::SeqCst) != 0
        || INSIDE.load(Ordering::SeqCst) != 0
        || sent < 64
        || unsafe { abi::close(fd) } != 0
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
