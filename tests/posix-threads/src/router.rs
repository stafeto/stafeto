// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The router of the process's signals leaves and the next thread routes
//! (spec 2, 3.3). The probe runs in the native-scope process: each variant
//! forks a child, the parent signals it with SIGUSR2 once the child says its
//! state is set, and the child's handler marks the arrival within 500 ms.
//!
//! - R1: the main thread, the router, calls pthread_exit; one native thread
//!   of a program stays in a scope of the layer and gets the signal.
//! - R2: two native threads; the first becomes the router and ends through
//!   `rt::sys::thread_exit`; the second gets the signal.
//! - R3: the main thread holds its entries deferred while the signal comes,
//!   then calls pthread_exit; the signal waited on the page and reaches the
//!   native thread after the handoff.
//! - R4: a thread B marked itself as leaving and is held there; the main
//!   thread leaves meanwhile; a third thread C becomes the router and gets
//!   the signal.
use super::*;
use crate::layer::signals::{self as api, SigAction};
use rt::{Stack, abi::Policy, handle::Channel as Chan, wait::Waiter};

static STACK_A: Stack<16384> = Stack::new();
static STACK_B: Stack<16384> = Stack::new();
static ARRIVED: AtomicUsize = AtomicUsize::new(0);
static ATTACHED: AtomicUsize = AtomicUsize::new(0);
static DEADLINE: AtomicU64 = AtomicU64::new(0);
static FIRST_ENDED: AtomicU64 = AtomicU64::new(0);
static READY_FD: AtomicU64 = AtomicU64::new(0);
static LEVEL: AtomicU64 = AtomicU64::new(0);
static VARIANT: AtomicUsize = AtomicUsize::new(0);
static LEAVE: AtomicUsize = AtomicUsize::new(0);
static MARKED: AtomicUsize = AtomicUsize::new(0);
static RELEASE: AtomicUsize = AtomicUsize::new(0);
static B_NUMBER: AtomicU64 = AtomicU64::new(0);

/// The buffers of the native threads of the variants.
const BUFFER: usize = 0xe60000;

unsafe extern "C" fn arrived(_signal: c_int) {
    ARRIVED.fetch_add(1, Ordering::SeqCst);
}

fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}

/// A thread's own short sleeps: a channel nobody sends to and a timer on it.
struct Sleeper {
    channel: Handle<Chan>,
    waiter: Waiter,
}

impl Sleeper {
    fn new() -> Sleeper {
        let level = LEVEL.load(Ordering::SeqCst) as u8;
        let channel = sys::channel_create(level).expect("router probe sleep channel");
        let waiter = Waiter::new(&channel, 0, level).expect("router probe sleep timer");
        Sleeper { channel, waiter }
    }

    /// Waits about `ms` milliseconds; a request of the thread's entry ends
    /// the wait early, as it does any wait.
    fn nap(&self, ms: u64) {
        let _ = self
            .waiter
            .receive_until(&self.channel, now() + ms * 1_000_000);
    }

    /// Until `condition` holds, for at most `ms` milliseconds.
    fn until(&self, ms: u64, condition: impl Fn() -> bool) -> bool {
        let limit = now() + ms * 1_000_000;
        while !condition() {
            if now() >= limit {
                return false;
            }
            self.nap(2);
        }
        true
    }
}

fn end_child(code: u64) -> ! {
    sys::process_exit(code)
}

/// The thread of the main thread has ended (its handoff was done).
fn main_ended() -> bool {
    sys::thread_info(&threads::main_handle()).map(|info| info.state) == Ok(ThreadState::Ended)
}

fn ended(raw: &AtomicU64) -> bool {
    let thread = Handle::<Thread>::borrowed(rt::abi::Handle(raw.load(Ordering::SeqCst)));
    sys::thread_info(&thread).map(|info| info.state) == Ok(ThreadState::Ended)
}

/// Tells the parent that the signal may be sent.
fn ready() {
    let fd = READY_FD.load(Ordering::SeqCst) as c_int;
    if abi::write(fd, &[1]) != Ok(1) {
        end_child(15);
    }
}

/// Ends the child with 0 when the signal arrived before `limit`.
fn finish(sleeper: &Sleeper, limit: u64) -> ! {
    let mut left = limit.saturating_sub(now()) / 1_000_000;
    if left == 0 {
        left = 1;
    }
    let arrived = sleeper.until(left, || ARRIVED.load(Ordering::SeqCst) != 0);
    end_child(if arrived {
        0
    } else {
        20 + VARIANT.load(Ordering::SeqCst) as u64
    })
}

/// A native thread of the program, started with its own buffer.
fn spawn(entry: extern "C" fn(u64) -> !, stack: &'static Stack<16384>, slot: usize) -> u64 {
    let level = LEVEL.load(Ordering::SeqCst) as u8;
    // SAFETY: the stack is this thread's alone and the entry never returns.
    let thread = unsafe {
        sys::thread_create_with(
            abi::allocation::process(),
            entry,
            stack.top(),
            0,
            level,
            Policy::Fifo,
            BUFFER + slot * 0x1000,
            None,
        )
    }
    .expect("router probe native thread");
    if sys::thread_start(&thread).is_err() {
        end_child(14);
    }
    thread.into_raw().0
}

/// R1 and R3: waits in a scope of the layer for the signal.
extern "C" fn survivor(_: u64) -> ! {
    let sleeper = Sleeper::new();
    tls::with_process(|| {
        ATTACHED.fetch_add(1, Ordering::SeqCst);
        if VARIANT.load(Ordering::SeqCst) == 1 {
            if !sleeper.until(2000, main_ended) {
                end_child(12);
            }
            ready();
            finish(&sleeper, now() + 500_000_000)
        }
        // R3: the main thread says when the 500 ms start.
        if !sleeper.until(2000, || DEADLINE.load(Ordering::SeqCst) != 0) {
            end_child(12);
        }
        finish(&sleeper, DEADLINE.load(Ordering::SeqCst))
    });
    end_child(13)
}

/// R2: the first native thread ends through `rt` once the main thread left.
extern "C" fn first(_: u64) -> ! {
    let sleeper = Sleeper::new();
    tls::with_process(|| {
        ATTACHED.fetch_add(1, Ordering::SeqCst);
        if !sleeper.until(2000, main_ended) {
            end_child(12);
        }
    });
    sys::thread_exit()
}

/// R2: the second native thread gets the signal after the first left.
extern "C" fn second(_: u64) -> ! {
    let sleeper = Sleeper::new();
    tls::with_process(|| {
        ATTACHED.fetch_add(1, Ordering::SeqCst);
        if !sleeper.until(2000, || main_ended() && ended(&FIRST_ENDED)) {
            end_child(12);
        }
        ready();
        finish(&sleeper, now() + 500_000_000)
    });
    end_child(13)
}

/// R4: the hook of `leaving` after a thread marked itself as leaving.
fn marked(own: u64) {
    if own == B_NUMBER.load(Ordering::SeqCst) {
        MARKED.store(1, Ordering::SeqCst);
        let limit = now() + 3_000_000_000;
        while RELEASE.load(Ordering::SeqCst) == 0 && now() < limit {
            let _ = sys::yield_now();
        }
    }
}

/// R4: the thread that is held in `leaving`.
unsafe extern "C" fn held(_: *mut c_void) -> *mut c_void {
    B_NUMBER.store(abi::relibc::current(), Ordering::SeqCst);
    let limit = now() + 3_000_000_000;
    while LEAVE.load(Ordering::SeqCst) == 0 && now() < limit {
        let _ = sys::yield_now();
    }
    ptr::null_mut()
}

/// R4: the thread that gets the signal.
unsafe extern "C" fn third(_: *mut c_void) -> *mut c_void {
    let sleeper = Sleeper::new();
    if !sleeper.until(3000, main_ended) {
        end_child(12);
    }
    ready();
    let limit = now() + 500_000_000;
    let arrived = sleeper.until(500, || ARRIVED.load(Ordering::SeqCst) != 0);
    let _ = limit;
    RELEASE.store(1, Ordering::SeqCst);
    end_child(if arrived { 0 } else { 24 })
}

/// The child of a variant, on the forked main thread.
fn child(variant: usize, fd: c_int) -> ! {
    VARIANT.store(variant, Ordering::SeqCst);
    READY_FD.store(fd as u64, Ordering::SeqCst);
    let level = sys::thread_info(&threads::main_handle())
        .expect("router probe main level")
        .base;
    LEVEL.store(level.into(), Ordering::SeqCst);
    let sleeper = Sleeper::new();
    match variant {
        1 | 3 => {
            let _ = spawn(survivor, &STACK_A, 0);
            if !sleeper.until(2000, || ATTACHED.load(Ordering::SeqCst) == 1) {
                end_child(11);
            }
            if variant == 3 {
                // The entries of this thread stay deferred for good, so
                // the signal waits on the page.
                core::mem::forget(rt::upcall::defer_entries().expect("router probe deferral"));
                ready();
                if !sleeper.until(1000, || {
                    abi::process::page().pending.load(Ordering::Acquire) != 0
                }) {
                    end_child(13);
                }
                DEADLINE.store(now() + 500_000_000, Ordering::SeqCst);
            }
        }
        2 => {
            let one = spawn(first, &STACK_A, 0);
            FIRST_ENDED.store(one, Ordering::SeqCst);
            if !sleeper.until(2000, || ATTACHED.load(Ordering::SeqCst) == 1) {
                end_child(11);
            }
            let _ = spawn(second, &STACK_B, 1);
            if !sleeper.until(2000, || ATTACHED.load(Ordering::SeqCst) == 2) {
                end_child(11);
            }
        }
        _ => {
            abi::relibc::probe_marked_hook(Some(marked));
            let (mut b, mut c) = (0, 0);
            // SAFETY: both routines are complete thread routines.
            if unsafe { ffi::pthread_create(&mut b, ptr::null(), Some(held), ptr::null_mut()) } != 0
                || unsafe { ffi::pthread_create(&mut c, ptr::null(), Some(third), ptr::null_mut()) }
                    != 0
            {
                end_child(11);
            }
            if !sleeper.until(2000, || B_NUMBER.load(Ordering::SeqCst) != 0) {
                end_child(11);
            }
            LEAVE.store(1, Ordering::SeqCst);
            if !sleeper.until(2000, || MARKED.load(Ordering::SeqCst) != 0) {
                end_child(11);
            }
        }
    }
    // SAFETY: the main thread of the child ends; the rest of the child
    // follows the variant.
    unsafe { ffi::pthread_exit(ptr::null_mut()) }
}

fn variant(number: usize) -> bool {
    let Ok([read, write]) = abi::pipe2(0) else {
        return failed(1600 + number);
    };
    let pid = match abi::fork::fork(None) {
        Ok(0) => child(number, write),
        Ok(pid) => pid,
        Err(_) => return failed(1610 + number),
    };
    let _ = abi::close(write);
    let mut byte = [0u8; 1];
    if abi::read(read, &mut byte) != Ok(1) {
        rt::println!("router: R{number} child gave no ready byte");
        let _ = abi::process::kill(pid, 9);
        let _ = abi::process::wait(proto_process::Selector::Pid(pid as u32), 0);
        return failed(1620 + number);
    }
    let _ = abi::close(read);
    if abi::process::kill(pid, SIGUSR2).is_err() {
        return failed(1630 + number);
    }
    let waited = abi::process::wait(
        proto_process::Selector::Pid(pid as u32),
        proto_process::WEXITED,
    );
    match waited {
        Ok(waited) if waited.end == Some(proto_process::End::exited(0)) => true,
        Ok(waited) => {
            rt::println!(
                "router: R{number} ended with status {}",
                waited.end.map_or(-1, |end| end.wait_status())
            );
            failed(1640 + number)
        }
        Err(errno) => {
            rt::println!("router: R{number} wait failed {errno}");
            failed(1650 + number)
        }
    }
}

#[inline(never)]
pub(super) fn run() -> bool {
    let action = SigAction {
        handler: arrived as *const () as u64,
        mask: 0,
        flags: 0,
    };
    let mut old = SigAction {
        handler: 0,
        mask: 0,
        flags: 0,
    };
    if unsafe { api::sigaction(SIGUSR2, &action, &mut old) } != 0 {
        return failed(1600);
    }
    let passed = (1..=4).all(variant);
    let _ = unsafe { api::sigaction(SIGUSR2, &old, ptr::null_mut()) };
    if passed {
        rt::println!(
            "router: the signal of the process reaches the next router (main exits, rt exit, deferred entries, a router held while leaving)"
        );
    }
    passed
}
