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
//! - R5: as R2, but the first thread ends past the contract of `rt` (no exit
//!   hook); the probe build notices it when the second thread collects the
//!   table, says so and passes the role on in the name of the first.
//! - R6: the last two threads leave at once; relibc's exit is called once.
//! - R7: the main thread leaves while a new thread, live in the table but
//!   without an entry, would be chosen first; the signal still arrives.
//! - R8: B is chosen by the main thread, leaves before the main thread's
//!   message and passes the role on to a third thread.
//! - R3: the main thread holds its entries deferred and, while it is leaving
//!   after its last routing, the signal comes; the signal waits on the page
//!   and reaches the native thread after the handoff.
//! - R4: a thread B marked itself as leaving and is held there; the main
//!   thread leaves meanwhile; a third thread C becomes the router and gets
//!   the signal.
use super::*;
use crate::layer::signals::{self as api, SigAction};
use rt::{Stack, abi::Policy, handle::Channel as Chan, upcall, wait::Waiter};

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
static B_PTHREAD: AtomicU64 = AtomicU64::new(0);
static BARRIER: AtomicUsize = AtomicUsize::new(0);
static MAKE: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn atexit(function: extern "C" fn()) -> c_int;
}

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
    if VARIANT.load(Ordering::SeqCst) == 5 {
        // A program that ends its thread past the contract of `rt`.
        upcall::set_exit_hook(None);
    }
    sys::thread_exit()
}

/// R2: the second native thread gets the signal after the first left.
extern "C" fn second(_: u64) -> ! {
    let sleeper = Sleeper::new();
    tls::with_process(|| {
        ATTACHED.fetch_add(1, Ordering::SeqCst);
        let probe = VARIANT.load(Ordering::SeqCst) == 5;
        if !sleeper.until(2000, || {
            if probe {
                // The probe build notices a router that ended without a
                // handoff when the table is collected.
                abi::relibc::collect();
            }
            main_ended() && ended(&FIRST_ENDED)
        }) {
            end_child(12);
        }
        ready();
        finish(&sleeper, now() + 500_000_000)
    });
    end_child(13)
}

/// The hook of `leaving` after a thread marked itself as leaving. R3: the
/// main thread says the signal may be sent now, when it routed its last and
/// is about to name the next router, and goes on once the signal waits on the
/// page. R4: the thread B is held until the third thread got the signal.
fn marked(own: u64) {
    match VARIANT.load(Ordering::SeqCst) {
        3 if own == 1 => {
            ready();
            let limit = now() + 2_000_000_000;
            while abi::process::page().pending.load(Ordering::Acquire) == 0 && now() < limit {
                let _ = sys::yield_now();
            }
            DEADLINE.store(now() + 500_000_000, Ordering::SeqCst);
        }
        4 if own == B_NUMBER.load(Ordering::SeqCst) => {
            // A thread held here takes no entry: a request of its entry
            // stays unserved, as it does for a thread that is gone.
            core::mem::forget(rt::upcall::defer_entries().expect("router probe deferral"));
            MARKED.store(1, Ordering::SeqCst);
            let limit = now() + 3_000_000_000;
            while RELEASE.load(Ordering::SeqCst) == 0 && now() < limit {
                let _ = sys::yield_now();
            }
        }
        8 if own == B_NUMBER.load(Ordering::SeqCst) => {
            MARKED.store(1, Ordering::SeqCst);
        }
        _ => {}
    }
}

/// R6: both of the last two threads pass their first steps before either
/// takes the table.
fn barrier(_own: u64) {
    BARRIER.fetch_add(1, Ordering::SeqCst);
    let limit = now() + 3_000_000_000;
    while BARRIER.load(Ordering::SeqCst) < 2 && now() < limit {
        let _ = sys::yield_now();
    }
}

/// R6: the handler of atexit runs once; it waits so that a second call of
/// exit has been counted, then ends the child with the verdict.
extern "C" fn on_exit() {
    let limit = now() + 200_000_000;
    while now() < limit {
        let _ = sys::yield_now();
    }
    end_child(if abi::relibc::probe_exit_calls() == 1 {
        0
    } else {
        40
    })
}

/// R8: the main thread, inside its handoff with the successor chosen and the
/// service not told, lets B leave and waits until B marked itself. B then
/// has to pass the role on after the main thread's message.
fn in_handover(own: u64) {
    if VARIANT.load(Ordering::SeqCst) == 8 && own == 1 {
        LEAVE.store(1, Ordering::SeqCst);
        let limit = now() + 2_000_000_000;
        while MARKED.load(Ordering::SeqCst) == 0 && now() < limit {
            let _ = sys::yield_now();
        }
    }
}

/// R7: the creator of a thread, with the new place live and the thread not
/// started, lets the main thread leave and the signal come.
extern "C" fn window(_id: u64) {
    LEAVE.store(1, Ordering::SeqCst);
    let limit = now() + 3_000_000_000;
    while !main_ended() && now() < limit {
        let _ = sys::yield_now();
    }
    ready();
    let limit = now() + 2_000_000_000;
    while abi::process::page().pending.load(Ordering::Acquire) == 0 && now() < limit {
        let _ = sys::yield_now();
    }
}

/// R7: makes the thread whose entry is not bound when the signal comes.
unsafe extern "C" fn maker(_: *mut c_void) -> *mut c_void {
    let limit = now() + 3_000_000_000;
    while MAKE.load(Ordering::SeqCst) == 0 && now() < limit {
        let _ = sys::yield_now();
    }
    abi::relibc::probe_start_window(Some(window));
    let mut made = 0;
    // SAFETY: `quick` is a complete thread routine.
    if unsafe { ffi::pthread_create(&mut made, ptr::null(), Some(quick), ptr::null_mut()) } != 0 {
        end_child(14);
    }
    let sleeper = Sleeper::new();
    finish(&sleeper, now() + 500_000_000)
}

unsafe extern "C" fn quick(_: *mut c_void) -> *mut c_void {
    ptr::null_mut()
}

/// R8: the thread that gets the signal once B passed the role on.
unsafe extern "C" fn third_after(_: *mut c_void) -> *mut c_void {
    let sleeper = Sleeper::new();
    let b_ended = || {
        // SAFETY: the pthread of B stays in the table until it is joined.
        match unsafe { threads::probe_native(B_PTHREAD.load(Ordering::SeqCst)) } {
            Ok(native) => {
                sys::thread_info(&native).map(|info| info.state) == Ok(ThreadState::Ended)
            }
            Err(_) => true,
        }
    };
    if !sleeper.until(3000, || main_ended() && b_ended()) {
        end_child(12);
    }
    ready();
    finish(&sleeper, now() + 500_000_000)
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
    let arrived = sleeper.until(500, || ARRIVED.load(Ordering::SeqCst) != 0);
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
                // nothing routes the signal but the thread that is named
                // the router; `marked` sends the signal while the role
                // passes.
                core::mem::forget(rt::upcall::defer_entries().expect("router probe deferral"));
                abi::relibc::probe_marked_hook(Some(marked));
            }
        }
        2 | 5 => {
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
        6 => {
            ready();
            // SAFETY: on_exit is a complete handler.
            unsafe { atexit(on_exit) };
            abi::relibc::probe_before_table_hook(Some(barrier));
            let mut other = 0;
            // SAFETY: `held` is a complete thread routine.
            if unsafe { ffi::pthread_create(&mut other, ptr::null(), Some(held), ptr::null_mut()) }
                != 0
            {
                end_child(11);
            }
            if !sleeper.until(2000, || B_NUMBER.load(Ordering::SeqCst) != 0) {
                end_child(11);
            }
            LEAVE.store(1, Ordering::SeqCst);
        }
        7 => {
            let (mut d, mut x) = (0, 0);
            // SAFETY: both routines are complete thread routines.
            if unsafe { ffi::pthread_create(&mut d, ptr::null(), Some(quick), ptr::null_mut()) }
                != 0
                || unsafe { ffi::pthread_create(&mut x, ptr::null(), Some(maker), ptr::null_mut()) }
                    != 0
                || unsafe { ffi::pthread_join(d, ptr::null_mut()) } != 0
            {
                end_child(11);
            }
            abi::relibc::probe_in_handover_hook(None);
            MAKE.store(1, Ordering::SeqCst);
            if !sleeper.until(3000, || LEAVE.load(Ordering::SeqCst) != 0) {
                end_child(11);
            }
        }
        8 => {
            abi::relibc::probe_marked_hook(Some(marked));
            abi::relibc::probe_in_handover_hook(Some(in_handover));
            let (mut b, mut c) = (0, 0);
            // SAFETY: both routines are complete thread routines.
            if unsafe { ffi::pthread_create(&mut b, ptr::null(), Some(held), ptr::null_mut()) } != 0
                || unsafe {
                    ffi::pthread_create(&mut c, ptr::null(), Some(third_after), ptr::null_mut())
                } != 0
            {
                end_child(11);
            }
            B_PTHREAD.store(b, Ordering::SeqCst);
            if !sleeper.until(2000, || B_NUMBER.load(Ordering::SeqCst) != 0) {
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
    // R6 ends by itself: it needs no signal.
    if number != 6 && abi::process::kill(pid, SIGUSR2).is_err() {
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
    let passed = (1..=8).all(variant);
    let _ = unsafe { api::sigaction(SIGUSR2, &old, ptr::null_mut()) };
    if passed {
        rt::println!(
            "router: the signal of the process reaches the next router (main exits, rt exit, deferred entries, a router held while leaving)"
        );
    }
    passed
}
