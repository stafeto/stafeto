// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Signals and cancellation in the threads' blocks, without a pthread
//! owner: pthread_sigmask makes no kernel call, raise delivers before it
//! returns with none, a signal raised inside the layer's lock comes at its
//! end with none; pthread_kill wakes a thread at 30 that sleeps, whose
//! handler runs and whose sleep gives EINTR with the time left; a thread
//! that only counts is not cancelled until it reaches a point.
use super::*;
use abi::metadata::Timespec;
use abi::signals::{self as api, SigAction};
use posix_sync::LayerLock;
use rt::wait::{Waited, Waiter};
use threads::cancel;

static HANDLED: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static SLEPT: AtomicUsize = AtomicUsize::new(0);
static LEFT: AtomicU64 = AtomicU64::new(0);
static COUNTED: AtomicU64 = AtomicU64::new(0);
static GO: AtomicUsize = AtomicUsize::new(0);
static LAYER: LayerLock = LayerLock::new();

fn bit(signal: i32) -> u64 {
    1 << (signal - 1)
}
fn error() {
    ERRORS.fetch_add(1, Ordering::SeqCst);
}
fn done() {
    let channel = Handle::<Channel>::borrowed(rt::abi::Handle(DONE.load(Ordering::Acquire)));
    sys::notify(&channel, 1).expect("blocks probe done");
}
/// The least count of kernel calls `run` makes in eight tries.
fn calls(mut run: impl FnMut()) -> u64 {
    (0..8)
        .map(|_| {
            let before = sys::calls();
            run();
            sys::calls() - before
        })
        .min()
        .unwrap()
}
unsafe extern "C" fn on_signal(_: i32) {
    HANDLED.fetch_add(1, Ordering::SeqCst);
}
/// Sleeps 10 s at level 30: a signal ends it with EINTR and the time left.
unsafe extern "C" fn sleeper(_: *mut c_void) -> *mut c_void {
    if threads::set_level(30).is_err() {
        error();
    }
    let request = Timespec {
        tv_sec: 10,
        tv_nsec: 0,
    };
    let mut left = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let status = unsafe {
        threads::sleep::clock_nanosleep(abi::clock::CLOCK_MONOTONIC, 0, &request, &mut left)
    };
    SLEPT.store(status as usize, Ordering::SeqCst);
    LEFT.store(left.tv_sec as u64, Ordering::SeqCst);
    done();
    ptr::null_mut()
}
/// Counts until GO falls; cancellation waits for its point.
unsafe extern "C" fn counter(_: *mut c_void) -> *mut c_void {
    done();
    while GO.load(Ordering::SeqCst) != 0 {
        COUNTED.fetch_add(1, Ordering::Relaxed);
        let _ = sys::yield_now();
    }
    done();
    cancel::pthread_testcancel();
    error();
    ptr::null_mut()
}
fn create(callback: unsafe extern "C" fn(*mut c_void) -> *mut c_void) -> u64 {
    let mut id = 0;
    if unsafe { threads::pthread_create(&mut id, ptr::null(), Some(callback), ptr::null_mut()) }
        != 0
    {
        error();
    }
    id
}
fn join(id: u64) -> *mut c_void {
    let mut value = ptr::null_mut();
    if unsafe { threads::pthread_join(id, &mut value) } != 0 {
        error();
    }
    value
}

pub(super) fn run() -> bool {
    let done_channel = sys::channel_create(30).expect("blocks done channel");
    DONE.store(done_channel.raw().0, Ordering::Release);
    let waiter = Waiter::new(&done_channel, 1, 30).expect("blocks watchdog");
    let wait = || {
        matches!(
            waiter.receive_until(
                &done_channel,
                rt::time::ticks_to_ns(rt::time::now()) + 5_000_000_000
            ),
            Ok(Waited::Got(_))
        )
    };
    let action = SigAction {
        handler: on_signal as *const () as u64,
        mask: 0,
        flags: 0,
    };
    if unsafe { api::sigaction(SIGUSR1, &action, ptr::null_mut()) } != 0 {
        return failed(640);
    }
    // The mask is a word of the block: no call either way.
    let block = calls(|| {
        let set = bit(SIGUSR2);
        if unsafe { api::pthread_sigmask(SIG_BLOCK, &set, ptr::null_mut()) } != 0
            || unsafe { api::pthread_sigmask(SIG_UNBLOCK, &set, ptr::null_mut()) } != 0
        {
            error();
        }
    });
    // raise delivers before it returns, with no call.
    let before = HANDLED.load(Ordering::SeqCst);
    let raised = calls(|| {
        if api::raise(SIGUSR1) != 0 {
            error();
        }
    });
    if block != 0 || raised != 0 || HANDLED.load(Ordering::SeqCst) != before + 8 {
        rt::println!(
            "blocks-probe: {} calls for a mask, {} for raise",
            block,
            raised
        );
        return failed(641);
    }
    // Inside the layer's lock the signal waits for its end, which delivers
    // it with no call.
    let before = HANDLED.load(Ordering::SeqCst);
    let guard = LAYER.lock();
    let _ = api::raise(SIGUSR1);
    let inside = HANDLED.load(Ordering::SeqCst);
    let start = sys::calls();
    drop(guard);
    let leave = sys::calls() - start;
    if inside != before || HANDLED.load(Ordering::SeqCst) != before + 1 || leave != 0 {
        rt::println!(
            "blocks-probe: {} calls to deliver at the end of the lock",
            leave
        );
        return failed(642);
    }
    rt::println!(
        "blocks-probe: pthread_sigmask, raise and delivery at the end of the layer's lock make no kernel call"
    );

    // pthread_kill wakes a sleeping thread at 30: its handler, EINTR, the
    // time left.
    let before = HANDLED.load(Ordering::SeqCst);
    let id = create(sleeper);
    let native = unsafe { threads::probe_native(id) }.expect("sleeper handle");
    if !waiting(&native) || api::pthread_kill(id, SIGUSR1) != 0 || !wait() {
        return failed(643);
    }
    join(id);
    let left = LEFT.load(Ordering::SeqCst);
    if HANDLED.load(Ordering::SeqCst) != before + 1
        || SLEPT.load(Ordering::SeqCst) != EINTR as usize
        || !(9..=10).contains(&left)
    {
        return failed(644);
    }
    rt::println!(
        "blocks-probe: pthread_kill ends the sleep of a thread at 30 with EINTR and the time left"
    );

    // A counting thread is cancelled only at its point.
    GO.store(1, Ordering::SeqCst);
    let id = create(counter);
    if !wait() || threads::pthread_cancel(id) != 0 {
        return failed(645);
    }
    let counted = COUNTED.load(Ordering::Relaxed);
    let pause = Timespec {
        tv_sec: 0,
        tv_nsec: 5_000_000,
    };
    let _ = unsafe { threads::sleep::nanosleep(&pause, ptr::null_mut()) };
    if COUNTED.load(Ordering::Relaxed) == counted {
        return failed(646);
    }
    GO.store(0, Ordering::SeqCst);
    if !wait() || join(id) != cancel::CANCELED {
        return failed(647);
    }
    let restored = SigAction {
        handler: api::DEFAULT,
        mask: 0,
        flags: 0,
    };
    if unsafe { api::sigaction(SIGUSR1, &restored, ptr::null_mut()) } != 0
        || ERRORS.load(Ordering::SeqCst) != 0
    {
        return failed(648);
    }
    rt::println!("blocks-probe: a counting thread is cancelled only at its point");
    true
}
