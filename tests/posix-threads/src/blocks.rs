// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Signals and cancellation in the threads' blocks, without a pthread
//! owner: pthread_sigmask makes no kernel call, raise delivers before it
//! returns with four entry-deferral calls, a signal raised inside the layer's lock
//! comes at its end with the same four calls; pthread_kill wakes a thread at 30 that sleeps, whose
//! handler runs and whose sleep gives EINTR with the time left; a thread
//! that only counts is not cancelled until it reaches a point; a handler
//! that runs while its thread waits by address, which sleeps or waits for
//! the lock of the actions, neither loses the wakeup of that wait nor
//! links the thread's node twice.
use super::*;
use crate::layer::signals::{self as api, SigAction};
use abi::metadata::Timespec;
use ffi::{Mutex, pthread_mutex_lock, pthread_mutex_unlock};
use posix_sync::LayerLock;
use posix_thread::flag;
use rt::wait::{Waited, Waiter};

static HANDLED: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static SLEPT: AtomicUsize = AtomicUsize::new(0);
static LEFT: AtomicU64 = AtomicU64::new(0);
static COUNTED: AtomicU64 = AtomicU64::new(0);
static GO: AtomicUsize = AtomicUsize::new(0);
static LAYER: LayerLock = LayerLock::new();
static MUTEX: Mutex = Mutex::new();
static IN_HANDLER: AtomicUsize = AtomicUsize::new(0);
static GOT: AtomicUsize = AtomicUsize::new(0);
/// The channel the holder of the lock of the actions waits on.
static RELEASE: AtomicU64 = AtomicU64::new(0);
static HELD: AtomicUsize = AtomicUsize::new(0);

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
        crate::layer::sleep::clock_nanosleep(abi::clock::CLOCK_MONOTONIC, 0, &request, &mut left)
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
    ffi::pthread_testcancel();
    error();
    ptr::null_mut()
}
fn mutex() -> *mut Mutex {
    ptr::from_ref(&MUTEX).cast_mut()
}
/// SIGUSR2: says it runs, then sleeps 50 ms.
unsafe extern "C" fn slow_handler(_: i32) {
    IN_HANDLER.store(1, Ordering::SeqCst);
    let pause = Timespec {
        tv_sec: 0,
        tv_nsec: 50_000_000,
    };
    let _ = unsafe { crate::layer::sleep::nanosleep(&pause, ptr::null_mut()) };
}
/// Takes MUTEX, which main holds, with SIGUSR2 pending and an entry marked
/// deferred: the entry comes at the end of the first section of its wait
/// by address, its node linked in the bucket.
unsafe extern "C" fn late_taker(_: *mut c_void) -> *mut c_void {
    let Some(block) = threads::probe_block(ffi::pthread_self()) else {
        error();
        return ptr::null_mut();
    };
    block.pending.fetch_or(bit(SIGUSR2), Ordering::SeqCst);
    block.flags.fetch_or(flag::ENTRY_DEFERRED, Ordering::SeqCst);
    if unsafe { pthread_mutex_lock(mutex()) } != 0 {
        error();
    }
    GOT.store(1, Ordering::SeqCst);
    if unsafe { pthread_mutex_unlock(mutex()) } != 0 {
        error();
    }
    ptr::null_mut()
}
/// Holds the lock of the actions until RELEASE is notified.
unsafe extern "C" fn actions_holder(_: *mut c_void) -> *mut c_void {
    let release = Handle::<Channel>::borrowed(rt::abi::Handle(RELEASE.load(Ordering::SeqCst)));
    api::probe_hold_actions(|| {
        HELD.store(1, Ordering::SeqCst);
        if sys::receive(&release).is_err() {
            error();
        }
    });
    ptr::null_mut()
}
/// Whether `flag` is set within 2 s, polling each millisecond.
fn soon(flag: &AtomicUsize) -> bool {
    let pause = Timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000,
    };
    (0..2000).any(|_| {
        if flag.load(Ordering::SeqCst) != 0 {
            return true;
        }
        let _ = unsafe { crate::layer::sleep::nanosleep(&pause, ptr::null_mut()) };
        false
    })
}
/// The entry of a thread that waits for MUTEX runs a handler while the
/// node of that wait is linked: with `hold`, the action has SA_RESETHAND,
/// which the delivery writes under the lock of the actions, and a thread
/// holds that lock, so that the delivery itself waits by address first.
/// Main lets MUTEX go meanwhile; the thread takes it within 2 s.
fn entry_in_a_wait(hold: bool) -> bool {
    IN_HANDLER.store(0, Ordering::SeqCst);
    GOT.store(0, Ordering::SeqCst);
    HELD.store(0, Ordering::SeqCst);
    let action = SigAction {
        handler: slow_handler as *const () as u64,
        mask: 0,
        flags: if hold { SA_RESETHAND } else { 0 },
    };
    if unsafe { api::sigaction(SIGUSR2, &action, ptr::null_mut()) } != 0 {
        return false;
    }
    if unsafe { pthread_mutex_lock(mutex()) } != 0 {
        return false;
    }
    let release = sys::channel_create(30).expect("release channel");
    RELEASE.store(release.raw().0, Ordering::SeqCst);
    let holder = hold.then(|| create(actions_holder));
    if hold && !soon(&HELD) {
        return false;
    }
    let taker = create(late_taker);
    let id = unsafe { threads::probe_native(taker) }.expect("taker handle");
    // The taker waits: in the handler's sleep, or for the lock of the
    // actions.
    let waits = if hold {
        (0..2000).any(|_| {
            let _ = sys::yield_now();
            threads::probe_futex_waiting(taker) && waiting(&id)
        })
    } else {
        soon(&IN_HANDLER)
    };
    if !waits || unsafe { pthread_mutex_unlock(mutex()) } != 0 {
        return false;
    }
    if hold && sys::notify(&release, 1).is_err() {
        return false;
    }
    let got = soon(&GOT);
    if got {
        join(taker);
        if let Some(holder) = holder {
            join(holder);
        }
    }
    got && IN_HANDLER.load(Ordering::SeqCst) == 1
}
fn create(callback: unsafe extern "C" fn(*mut c_void) -> *mut c_void) -> u64 {
    let mut id = 0;
    if unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(callback), ptr::null_mut()) } != 0 {
        error();
    }
    id
}
fn join(id: u64) -> *mut c_void {
    let mut value = ptr::null_mut();
    if unsafe { ffi::pthread_join(id, &mut value) } != 0 {
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
            {
                let deadline = rt::time::ticks_to_ns(rt::time::now()) + 5_000_000_000;
                crate::watchdog::receive(deadline, rt::abi::Error::Interrupted, |deadline| {
                    waiter.receive_until(&done_channel, deadline)
                })
            },
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
    // raise retains its target under two TABLE priority calls and delivers
    // before it returns with two Defer/Resume pairs.
    let before = HANDLED.load(Ordering::SeqCst);
    let raised = calls(|| {
        if api::raise(SIGUSR1) != 0 {
            error();
        }
    });
    if block != 0 || raised != 6 || HANDLED.load(Ordering::SeqCst) != before + 8 {
        rt::println!(
            "blocks-probe: {} calls for a mask, {} for raise",
            block,
            raised
        );
        return failed(641);
    }
    // Inside the layer's lock the signal waits for its end, which delivers
    // it with two Defer/Resume pairs.
    let before = HANDLED.load(Ordering::SeqCst);
    let guard = LAYER.lock();
    let _ = api::raise(SIGUSR1);
    let inside = HANDLED.load(Ordering::SeqCst);
    let start = sys::calls();
    drop(guard);
    let leave = sys::calls() - start;
    if inside != before || HANDLED.load(Ordering::SeqCst) != before + 1 || leave != 4 {
        rt::println!(
            "blocks-probe: {} calls to deliver at the end of the lock",
            leave
        );
        return failed(642);
    }
    rt::println!(
        "blocks-probe: pthread_sigmask makes zero calls; raise uses six calls; lock-end delivery uses four deferral calls"
    );

    // pthread_kill wakes a sleeping thread at 30: its handler, EINTR, the
    // time left.
    let before = HANDLED.load(Ordering::SeqCst);
    let id = create(sleeper);
    let native = unsafe { threads::probe_native(id) }.expect("sleeper handle");
    if !waiting(&native) || ffi::pthread_kill(id, SIGUSR1) != 0 || !wait() {
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
    if !wait() || ffi::pthread_cancel(id) != 0 {
        return failed(645);
    }
    let counted = COUNTED.load(Ordering::Relaxed);
    let pause = Timespec {
        tv_sec: 0,
        tv_nsec: 5_000_000,
    };
    let _ = unsafe { crate::layer::sleep::nanosleep(&pause, ptr::null_mut()) };
    if COUNTED.load(Ordering::Relaxed) == counted {
        return failed(646);
    }
    GO.store(0, Ordering::SeqCst);
    if !wait() || join(id) != ffi::CANCELED {
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
    // An entry while the thread's node is linked in a bucket.
    if !entry_in_a_wait(false) {
        return failed(650);
    }
    if !entry_in_a_wait(true) {
        return failed(651);
    }
    if unsafe { api::sigaction(SIGUSR2, &restored, ptr::null_mut()) } != 0
        || ERRORS.load(Ordering::SeqCst) != 0
    {
        return failed(652);
    }
    // The holder of the lock of the actions runs at the ceiling of the
    // process, and goes back to its level after.
    let me = unsafe { threads::probe_native(ffi::pthread_self()) }.expect("own handle");
    let level = || sys::thread_info(&me).map_or(0, |info| info.base);
    let ceiling = abi::probe_ceiling();
    let before = level();
    let mut actions = 0;
    api::probe_hold_actions(|| actions = level());
    if actions != ceiling || level() != before || before >= ceiling {
        rt::println!(
            "blocks-probe: at {} under the actions' lock, {} after, ceiling {}",
            actions,
            level(),
            ceiling
        );
        return failed(653);
    }
    rt::println!(
        "blocks-probe: a handler that sleeps or waits for the lock of the actions inside a wait by address loses no wakeup; the actions' lock runs at the ceiling"
    );
    true
}
