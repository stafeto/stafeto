// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Real interrupted pthread requests and application-thread process lifetime.
//! The probe is a C program on relibc: posix-crt starts it, relibc calls
//! its `main`; relibc's pthreads come through libc-ffi, the layer's
//! internals through the layer's Rust interface.

#![no_std]
#![no_main]

use core::{
    ffi::{c_char, c_int, c_void},
    ptr,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};
use libc_ffi::{self as ffi, PTHREAD_CANCEL_DISABLE};
#[cfg(not(feature = "cancel-input"))]
use libc_ffi::{
    PTHREAD_CANCEL_ENABLE, PTHREAD_DESTRUCTOR_ITERATIONS, PTHREAD_MUTEX_ERRORCHECK,
    PTHREAD_MUTEX_RECURSIVE, PTHREAD_STACK_MIN,
};
use posix_abi::{self as abi, threads};
#[cfg(not(feature = "cancel-input"))]
use posix_abi::{constants::*, tls};
#[cfg(not(feature = "cancel-input"))]
use rt::handle::Channel;
use rt::{
    abi::ThreadState,
    handle::{Handle, Thread},
    sys,
};

#[cfg(not(feature = "cancel-input"))]
mod blocks;
#[cfg(not(feature = "cancel-input"))]
mod borrow_guards;
#[cfg(not(feature = "cancel-input"))]
mod cancellation;
#[cfg(not(feature = "cancel-input"))]
mod capacity;
#[cfg(not(feature = "cancel-input"))]
mod clocks;
#[cfg(not(feature = "cancel-input"))]
mod credentials;
#[cfg(not(feature = "cancel-input"))]
mod futex;
#[cfg(not(feature = "cancel-input"))]
mod heap_lock;
#[cfg(feature = "cancel-input")]
mod input;
#[cfg(not(feature = "cancel-input"))]
mod long;
#[cfg(not(feature = "cancel-input"))]
mod mutex;
#[cfg(not(feature = "cancel-input"))]
mod once;
#[cfg(not(feature = "cancel-input"))]
mod one_thread;
#[cfg(not(feature = "cancel-input"))]
mod reentry;
#[cfg(not(feature = "cancel-input"))]
mod signal_context;
#[cfg(not(feature = "cancel-input"))]
mod signal_wait;
#[cfg(not(feature = "cancel-input"))]
mod signals;
#[cfg(not(feature = "cancel-input"))]
mod sleep;
#[cfg(not(feature = "cancel-input"))]
mod specific;
#[cfg(not(feature = "cancel-input"))]
mod tcb;
#[cfg(not(feature = "cancel-input"))]
mod timed;
#[cfg(not(feature = "cancel-input"))]
mod upcall;

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;
/// The main thread's relibc `pthread_t`, which a later thread joins.
#[cfg(not(feature = "cancel-input"))]
static MAIN: AtomicU64 = AtomicU64::new(0);
static PROCESS: AtomicU64 = AtomicU64::new(0);
#[cfg(not(feature = "cancel-input"))]
static MAIN_BASE: AtomicU64 = AtomicU64::new(0);
#[cfg(not(feature = "cancel-input"))]
static TARGET: AtomicU64 = AtomicU64::new(0);
#[cfg(not(feature = "cancel-input"))]
static JOINED: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
#[cfg(not(feature = "cancel-input"))]
const VALUE: usize = 0x5678;

/// Ends its thread with thread_exit, past the library: no EXIT reaches the
/// owner, only the kernel's notification of the thread's end.
#[cfg(not(feature = "cancel-input"))]
unsafe extern "C" fn past_the_library(_: *mut c_void) -> *mut c_void {
    sys::thread_exit()
}

unsafe extern "C" fn returning(argument: *mut c_void) -> *mut c_void {
    CALLS.fetch_add(1, Ordering::AcqRel);
    argument
}
#[cfg(not(feature = "cancel-input"))]
unsafe extern "C" fn gated(argument: *mut c_void) -> *mut c_void {
    let gate = Handle::<Channel>::borrowed(rt::abi::Handle(argument as u64));
    sys::receive(&gate).expect("target release");
    VALUE as *mut c_void
}
#[cfg(not(feature = "cancel-input"))]
unsafe extern "C" fn joiner(_: *mut c_void) -> *mut c_void {
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    let mut value = ptr::null_mut();
    let status = unsafe { ffi::pthread_join(TARGET.load(Ordering::Acquire), &mut value) };
    let passed = status == 0 && value as usize == VALUE && unsafe { *errno } == 777;
    JOINED.store(if passed { 1 } else { 2 }, Ordering::Release);
    value
}

#[cfg(not(feature = "cancel-input"))]
fn waiting(thread: &Handle<Thread>) -> bool {
    waiting_registered(thread, || true)
}

#[cfg(not(feature = "cancel-input"))]
fn waiting_registered(thread: &Handle<Thread>, registered: impl Fn() -> bool) -> bool {
    let wake = sys::channel_create(30).expect("poll wake channel");
    let timer = sys::timer_create(&wake, 30).expect("poll timer");
    for _ in 0..100 {
        // In a request of a service, or in receive on a channel of its own.
        if sys::thread_info(thread).is_ok_and(|info| {
            matches!(
                info.state,
                ThreadState::AwaitingReply | ThreadState::Receiving
            )
        }) && registered()
        {
            return true;
        }
        // Let setup RPCs finish before checking the specific registered wait.
        sys::timer_set(&timer, sys::clock_now().expect("poll clock") + 1_000_000)
            .expect("poll deadline");
        sys::receive(&wake).expect("poll wake");
    }
    false
}

/// Whether pthread `id` waits by address within 100 ms (its node linked
/// in a bucket, posix-sync).
#[cfg(not(feature = "cancel-input"))]
fn futex_blocked(id: u64) -> bool {
    let wake = sys::channel_create(30).expect("poll wake channel");
    let timer = sys::timer_create(&wake, 30).expect("poll timer");
    for _ in 0..100 {
        if threads::probe_futex_waiting(id) {
            return true;
        }
        sys::timer_set(&timer, sys::clock_now().expect("poll clock") + 1_000_000)
            .expect("poll deadline");
        sys::receive(&wake).expect("poll wake");
    }
    false
}

#[cfg(not(feature = "cancel-input"))]
static REUSED_SIGNALLED: AtomicUsize = AtomicUsize::new(0);

#[cfg(not(feature = "cancel-input"))]
unsafe extern "C" fn reused_signal(_: i32) {
    REUSED_SIGNALLED.fetch_add(1, Ordering::SeqCst);
}

/// Made after main was joined: waits up to 1 s for its signal, then
/// returns 0x55.
#[cfg(not(feature = "cancel-input"))]
unsafe extern "C" fn after_main(_: *mut c_void) -> *mut c_void {
    let pause = abi::metadata::Timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000,
    };
    for _ in 0..1000 {
        if REUSED_SIGNALLED.load(Ordering::SeqCst) != 0 {
            break;
        }
        let _ = unsafe { threads::sleep::nanosleep(&pause, ptr::null_mut()) };
    }
    0x55 as *mut c_void
}

#[cfg(not(feature = "cancel-input"))]
unsafe extern "C" fn last_thread(_: *mut c_void) -> *mut c_void {
    // Main exited through pthread_exit. Its join must still yield its value.
    let mut value = ptr::null_mut();
    let passed = unsafe { ffi::pthread_join(MAIN.load(Ordering::Acquire), &mut value) } == 0
        && value as usize == VALUE;
    if !passed || !specific::main_completed() {
        sys::process_exit(70);
    }
    // Files and allocation owners stay usable after main has ended.
    let block = unsafe { abi::allocation::malloc(64) };
    if block.is_null() {
        sys::process_exit(71);
    }
    unsafe { abi::allocation::free(block) };
    if unsafe { abi::open(c"/etc/motd".as_ptr(), O_RDONLY) } < 0 {
        sys::process_exit(72);
    }
    // A thread made after main was joined has a block of its own: its
    // signal and its value are its, not main's.
    let action = abi::signals::SigAction {
        handler: reused_signal as *const () as u64,
        mask: 0,
        flags: 0,
    };
    let mut reused = 0;
    let mut value = ptr::null_mut();
    if unsafe { abi::signals::sigaction(SIGUSR2, &action, ptr::null_mut()) } != 0
        || unsafe {
            ffi::pthread_create(&mut reused, ptr::null(), Some(after_main), ptr::null_mut())
        } != 0
        || ffi::pthread_kill(reused, SIGUSR2) != 0
        || unsafe { ffi::pthread_join(reused, &mut value) } != 0
        || value as usize != 0x55
        || REUSED_SIGNALLED.load(Ordering::SeqCst) != 1
    {
        rt::println!(
            "posix-thread-probe: after main, value {:#x}, signalled {}",
            value as usize,
            REUSED_SIGNALLED.load(Ordering::SeqCst)
        );
        sys::process_exit(73);
    }
    rt::println!("posix-thread-probe: main exit and last application thread ok");
    rt::println!("posix-thread-probe: ok");
    ptr::null_mut()
}

/// The channels that fill the table of handles (`fill_handles`).
#[cfg(not(feature = "cancel-input"))]
static HELD: [AtomicU64; 1024] = [const { AtomicU64::new(0) }; 1024];

/// The table of handles filled with channels until `channel_create`
/// fails; they close when it drops.
#[cfg(not(feature = "cancel-input"))]
struct Filled(usize);
#[cfg(not(feature = "cancel-input"))]
impl Filled {
    /// Whether the table filled before the room of HELD did.
    fn full(&self) -> bool {
        self.0 != 0 && self.0 != HELD.len()
    }
    /// Gives back the last channel.
    fn release_last(&mut self) {
        self.0 -= 1;
        let raw = HELD[self.0].swap(0, Ordering::Relaxed);
        drop(Handle::<Channel>::from_raw(rt::abi::Handle(raw)));
    }
}
#[cfg(not(feature = "cancel-input"))]
impl Drop for Filled {
    fn drop(&mut self) {
        while self.0 != 0 {
            self.release_last();
        }
    }
}
#[cfg(not(feature = "cancel-input"))]
fn fill_handles() -> Filled {
    let mut count = 0;
    while count < HELD.len() {
        let Ok(channel) = sys::channel_create(1) else {
            break;
        };
        HELD[count].store(channel.into_raw().0, Ordering::Relaxed);
        count += 1;
    }
    Filled(count)
}

/// Waits until the layer took back what the joined threads held (it does
/// so once the kernel says they ended): their places, handles and memory.
fn settle() -> bool {
    for _ in 0..1000 {
        abi::relibc::collect();
        if abi::relibc::occupied() == 1 {
            return true;
        }
        let _ = sys::yield_now();
    }
    false
}

fn failed(stage: usize) -> bool {
    rt::println!("posix-thread-probe: failed stage {}", stage);
    false
}

/// The holders of the locks of the heap and of the files run at the
/// process ceiling, which the init table puts one above main; the process
/// has no helper thread.
#[cfg(not(feature = "cancel-input"))]
fn priorities() -> bool {
    let main = MAIN_BASE.load(Ordering::Acquire) as u8;
    let me = unsafe { threads::probe_native(ffi::pthread_self()) }.expect("own handle");
    let level = || sys::thread_info(&me).map_or(0, |info| info.base);
    let (mut heap, mut files) = (0, 0);
    abi::allocation::probe_hold(|| heap = level());
    abi::shared::probe_hold(|| files = level());
    if heap != main + 1 || files != heap || level() != main {
        rt::println!(
            "posix-thread-probe: main {} heap {} files {}",
            main,
            heap,
            files
        );
        return failed(451);
    }
    rt::println!("priority-probe: heap and files at the ceiling above main, no helper thread");
    true
}

#[cfg(not(feature = "cancel-input"))]
fn run(clocks: &clocks::Peers, parent: &Handle<Channel>) -> bool {
    let expected = abi::process::client()
        .query()
        .expect("the snapshot of the process's record");
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 123 };
    if expected.pid < proto_process::RECORDS as u32
        || expected.parent != proto_process::INIT_PID
        || abi::process::getpid() != expected.pid as i32
        || abi::process::getppid() != expected.parent as i32
        || unsafe { *errno } != 123
    {
        return failed(450);
    }
    rt::println!(
        "process-identity-probe: Rust PID/PPID match the process service's record and preserve errno"
    );
    if !one_thread::run() {
        return false;
    }
    if !priorities() {
        return false;
    }
    if !credentials::run(parent) {
        return false;
    }
    let mut child = 0;
    let mut value = ptr::null_mut();
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 123 };
    if unsafe {
        ffi::pthread_create(
            &mut child,
            ptr::null(),
            Some(returning),
            VALUE as *mut c_void,
        )
    } != 0
        || unsafe { ffi::pthread_join(child, &mut value) } != 0
        || value as usize != VALUE
        || CALLS.load(Ordering::Acquire) != 1
        || unsafe { *errno } != 123
    {
        return failed(1);
    }
    rt::println!("posix-thread-probe: a joined thread gives its value and keeps errno");
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    if !settle() {
        return failed(2);
    }
    let _ = settle();
    let baseline = sys::process_handles(&process)
        .expect("handle baseline")
        .live;
    let mut held = fill_handles();
    if !held.full() {
        return failed(3);
    }
    // Leave one handle slot for the stack memory, forcing thread_create to
    // fail after the stack has actually been mapped by the real owner.
    held.release_last();
    let _ = settle();
    let occupied = sys::process_handles(&process)
        .expect("occupied handles")
        .live;
    let charged = sys::process_memory(&process)
        .expect("failure quota baseline")
        .used;
    child = 987;
    if unsafe { ffi::pthread_create(&mut child, ptr::null(), Some(returning), ptr::null_mut()) }
        != EAGAIN
        || child != 987
        || unsafe { *errno } != 123
        || sys::process_handles(&process)
            .expect("failure handles")
            .live
            != occupied
        || sys::process_memory(&process).expect("failure quota").used != charged
    {
        return failed(4);
    }
    drop(held);
    let _ = settle();
    let charged = sys::process_memory(&process)
        .expect("reuse quota baseline")
        .used;
    for index in 0..32 {
        if unsafe {
            ffi::pthread_create(
                &mut child,
                ptr::null(),
                Some(returning),
                (index + 1) as *mut c_void,
            )
        } != 0
            || unsafe { ffi::pthread_join(child, &mut value) } != 0
            || value as usize != index + 1
            || !settle()
            || sys::process_handles(&process).expect("reuse handles").live != baseline
            || sys::process_memory(&process).expect("reuse quota").used != charged
        {
            return failed(5);
        }
    }
    rt::println!("posix-thread-probe: failed creation and joined stacks restore handles and quota");

    let gate = sys::channel_create(1).expect("target gate");
    let mut target = 0;
    if unsafe {
        ffi::pthread_create(
            &mut target,
            ptr::null(),
            Some(gated),
            gate.raw().0 as *mut c_void,
        )
    } != 0
    {
        return failed(6);
    }
    TARGET.store(target, Ordering::Release);
    if unsafe { ffi::pthread_create(&mut child, ptr::null(), Some(joiner), ptr::null_mut()) } != 0 {
        return failed(7);
    }
    // The gate keeps the target live; the waiting joiner cannot finish yet.
    let native = unsafe { threads::probe_native(child) }.expect("live joiner handle");
    for _ in 0..3 {
        if !waiting(&native) || sys::thread_interrupt(&native).is_err() {
            return failed(8);
        }
        let _ = sys::yield_now();
        if JOINED.load(Ordering::Acquire) != 0 {
            return failed(9);
        }
    }
    if !waiting(&native) || sys::notify(&gate, 1).is_err() {
        return failed(10);
    }
    // Stop using the borrowed handle before allowing the joiner to terminate.
    if unsafe { ffi::pthread_join(child, &mut value) } != 0
        || value as usize != VALUE
        || JOINED.load(Ordering::Acquire) != 1
        || unsafe { *errno } != 123
    {
        return failed(11);
    }
    rt::println!("posix-thread-probe: live join interruption retries without EINTR");

    if !tcb::run()
        || !futex::run()
        || !blocks::run()
        || !heap_lock::run()
        || !long::run(parent)
        || !clocks::run(clocks)
        || !capacity::run()
        || !specific::run()
        || !once::run()
        || !mutex::run()
        || !timed::run()
        || !sleep::run()
        || !upcall::run()
        || !borrow_guards::run(parent)
        || !reentry::run()
        || !signals::run()
        || !signal_context::run()
        || !signal_wait::run()
        || !cancellation::run()
    {
        return false;
    }

    // A thread that ends past the library and that nobody joins: the
    // process still ends with its last application thread.
    let mut unjoined = 0;
    if unsafe {
        ffi::pthread_create(
            &mut unjoined,
            ptr::null(),
            Some(past_the_library),
            ptr::null_mut(),
        )
    } != 0
    {
        return failed(14);
    }
    if unsafe { ffi::pthread_create(&mut child, ptr::null(), Some(last_thread), ptr::null_mut()) }
        != 0
    {
        return failed(12);
    }
    // This call ends main only. The child verifies main's value and becomes the
    // last application thread; internal owners must not keep the process alive.
    unsafe { ffi::pthread_exit(VALUE as *mut c_void) }
}

/// The probe's C main, which relibc calls once posix-crt started the
/// process (files, clocks, heap, the process service) and relibc the
/// thread.
#[unsafe(no_mangle)]
extern "C" fn main(_: isize, _: *mut *mut c_char, _: *mut *mut c_char) -> c_int {
    #[cfg(not(feature = "cancel-input"))]
    let parent = posix_crt::parent();
    #[cfg(not(feature = "cancel-input"))]
    let Ok(clocks) = clocks::Peers::connect(&parent) else {
        return 5;
    };
    PROCESS.store(abi::allocation::process().raw().0, Ordering::Release);
    #[cfg(not(feature = "cancel-input"))]
    {
        let main = ffi::pthread_self();
        MAIN.store(main, Ordering::Release);
        let native = unsafe { threads::probe_native(main) }.expect("main's handle");
        MAIN_BASE.store(
            sys::thread_info(&native).map_or(0, |info| info.base as u64),
            Ordering::Release,
        );
    }
    #[cfg(feature = "cancel-input")]
    let passed = input::run();
    #[cfg(not(feature = "cancel-input"))]
    let passed = run(&clocks, &parent);
    if !passed {
        rt::println!("posix-thread-probe: failed");
        return 4;
    }
    0
}
