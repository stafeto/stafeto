// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `pthread_kill` takes no lock of the table, so its target's place is
//! pinned instead: the collector passes a pinned place over. The probe makes
//! the thread end inside the pin (the hook of `with_target`, after the block
//! was read) and calls `collect` there: the place must stay occupied, the
//! block unread-after-free, and the next `collect` after the call frees it.
//! Two targets: a detached thread of relibc (the row `collect` frees) and a
//! native thread that ends past the library (the row `collect_row` frees).
use super::*;
use rt::Stack;
use rt::abi::Policy;

static GATE: AtomicU64 = AtomicU64::new(0);
static READY: AtomicU64 = AtomicU64::new(0);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static NATIVE_ID: AtomicU64 = AtomicU64::new(0);
static STACK: Stack<16384> = Stack::new();
/// Set by the hook: 0 not run, 1 target ended and place kept, 2 the place
/// was freed inside the pin, 3 no handle, 4 no gate, 5 the target did not end.
static HOOK: AtomicUsize = AtomicUsize::new(0);
static HOOK_BEFORE: AtomicUsize = AtomicUsize::new(0);
static HOOK_ID: AtomicU64 = AtomicU64::new(0);
static TARGET: AtomicU64 = AtomicU64::new(0);

fn gate() -> core::mem::ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(GATE.load(Ordering::Acquire)))
}
fn ready() -> core::mem::ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(READY.load(Ordering::Acquire)))
}

fn receive_through_interrupts(channel: &Handle<Channel>) {
    loop {
        match sys::receive(channel) {
            Err(rt::abi::Error::Interrupted) => continue,
            result => {
                result.expect("kill-collect receive");
                return;
            }
        }
    }
}

/// A relibc thread that waits for the gate and ends.
unsafe extern "C" fn waiting(_: *mut c_void) -> *mut c_void {
    sys::notify(&ready(), 1).expect("kill-collect ready");
    receive_through_interrupts(&gate());
    ptr::null_mut()
}

/// A native thread: the layer made its place when it first used the library.
extern "C" fn native_worker(_: u64) -> ! {
    abi::tls::with_process(|| NATIVE_ID.store(ffi::pthread_self(), Ordering::SeqCst));
    sys::notify(&ready(), 1).expect("kill-collect native ready");
    receive_through_interrupts(&gate());
    sys::thread_exit()
}

/// Runs inside `with_target` with the place pinned: lets the target end,
/// collects, and notes whether the place stayed.
extern "C" fn window(id: u64) {
    // `id` is the number of the place; the pthread is in TARGET.
    HOOK_ID.store(id, Ordering::SeqCst);
    let before = abi::relibc::occupied();
    HOOK_BEFORE.store(before, Ordering::SeqCst);
    // SAFETY: the pthread is live and pinned.
    let Ok(native) = (unsafe { threads::probe_native(TARGET.load(Ordering::SeqCst)) }) else {
        HOOK.store(3, Ordering::SeqCst);
        return;
    };
    if sys::notify(&gate(), 1).is_err() {
        HOOK.store(4, Ordering::SeqCst);
        return;
    }
    let mut ended = false;
    for _ in 0..100_000 {
        if sys::thread_info(&native).is_ok_and(|info| info.state == ThreadState::Ended) {
            ended = true;
            break;
        }
        let _ = sys::yield_now();
    }
    if !ended {
        HOOK.store(5, Ordering::SeqCst);
        return;
    }
    // The thread has ended, was released and nobody freed its place: only
    // the pin keeps it.
    abi::relibc::collect();
    abi::relibc::collect();
    HOOK.store(
        if abi::relibc::occupied() == before {
            1
        } else {
            2
        },
        Ordering::SeqCst,
    );
}

fn settled(expected: usize) -> bool {
    for _ in 0..1000 {
        abi::relibc::collect();
        if abi::relibc::occupied() == expected {
            return true;
        }
        let _ = sys::yield_now();
    }
    false
}

pub(super) fn run() -> bool {
    let gate_channel = sys::channel_create(30).expect("kill-collect gate");
    let ready_channel = sys::channel_create(30).expect("kill-collect ready channel");
    GATE.store(gate_channel.raw().0, Ordering::Release);
    READY.store(ready_channel.raw().0, Ordering::Release);
    if !settled(1) {
        return failed(1801);
    }
    let base = abi::relibc::occupied();

    // A detached thread of relibc.
    HOOK.store(0, Ordering::SeqCst);
    let mut id = 0;
    if unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(waiting), ptr::null_mut()) } != 0 {
        return failed(1802);
    }
    if sys::receive(&ready_channel).is_err() || unsafe { ffi::pthread_detach(id) } != 0 {
        return failed(1803);
    }
    TARGET.store(id, Ordering::SeqCst);
    abi::relibc::probe_target_pin_window(Some(window));
    let status = ffi::pthread_kill(id, 0);
    if HOOK.load(Ordering::SeqCst) != 1 {
        rt::println!(
            "kill-collect: relibc target: hook {} (1 expected), occupied {} before",
            HOOK.load(Ordering::SeqCst),
            HOOK_BEFORE.load(Ordering::SeqCst)
        );
        return failed(1804);
    }
    // No fault, no stale answer: the call lived through the end of its target.
    if status != 0 && status != ESRCH {
        return failed(1805);
    }
    if !settled(base) {
        return failed(1806);
    }

    // A native thread.
    HOOK.store(0, Ordering::SeqCst);
    let main = unsafe { threads::probe_native(ffi::pthread_self()) }.expect("main identity");
    let level = sys::thread_info(&main).expect("main priority").base;
    let native = unsafe {
        sys::thread_create_with(
            abi::allocation::process(),
            native_worker,
            STACK.top(),
            0,
            level,
            Policy::Fifo,
            0xe00000,
            None,
        )
    }
    .expect("kill-collect native create");
    NATIVE.store(native.raw().0, Ordering::SeqCst);
    if sys::thread_start(&native).is_err() || sys::receive(&ready_channel).is_err() {
        return failed(1807);
    }
    let native_id = NATIVE_ID.load(Ordering::SeqCst);
    if native_id == 0 || abi::relibc::occupied() != base + 1 {
        return failed(1808);
    }
    TARGET.store(native_id, Ordering::SeqCst);
    abi::relibc::probe_target_pin_window(Some(window));
    let status = ffi::pthread_kill(native_id, 0);
    if HOOK.load(Ordering::SeqCst) != 1 {
        rt::println!(
            "kill-collect: native target: hook {} (1 expected), occupied {} before",
            HOOK.load(Ordering::SeqCst),
            HOOK_BEFORE.load(Ordering::SeqCst)
        );
        return failed(1809);
    }
    if status != 0 && status != ESRCH {
        return failed(1810);
    }
    if !settled(base) {
        return failed(1811);
    }
    rt::println!(
        "kill-collect: a thread that ended inside pthread_kill kept its place until the call returned (relibc and native rows)"
    );
    true
}
