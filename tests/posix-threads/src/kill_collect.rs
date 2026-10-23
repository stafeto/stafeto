// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `pthread_kill` takes no lock of the table, so its target's place is
//! pinned instead: the collector passes a pinned place over. The probe makes
//! the thread end inside the pin (the hook of `with_target`, after the block
//! was read) and calls `collect` there: the place must stay occupied, the
//! block unread-after-free, and the next `collect` after the call frees it.
//! Two targets: a detached thread of relibc (the row `collect` frees) and a
//! native thread that ends past the library (the row `collect_row` frees).
//!
//! The third case is the wait of `reserve`: with the table full and the
//! only collectable place pinned, `pthread_create` waits (it does not
//! return EAGAIN) and the release of the pin wakes it at once, not at the
//! 1 ms deadline that backs the wait. A thread of relibc calls
//! `pthread_create` inside the pin window of a `pthread_kill` of a thread
//! that ended, and the probe notes that the call has not returned after
//! 3 ms, that it succeeds after the pin goes, that the release woke it
//! (`probe_pin_wakes`) and how long the wait of `reserve` took to return
//! after it.
//!
//! The fourth case is the rollback of `pthread_create`: the start of the new
//! thread is refused after its place went LIVE (`probe_fail_start`). A
//! sender pins the place in that window (`pthread_kill` of the number the
//! start hook learned) and holds the pin until the creation waits for it
//! (`probe_pin_waited`); the creation must wait, return EAGAIN with the
//! process alive, and the sender must come out with 0 or ESRCH. A rollback
//! that does not wait unmaps the TCB under the sender, which faults in the
//! layer.
use super::*;
use rt::Stack;
use rt::abi::Policy;
use rt::handle::Channel;

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

/// Creates a thread on request: the third case's helper, a thread of
/// relibc that takes the table's last place while the target's is pinned.
static CREATE_GO: AtomicU64 = AtomicU64::new(0);
static CREATE_DONE: AtomicU64 = AtomicU64::new(0);
/// 0 while the call has not returned, 1 after a success, 2 + the error else.
static CREATE_STATE: AtomicU64 = AtomicU64::new(0);
static CREATE_STOP: AtomicU64 = AtomicU64::new(0);

fn create_channel(raw: &AtomicU64) -> core::mem::ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(raw.load(Ordering::Acquire)))
}

fn now() -> u64 {
    sys::clock_now().expect("kill-collect clock")
}

unsafe extern "C" fn quick(_: *mut c_void) -> *mut c_void {
    ptr::null_mut()
}

/// Calls `pthread_create` for each request, notes when and how it returned,
/// joins the thread it made, and reports on the done channel.
unsafe extern "C" fn creator(_: *mut c_void) -> *mut c_void {
    sys::notify(&ready(), 1).expect("kill-collect creator ready");
    loop {
        receive_through_interrupts(&create_channel(&CREATE_GO));
        if CREATE_STOP.load(Ordering::Acquire) != 0 {
            return ptr::null_mut();
        }
        let mut made = 0;
        let status =
            unsafe { ffi::pthread_create(&mut made, ptr::null(), Some(quick), ptr::null_mut()) };
        CREATE_STATE.store(
            if status == 0 { 1 } else { 2 + status as u64 },
            Ordering::SeqCst,
        );
        if status == 0 {
            let mut value = ptr::null_mut();
            unsafe { ffi::pthread_join(made, &mut value) };
        }
        sys::notify(&create_channel(&CREATE_DONE), 1).expect("kill-collect creator done");
    }
}

/// A relibc thread that fills a place until it is released.
unsafe extern "C" fn filler(_: *mut c_void) -> *mut c_void {
    sys::notify(&ready(), 1).expect("kill-collect filler ready");
    receive_through_interrupts(&create_channel(&FILL_RELEASE));
    ptr::null_mut()
}
static FILL_RELEASE: AtomicU64 = AtomicU64::new(0);

/// Inside the pin of `pthread_kill`: the target ends, the creator is asked
/// to make a thread (the table is full and the only place to take is
/// pinned), and the hook waits until the creation found the place pinned
/// and waits for it, then 3 ms more (#379: a fixed 3 ms let a slow host
/// release the pin before the creation came to it, with no wake to count).
extern "C" fn window_create(_: u64) {
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
    CREATE_STATE.store(0, Ordering::SeqCst);
    if sys::notify(&create_channel(&CREATE_GO), 1).is_err() {
        HOOK.store(4, Ordering::SeqCst);
        return;
    }
    let start = now();
    while !abi::relibc::probe_pin_waited() && now() - start < 10_000_000_000 {
        let _ = sys::yield_now();
    }
    if !abi::relibc::probe_pin_waited() {
        HOOK.store(7, Ordering::SeqCst);
        return;
    }
    let start = now();
    while now() - start < 3_000_000 {
        let _ = sys::yield_now();
    }
    HOOK.store(
        if CREATE_STATE.load(Ordering::SeqCst) == 0 {
            1
        } else {
            6
        },
        Ordering::SeqCst,
    );
}

/// Rounds of the third case, and the delay after the return of
/// `pthread_kill` that a wake keeps the creation under (the deadline that
/// backs the wait is 1 ms: without the wake the delay is spread over
/// 0 to 1 ms and most rounds are over this).
const ROUNDS: usize = 12;
const WOKEN_WITHIN_NS: u64 = 400_000;
/// Rounds that may be over the delay (a host that was busy for a moment).
const SLOW_ROUNDS_MAX: usize = 2;

/// The wait of `reserve` for a pinned place. Fails with the stage.
fn reserve_waits(base: usize) -> Result<(), usize> {
    const FILLERS: usize = abi::relibc::PLACES - 3;
    let ready_channel = ready();
    let create_go = sys::channel_create(30).expect("kill-collect create channel");
    let create_done = sys::channel_create(30).expect("kill-collect done channel");
    let fill_release = sys::channel_create(30).expect("kill-collect fill channel");
    CREATE_GO.store(create_go.raw().0, Ordering::Release);
    CREATE_DONE.store(create_done.raw().0, Ordering::Release);
    FILL_RELEASE.store(fill_release.raw().0, Ordering::Release);
    CREATE_STOP.store(0, Ordering::Release);
    let mut helper = 0;
    if unsafe { ffi::pthread_create(&mut helper, ptr::null(), Some(creator), ptr::null_mut()) } != 0
        || sys::receive(&ready_channel).is_err()
    {
        return Err(1812);
    }
    let mut fillers = [0; FILLERS];
    for filler_id in &mut fillers {
        if unsafe { ffi::pthread_create(filler_id, ptr::null(), Some(filler), ptr::null_mut()) }
            != 0
            || sys::receive(&ready_channel).is_err()
        {
            return Err(1813);
        }
    }
    let mut slow = 0;
    let mut longest = 0;
    for _ in 0..ROUNDS {
        // The target takes the last place: the table is full.
        HOOK.store(0, Ordering::SeqCst);
        let mut id = 0;
        if unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(waiting), ptr::null_mut()) } != 0
            || sys::receive(&ready_channel).is_err()
            || unsafe { ffi::pthread_detach(id) } != 0
        {
            return Err(1814);
        }
        if abi::relibc::occupied() != abi::relibc::PLACES {
            return Err(1815);
        }
        TARGET.store(id, Ordering::SeqCst);
        let wakes = abi::relibc::probe_pin_wakes();
        abi::relibc::probe_target_pin_window(Some(window_create));
        let status = ffi::pthread_kill(id, 0);
        if HOOK.load(Ordering::SeqCst) != 1 {
            rt::println!(
                "kill-collect: reserve: hook {} (1 expected, 6 is a creation that returned inside the pin: state {}, 7 one that never waited for it)",
                HOOK.load(Ordering::SeqCst),
                CREATE_STATE.load(Ordering::SeqCst)
            );
            return Err(1816);
        }
        if status != 0 && status != ESRCH {
            return Err(1817);
        }
        sys::receive(&create_done).expect("kill-collect creation done");
        if CREATE_STATE.load(Ordering::SeqCst) != 1 {
            return Err(1818);
        }
        if abi::relibc::probe_pin_wakes() != wakes + 1 {
            rt::println!(
                "kill-collect: reserve: {} wakes from the release of the pin (1 expected)",
                abi::relibc::probe_pin_wakes() - wakes
            );
            return Err(1819);
        }
        let delay = abi::relibc::probe_pin_wake_delay();
        longest = longest.max(delay);
        if delay > WOKEN_WITHIN_NS {
            slow += 1;
        }
    }
    if slow > SLOW_ROUNDS_MAX {
        rt::println!(
            "kill-collect: reserve: {slow} of {ROUNDS} creations came more than {WOKEN_WITHIN_NS} ns after the pin went (longest {longest} ns)"
        );
        return Err(1820);
    }
    rt::println!(
        "kill-collect: a pthread_create on a full table waited for the pinned place and woke at its release ({slow} of {ROUNDS} rounds over {WOKEN_WITHIN_NS} ns, longest {longest} ns)"
    );
    for _ in &fillers {
        sys::notify(&fill_release, 1).expect("kill-collect release a filler");
    }
    for filler_id in fillers {
        let mut value = ptr::null_mut();
        if unsafe { ffi::pthread_join(filler_id, &mut value) } != 0 {
            return Err(1821);
        }
    }
    CREATE_STOP.store(1, Ordering::Release);
    sys::notify(&create_go, 1).expect("kill-collect stop the creator");
    let mut value = ptr::null_mut();
    if unsafe { ffi::pthread_join(helper, &mut value) } != 0 || !crate::settled(base) {
        return Err(1822);
    }
    Ok(())
}

static RB_GO: AtomicU64 = AtomicU64::new(0);
static RB_PINNED: AtomicU64 = AtomicU64::new(0);
static RB_DONE: AtomicU64 = AtomicU64::new(0);
static RB_ID: AtomicU64 = AtomicU64::new(0);
static RB_STOP: AtomicU64 = AtomicU64::new(0);
/// 0 not run, 1 the creation waited for the pin, 2 it did not within 2 s.
static RB_HOOK: AtomicUsize = AtomicUsize::new(0);
static RB_STATUS: AtomicUsize = AtomicUsize::new(usize::MAX);

/// In the pin of the sender: tells the creator, then holds the pin until the
/// creation waits for it (or 2 s pass, which a rollback without the wait
/// spends after its unmap).
extern "C" fn rollback_window(_: u64) {
    sys::notify(&create_channel(&RB_PINNED), 1).expect("kill-collect rollback pinned");
    let start = now();
    while !abi::relibc::probe_pin_waited() && now() - start < 2_000_000_000 {
        let _ = sys::yield_now();
    }
    RB_HOOK.store(
        if abi::relibc::probe_pin_waited() {
            1
        } else {
            2
        },
        Ordering::SeqCst,
    );
}

/// The start hook of the creator, the new place LIVE and its thread not
/// started: lets the sender in and waits until it holds the pin.
extern "C" fn rollback_start(id: u64) {
    RB_ID.store(id, Ordering::SeqCst);
    sys::notify(&create_channel(&RB_GO), 1).expect("kill-collect rollback go");
    receive_through_interrupts(&create_channel(&RB_PINNED));
}

/// The sender: the layer's `pthread_kill` of the number the start hook named, with the
/// pin held by `rollback_window`.
unsafe extern "C" fn rollback_sender(_: *mut c_void) -> *mut c_void {
    sys::notify(&ready(), 1).expect("kill-collect sender ready");
    loop {
        receive_through_interrupts(&create_channel(&RB_GO));
        if RB_STOP.load(Ordering::Acquire) != 0 {
            return ptr::null_mut();
        }
        abi::relibc::probe_target_pin_window(Some(rollback_window));
        let status = abi::signals::kill_relibc_thread(RB_ID.load(Ordering::SeqCst), SIGUSR1);
        RB_STATUS.store(status as usize, Ordering::SeqCst);
        sys::notify(&create_channel(&RB_DONE), 1).expect("kill-collect sender done");
    }
}

/// The rollback of a refused start waits for the pin of a sender. Fails
/// with the stage.
fn rollback_waits(base: usize) -> Result<(), usize> {
    let ready_channel = ready();
    let go = sys::channel_create(30).expect("kill-collect rollback go channel");
    let pinned = sys::channel_create(30).expect("kill-collect rollback pinned channel");
    let done = sys::channel_create(30).expect("kill-collect rollback done channel");
    RB_GO.store(go.raw().0, Ordering::Release);
    RB_PINNED.store(pinned.raw().0, Ordering::Release);
    RB_DONE.store(done.raw().0, Ordering::Release);
    RB_STOP.store(0, Ordering::Release);
    let mut sender = 0;
    if unsafe {
        ffi::pthread_create(
            &mut sender,
            ptr::null(),
            Some(rollback_sender),
            ptr::null_mut(),
        )
    } != 0
        || sys::receive(&ready_channel).is_err()
    {
        return Err(1830);
    }
    for _ in 0..3 {
        RB_HOOK.store(0, Ordering::SeqCst);
        RB_STATUS.store(usize::MAX, Ordering::SeqCst);
        abi::relibc::probe_fail_start();
        abi::relibc::probe_start_window(Some(rollback_start));
        let mut made = 0;
        let status =
            unsafe { ffi::pthread_create(&mut made, ptr::null(), Some(quick), ptr::null_mut()) };
        abi::relibc::probe_start_window(None);
        sys::receive(&done).expect("kill-collect rollback done");
        if status != EAGAIN {
            rt::println!("kill-collect: rollback: pthread_create gave {status} (EAGAIN expected)");
            return Err(1831);
        }
        if RB_HOOK.load(Ordering::SeqCst) != 1 {
            rt::println!(
                "kill-collect: rollback: the creation did not wait for the pinned place ({})",
                RB_HOOK.load(Ordering::SeqCst)
            );
            return Err(1832);
        }
        let sent = RB_STATUS.load(Ordering::SeqCst);
        if sent != 0 && sent != ESRCH as usize {
            rt::println!("kill-collect: rollback: pthread_kill gave {sent}");
            return Err(1833);
        }
        // The place went back: a thread can be made and joined again.
        let mut again = 0;
        let mut value = ptr::null_mut();
        if unsafe { ffi::pthread_create(&mut again, ptr::null(), Some(quick), ptr::null_mut()) }
            != 0
            || unsafe { ffi::pthread_join(again, &mut value) } != 0
            || !crate::settled(base + 1)
        {
            return Err(1834);
        }
    }
    RB_STOP.store(1, Ordering::Release);
    sys::notify(&go, 1).expect("kill-collect stop the sender");
    let mut value = ptr::null_mut();
    if unsafe { ffi::pthread_join(sender, &mut value) } != 0 || !crate::settled(base) {
        return Err(1835);
    }
    rt::println!(
        "kill-collect: a refused start rolled back after waiting for the sender that pinned the place (3 rounds)"
    );
    Ok(())
}

pub(super) fn run() -> bool {
    let gate_channel = sys::channel_create(30).expect("kill-collect gate");
    let ready_channel = sys::channel_create(30).expect("kill-collect ready channel");
    GATE.store(gate_channel.raw().0, Ordering::Release);
    READY.store(ready_channel.raw().0, Ordering::Release);
    if !crate::settled(1) {
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
    if !crate::settled(base) {
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
    if !crate::settled(base) {
        return failed(1811);
    }
    rt::println!(
        "kill-collect: a thread that ended inside pthread_kill kept its place until the call returned (relibc and native rows)"
    );
    if let Err(stage) = reserve_waits(base) {
        return failed(stage);
    }
    if let Err(stage) = rollback_waits(base) {
        return failed(stage);
    }
    true
}
