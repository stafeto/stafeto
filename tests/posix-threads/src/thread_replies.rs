// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Nested native owner queries must not evict committed lifecycle replies.
use super::*;
use core::cell::UnsafeCell;
rt::upcall_entry!(entry, dispatch);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static DEPTH: AtomicUsize = AtomicUsize::new(0);
static HANDLERS: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static CREATED: AtomicUsize = AtomicUsize::new(0);
static MODE: AtomicUsize = AtomicUsize::new(0);
static QUERY_KEY: AtomicU64 = AtomicU64::new(0);
struct Held(UnsafeCell<[Option<Handle<Channel>>; 128]>);
// SAFETY: one pressure worker writes; main accesses only after join and an
// acquire of PRESSURE_DONE. No other probe touches these owned handles.
unsafe impl Sync for Held {}
static HELD: Held = Held(UnsafeCell::new([const { None }; 128]));
static PRESSURE_GO: AtomicU64 = AtomicU64::new(0);
static PRESSURE_KEY: AtomicU64 = AtomicU64::new(0);
static PRESSURE_DONE: AtomicUsize = AtomicUsize::new(0);
static DESTROYED: AtomicUsize = AtomicUsize::new(0);
unsafe extern "C" fn dispatch() {
    let depth = DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
    HANDLERS.fetch_add(1, Ordering::SeqCst);
    let errno = unsafe { abi::__errno_location() };
    let saved = unsafe { *errno };
    let key_mode = MODE.load(Ordering::Acquire) == 1;
    if depth == 1 {
        threads::probe_reply_upcall(if key_mode { 11 } else { 6 });
        unsafe { rt::upcall::enable() }.unwrap();
    } else {
        threads::probe_ack_interrupt();
    }
    let passed = if key_mode {
        let key = QUERY_KEY.load(Ordering::Acquire);
        let value = threads::specific::pthread_getspecific(key);
        let updated = depth != 2
            || threads::specific::pthread_setspecific(key, (VALUE + 1) as *const c_void) == 0;
        value as usize == VALUE && updated
    } else {
        let result = unsafe { threads::probe_native(threads::pthread_self()) };
        result.is_ok_and(|handle| handle.raw().0 == NATIVE.load(Ordering::Acquire))
    };
    if !passed || unsafe { *errno } != saved {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    rt::upcall::mask().unwrap();
    unsafe { *errno = saved };
    DEPTH.fetch_sub(1, Ordering::SeqCst);
}
unsafe extern "C" fn child(argument: *mut c_void) -> *mut c_void {
    CREATED.fetch_add(1, Ordering::AcqRel);
    argument
}
unsafe extern "C" fn worker(_: *mut c_void) -> *mut c_void {
    let native = unsafe { threads::probe_native(threads::pthread_self()) }.unwrap();
    NATIVE.store(native.raw().0, Ordering::Release);
    let errno = unsafe { abi::__errno_location() };
    unsafe { *errno = 777 };
    unsafe { rt::upcall::bind(entry) }.unwrap();
    unsafe { rt::upcall::enable() }.unwrap();
    let before_ack = threads::probe_ack_interrupts();
    threads::probe_reply_upcall(1);
    let mut id = 0;
    if unsafe { threads::pthread_create(&mut id, ptr::null(), Some(child), VALUE as *mut c_void) }
        != 0
        || HANDLERS.load(Ordering::Acquire) != 2
    {
        failed(280);
        return ptr::null_mut();
    }
    threads::probe_reply_upcall(3);
    let mut value = ptr::null_mut();
    if unsafe { threads::pthread_join(id, &mut value) } != 0
        || value as usize != VALUE
        || CREATED.load(Ordering::Acquire) != 1
        || HANDLERS.load(Ordering::Acquire) != 4
        || ERRORS.load(Ordering::Acquire) != 0
        || DEPTH.load(Ordering::Acquire) != 0
        || unsafe { *errno } != 777
        || threads::probe_ack_interrupts() != before_ack + 2
    {
        failed(281);
        return ptr::null_mut();
    }
    let mut key = 0;
    if unsafe { threads::specific::pthread_key_create(&mut key, None) } != 0
        || threads::specific::pthread_setspecific(key, VALUE as *const c_void) != 0
    {
        return ptr::null_mut();
    }
    QUERY_KEY.store(key, Ordering::Release);
    MODE.store(1, Ordering::Release);
    threads::probe_reply_upcall(11);
    if threads::specific::pthread_getspecific(key) as usize != VALUE
        || HANDLERS.load(Ordering::Acquire) != 6
        || ERRORS.load(Ordering::Acquire) != 0
        || threads::probe_ack_interrupts() != before_ack + 3
        || threads::specific::pthread_getspecific(key) as usize != VALUE + 1
    {
        failed(296);
        return ptr::null_mut();
    }
    rt::upcall::mask().unwrap();
    rt::upcall::unbind().unwrap();
    MODE.store(0, Ordering::Release);
    if threads::specific::pthread_key_delete(key) != 0 {
        return ptr::null_mut();
    }
    if !reservation_failure() {
        return ptr::null_mut();
    }
    ptr::dangling_mut::<c_void>()
}

fn reservation_failure() -> bool {
    fn available_keys() -> usize {
        let mut keys = [0; PTHREAD_KEYS_MAX as usize];
        let mut count = 0;
        while count < keys.len() {
            let status = unsafe { threads::specific::pthread_key_create(&mut keys[count], None) };
            if status == EAGAIN {
                break;
            }
            assert_eq!(status, 0);
            count += 1;
        }
        for key in &keys[..count] {
            assert_eq!(threads::specific::pthread_key_delete(*key), 0);
        }
        count
    }
    let key_capacity = available_keys();
    let mut held: [Option<Handle<Channel>>; 128] = core::array::from_fn(|_| None);
    let mut handles = 0;
    while handles < held.len() {
        let Ok(channel) = sys::channel_create(1) else {
            break;
        };
        held[handles] = Some(channel);
        handles += 1;
    }
    if handles == 0 || handles == held.len() {
        return failed(286);
    }
    let mut nonces = [0; 2000];
    let mut count = 0;
    while count < nonces.len() {
        match threads::probe_leave_reply() {
            Ok(nonce) => {
                nonces[count] = nonce;
                count += 1;
            }
            Err(ENOMEM) => break,
            _ => return failed(287),
        }
    }
    if count < 400 || count == nonces.len() {
        return failed(288);
    }
    let before = CREATED.load(Ordering::Acquire);
    let mut id = 999;
    if unsafe { threads::pthread_create(&mut id, ptr::null(), Some(child), ptr::null_mut()) }
        != EAGAIN
        || id != 999
        || CREATED.load(Ordering::Acquire) != before
    {
        return failed(289);
    }
    // Key creation needs no new kernel handle, so its capacity proves that
    // a refused journal reservation did not leave an unreported side effect.
    let mut key = 999;
    if unsafe { threads::specific::pthread_key_create(&mut key, None) } != ENOMEM || key != 999 {
        return failed(291);
    }
    for nonce in &nonces[..count] {
        if threads::probe_release_reply(*nonce).is_err() {
            return failed(290);
        }
    }
    drop(held);
    if available_keys() != key_capacity {
        return failed(292);
    }
    rt::println!(
        "thread-reply-probe: reservation failure precedes CREATE, Ack needs no allocation"
    );
    true
}
pub(super) fn run() -> bool {
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let handles = sys::process_handles(&process).unwrap().live;
    let used = sys::process_memory(&process).unwrap().used;
    let mut id = 0;
    let mut value = ptr::null_mut();
    if unsafe { threads::pthread_create(&mut id, ptr::null(), Some(worker), ptr::null_mut()) } != 0
        || unsafe { threads::pthread_join(id, &mut value) } != 0
        || value as usize != 1
    {
        return failed(282);
    }
    // More than a chunk of transactions proves released records are reused.
    for _ in 0..2000 {
        if unsafe { threads::probe_native(threads::pthread_self()) }.is_err() {
            return failed(283);
        }
    }
    if sys::process_handles(&process).unwrap().live != handles
        || sys::process_memory(&process).unwrap().used != used
    {
        return failed(283);
    }
    for _ in 0..1000 {
        if unsafe { threads::pthread_create(&mut id, ptr::null(), Some(orphan), ptr::null_mut()) }
            != 0
            || unsafe { threads::pthread_join(id, &mut value) } != 0
            || value as usize != 1
        {
            return failed(284);
        }
    }
    if sys::process_handles(&process).unwrap().live != handles
        || sys::process_memory(&process).unwrap().used != used
    {
        return failed(285);
    }
    if !exit_under_pressure()
        || sys::process_handles(&process).unwrap().live != handles
        || sys::process_memory(&process).unwrap().used != used
    {
        return failed(295);
    }
    rt::println!(
        "thread-reply-probe: nested queries retain CREATE/JOIN identity, one callback, Ack and quota"
    );
    true
}

unsafe extern "C" fn orphan(_: *mut c_void) -> *mut c_void {
    usize::from(threads::probe_leave_reply().is_ok()) as *mut c_void
}

unsafe extern "C" fn destructor(value: *mut c_void) {
    if value as usize == VALUE {
        DESTROYED.fetch_add(1, Ordering::Release);
    }
}
unsafe extern "C" fn pressure(_: *mut c_void) -> *mut c_void {
    let gate = Handle::<Channel>::borrowed(rt::abi::Handle(PRESSURE_GO.load(Ordering::Acquire)));
    sys::receive(&gate).unwrap();
    if threads::specific::pthread_setspecific(
        PRESSURE_KEY.load(Ordering::Acquire),
        VALUE as *const c_void,
    ) != 0
    {
        return ptr::null_mut();
    }
    // SAFETY: this worker uniquely owns HELD until its joined completion.
    let held = unsafe { &mut *HELD.0.get() };
    for slot in held.iter_mut() {
        let Ok(channel) = sys::channel_create(1) else {
            break;
        };
        *slot = Some(channel);
    }
    let mut count = 0;
    while count < 2000 {
        match threads::probe_leave_reply() {
            Ok(_) => count += 1,
            Err(ENOMEM) => break,
            _ => return ptr::null_mut(),
        }
    }
    if !(400..2000).contains(&count) {
        return ptr::null_mut();
    }
    PRESSURE_DONE.store(1, Ordering::Release);
    // Neither TAKE nor EXIT may need a new journal node at this point.
    ptr::dangling_mut::<c_void>()
}
fn exit_under_pressure() -> bool {
    let gate = sys::channel_create(30).unwrap();
    let wake = sys::channel_create(30).unwrap();
    let timer = sys::timer_create(&wake, 30).unwrap();
    let mut key = 0;
    if unsafe { threads::specific::pthread_key_create(&mut key, Some(destructor)) } != 0 {
        return failed(293);
    }
    PRESSURE_GO.store(gate.raw().0, Ordering::Release);
    PRESSURE_KEY.store(key, Ordering::Release);
    let mut id = 0;
    if unsafe { threads::pthread_create(&mut id, ptr::null(), Some(pressure), ptr::null_mut()) }
        != 0
    {
        return failed(293);
    }
    let native = unsafe { threads::probe_native(id) }.unwrap();
    let retained = sys::handle_duplicate(&native, rt::abi::Rights::MANAGE).unwrap();
    sys::notify(&gate, 1).unwrap();
    let deadline = sys::clock_now().unwrap() + 5_000_000_000;
    while sys::thread_info(&retained).unwrap().state != ThreadState::Ended {
        let now = sys::clock_now().unwrap();
        if now >= deadline {
            return failed(294);
        }
        sys::timer_set(&timer, now + 1_000_000).unwrap();
        sys::receive(&wake).unwrap();
    }
    let mut value = ptr::null_mut();
    if unsafe { threads::pthread_join(id, &mut value) } != 0
        || value as usize != 1
        || PRESSURE_DONE.load(Ordering::Acquire) != 1
        || DESTROYED.load(Ordering::Acquire) != 1
    {
        return failed(294);
    }
    // SAFETY: joined completion and publication end the worker's sole ownership.
    for slot in unsafe { &mut *HELD.0.get() } {
        *slot = None;
    }
    if threads::specific::pthread_key_delete(key) != 0 {
        return failed(294);
    }
    rt::println!(
        "thread-reply-probe: full journal permits destructor, managed exit and caller reclamation"
    );
    true
}
