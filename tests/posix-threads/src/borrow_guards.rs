// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Deferred entries preserve interruptibility without overlapping local borrows.
use super::*;
use rt::{
    abi::Error,
    upcall,
    wait::{Waited, Waiter},
};
rt::upcall_entry!(entry, dispatch);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static MODE: AtomicUsize = AtomicUsize::new(0);
static READY: AtomicU64 = AtomicU64::new(0);
static GATE: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static RESULT: AtomicUsize = AtomicUsize::new(0);
fn native() -> core::mem::ManuallyDrop<Handle<Thread>> {
    Handle::borrowed(rt::abi::Handle(NATIVE.load(Ordering::Acquire)))
}
fn channel(raw: &AtomicU64) -> core::mem::ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(raw.load(Ordering::Acquire)))
}
fn poke() {
    sys::thread_upcall_request(&native()).unwrap();
}
unsafe extern "C" fn dispatch() {
    COUNT.fetch_add(1, Ordering::SeqCst);
    // Avoid creating the conflicting reference even in the broken-guard probe.
    if abi::shared::probe_local_borrow_live() {
        ERRORS.fetch_add(1, Ordering::Release);
        return;
    }
    if MODE.load(Ordering::Acquire) == 3 {
        let errno = unsafe { abi::__errno_location() };
        let saved = unsafe { *errno };
        let fd = unsafe { abi::open(c"/etc/motd".as_ptr(), O_RDONLY) };
        let mut byte = 0;
        if fd < 0 || unsafe { abi::read(fd, &mut byte, 1) } != 1 || unsafe { abi::close(fd) } != 0 {
            ERRORS.fetch_add(1, Ordering::Release);
        }
        unsafe { *errno = saved };
    }
}
fn simple() -> bool {
    let gate = sys::channel_create(10).unwrap();
    let outer = upcall::defer_entries().unwrap();
    let inner = upcall::defer_entries().unwrap();
    poke();
    poke();
    if COUNT.load(Ordering::Acquire) != 0
        || upcall::unbind() != Err(Error::BadState)
        || sys::receive(&gate) != Err(Error::Interrupted)
        || sys::try_receive(&gate) != Err(Error::WouldBlock)
    {
        return failed(340);
    }
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let handles = sys::process_handles(&process).unwrap().live;
    let moved = sys::channel_create(10).unwrap();
    match sys::send_handles(&gate, b"not queued", [moved.erase()]) {
        Err(refused) if refused.error == Error::Interrupted && refused.back.is_none() => (),
        _ => return failed(341),
    }
    if sys::process_handles(&process).unwrap().live != handles
        || sys::send(&gate, b"inline") != Err(Error::Interrupted)
        || sys::send(&gate, &[0x55; 80]) != Err(Error::Interrupted)
        || sys::try_receive(&gate) != Err(Error::WouldBlock)
    {
        return failed(342);
    }
    sys::notify(&gate, 1).unwrap();
    if sys::receive(&gate) != Err(Error::Interrupted)
        || !matches!(
            sys::try_receive(&gate),
            Ok(sys::Received::Notification { bits: 1, .. })
        )
    {
        return failed(343);
    }
    drop(inner);
    if COUNT.load(Ordering::Acquire) != 0 {
        return failed(344);
    }
    drop(outer);
    if COUNT.load(Ordering::Acquire) != 1 || upcall::mask() != Ok(false) {
        return failed(345);
    }
    let guard = upcall::defer_entries().unwrap();
    poke();
    drop(guard);
    if COUNT.load(Ordering::Acquire) != 1 || upcall::mask() != Ok(true) {
        return failed(346);
    }
    // A changed application mask remains changed after dropping the guard.
    let guard = upcall::defer_entries().unwrap();
    unsafe { upcall::enable() }.unwrap();
    if COUNT.load(Ordering::Acquire) != 1 || sys::receive(&gate) != Err(Error::Interrupted) {
        return failed(347);
    }
    upcall::mask().unwrap();
    drop(guard);
    if COUNT.load(Ordering::Acquire) != 1 {
        return failed(348);
    }
    unsafe { upcall::enable() }.unwrap();
    if COUNT.load(Ordering::Acquire) != 2 {
        return failed(349);
    }
    true
}
fn local(parent: &Handle<Channel>) -> bool {
    let id = threads::pthread_self();
    let outer_errno = unsafe { abi::__errno_location() };
    unsafe { *outer_errno = 777 };
    let mut files = PosixFs::connect(parent).unwrap();
    let result = tls::with_files(&mut files, || {
        let errno = unsafe { abi::__errno_location() };
        unsafe { *errno = 456 };
        for kind in [1, 2] {
            COUNT.store(0, Ordering::Release);
            abi::shared::probe_local_borrow(kind, &native());
            let value = if kind == 1 {
                let mut stat = core::mem::MaybeUninit::<abi::metadata::Stat>::uninit();
                // All bytes, including padding, are initialized and observed.
                // The failed stat must not publish a partial result.
                unsafe {
                    ptr::write_bytes(
                        stat.as_mut_ptr().cast::<u8>(),
                        0x55,
                        core::mem::size_of_val(&stat),
                    )
                };
                let status =
                    unsafe { abi::metadata::stat(c"/etc/motd".as_ptr(), stat.as_mut_ptr()) };
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        stat.as_ptr().cast::<u8>(),
                        core::mem::size_of_val(&stat),
                    )
                };
                if bytes.iter().any(|&byte| byte != 0x55) {
                    return failed(367);
                }
                status
            } else {
                unsafe { abi::open(c"/etc/motd".as_ptr(), O_RDONLY) }
            };
            if value != -1
                || unsafe { *errno } != EINTR
                || COUNT.load(Ordering::Acquire) != 1
                || ERRORS.load(Ordering::Acquire) != 0
                || abi::shared::probe_local_borrow_live()
            {
                return failed(350 + kind as usize);
            }
        }
        // No transport is needed for cwd; an already pending entry must wait
        // through this successful borrow too, and run before the C call returns.
        COUNT.store(0, Ordering::Release);
        abi::shared::probe_local_borrow(1, &native());
        let mut cwd = [0; 8];
        if unsafe { abi::getcwd(cwd.as_mut_ptr(), cwd.len()) }.is_null()
            || cwd[..2] != [b'/', 0]
            || COUNT.load(Ordering::Acquire) != 1
        {
            return failed(353);
        }
        let current = unsafe { abi::__errno_location() };
        tls::with_errno(|| {
            let nested = unsafe { abi::__errno_location() };
            unsafe { *nested = 901 };
            // Both early missing-context exits must balance their guard.
            assert_eq!(unsafe { abi::open(c"/etc/motd".as_ptr(), O_RDONLY) }, -1);
            assert_eq!(unsafe { *nested }, ENOSYS);
            let mut stat = core::mem::MaybeUninit::<abi::metadata::Stat>::uninit();
            assert_eq!(
                unsafe { abi::metadata::stat(c"/etc/motd".as_ptr(), stat.as_mut_ptr()) },
                -1
            );
            assert_eq!(unsafe { *nested }, ENOSYS);
            upcall::mask().unwrap();
            poke();
            // Scope transitions must not consume the caller's mask or pending entry.
        });
        if unsafe { abi::__errno_location() } != current || upcall::mask() != Ok(true) {
            return failed(354);
        }
        unsafe { upcall::enable() }.unwrap();
        if COUNT.load(Ordering::Acquire) != 2 {
            return failed(365);
        }
        let guard = upcall::defer_entries().unwrap();
        poke();
        tls::with_errno(|| {
            unsafe { *abi::__errno_location() = 902 };
            assert_eq!(COUNT.load(Ordering::Acquire), 2);
        });
        if unsafe { abi::__errno_location() } != current || COUNT.load(Ordering::Acquire) != 2 {
            return failed(366);
        }
        drop(guard);
        COUNT.load(Ordering::Acquire) == 3 && ERRORS.load(Ordering::Acquire) == 0
    });
    result
        && threads::pthread_self() == id
        && unsafe { abi::__errno_location() } == outer_errno
        && unsafe { *outer_errno } == 777
}
unsafe extern "C" fn worker(parent: *mut c_void) -> *mut c_void {
    let native_handle = unsafe { threads::probe_native(threads::pthread_self()) }.unwrap();
    NATIVE.store(native_handle.raw().0, Ordering::Release);
    unsafe { upcall::bind(entry) }.unwrap();
    unsafe { upcall::enable() }.unwrap();
    let passed = match MODE.load(Ordering::Acquire) {
        0 => simple(),
        1 | 2 => {
            let outer = upcall::defer_entries().unwrap();
            let inner = upcall::defer_entries().unwrap();
            sys::notify(&channel(&READY), 1).unwrap();
            // A receive is interrupted; a request the service accepted
            // gets its reply, and the entry waits for the deferrals.
            let interrupted = if MODE.load(Ordering::Acquire) == 1 {
                sys::receive(&channel(&GATE)) == Err(Error::Interrupted)
            } else {
                sys::send(&channel(&GATE), b"live wait").is_ok_and(|reply| reply.len == 4)
            };
            let before = COUNT.load(Ordering::Acquire) == 0;
            drop(inner);
            let nested = COUNT.load(Ordering::Acquire) == 0;
            drop(outer);
            interrupted && before && nested && COUNT.load(Ordering::Acquire) == 1
        }
        3 => local(&Handle::<Channel>::borrowed(rt::abi::Handle(parent as u64))),
        _ => false,
    };
    upcall::unbind().unwrap();
    RESULT.store(if passed { 1 } else { 2 }, Ordering::Release);
    sys::notify(&channel(&DONE), 1).unwrap();
    ptr::with_exposed_provenance_mut(usize::from(passed))
}
pub(super) fn run(parent: &Handle<Channel>) -> bool {
    let ready = sys::channel_create(30).unwrap();
    let gate = sys::channel_create(10).unwrap();
    let done = sys::channel_create(30).unwrap();
    let waiter = Waiter::new(&ready, 0, 30).unwrap();
    let done_waiter = Waiter::new(&done, 0, 30).unwrap();
    READY.store(ready.raw().0, Ordering::Release);
    GATE.store(gate.raw().0, Ordering::Release);
    DONE.store(done.raw().0, Ordering::Release);
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let handles = sys::process_handles(&process).unwrap().live;
    for mode in 0..4 {
        MODE.store(mode, Ordering::Release);
        COUNT.store(0, Ordering::Release);
        ERRORS.store(0, Ordering::Release);
        RESULT.store(0, Ordering::Release);
        let mut id = 0;
        let mut result = ptr::null_mut();
        if unsafe {
            threads::pthread_create(
                &mut id,
                ptr::null(),
                Some(worker),
                parent.raw().0 as *mut c_void,
            )
        } != 0
        {
            return failed(355);
        }
        if mode == 1 || mode == 2 {
            let now = || rt::time::ticks_to_ns(rt::time::now());
            if !matches!(
                waiter.receive_until(&ready, now() + 500_000_000),
                Ok(Waited::Got(_))
            ) {
                return failed(356);
            }
            let token = if mode == 2 {
                match sys::receive(&gate).unwrap() {
                    sys::Received::Message { token, .. } => Some(token),
                    _ => return failed(357),
                }
            } else {
                if !matches!(
                    waiter.receive_until(&ready, now() + 20_000_000),
                    Ok(Waited::Expired)
                ) || sys::thread_info(&native()).unwrap().state != ThreadState::Receiving
                {
                    return failed(358);
                }
                None
            };
            poke();
            if let Some(token) = token {
                // The request of the worker stays accepted through the
                // request of an entry: its reply goes (spec 6.1).
                let reply = token.reply(b"late");
                if reply != Ok(()) {
                    rt::println!("borrow-guard-probe: reply {:?}", reply);
                    return failed(359);
                }
            }
        }
        let deadline = rt::time::ticks_to_ns(rt::time::now()) + 500_000_000;
        if !matches!(
            done_waiter.receive_until(&done, deadline),
            Ok(Waited::Got(_))
        ) {
            return failed(369);
        }
        if unsafe { threads::pthread_join(id, &mut result) } != 0
            || result as usize != 1
            || RESULT.load(Ordering::Acquire) != 1
        {
            return failed(360 + mode);
        }
    }
    if sys::process_handles(&process).unwrap().live != handles {
        return failed(368);
    }
    rt::println!(
        "borrow-guard-probe: live/pending IPC, transfer consumption, nested masks, local file reentry and TLS scopes ok"
    );
    true
}
