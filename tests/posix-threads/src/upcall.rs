// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Native asynchronous entry, including a CPU-bound target and nested context.
use super::*;
use core::cell::UnsafeCell;
use rt::upcall;
use rt::wait::{Waited, Waiter};
core::arch::global_asm!(include_str!("upcall.S"), options(raw));
rt::upcall_entry!(entry, dispatch);
unsafe extern "C" {
    fn native_upcall_register_probe(output: *mut u64, state: *const AtomicU64);
}
struct Output(UnsafeCell<[u64; 106]>);
// SAFETY: only one joined worker writes OUTPUT; publication uses RESULT.
unsafe impl Sync for Output {}
static OUTPUT: Output = Output(UnsafeCell::new([0; 106]));
#[repr(C, align(16))]
struct State {
    seeded: AtomicU64,
    done: AtomicU64,
}
static STATE: State = State {
    seeded: AtomicU64::new(0),
    done: AtomicU64::new(0),
};
static MODE: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static DEEPEST: AtomicUsize = AtomicUsize::new(0);
static HANDLER_ID: AtomicU64 = AtomicU64::new(0);
static RESULT: AtomicUsize = AtomicUsize::new(0);
static READY: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static NATIVE: AtomicU64 = AtomicU64::new(0);
static GO: AtomicU64 = AtomicU64::new(0);
static GATE: AtomicU64 = AtomicU64::new(0);
fn channel(raw: &AtomicU64) -> core::mem::ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(raw.load(Ordering::Acquire)))
}
fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}
fn poke() {
    let target = Handle::<Thread>::borrowed(rt::abi::Handle(NATIVE.load(Ordering::Acquire)));
    sys::thread_upcall_request(&target).unwrap();
}
unsafe extern "C" fn dispatch() {
    HANDLER_ID.store(ffi::pthread_self(), Ordering::Release);
    let depth = ACTIVE.fetch_add(1, Ordering::SeqCst) + 1;
    DEEPEST.fetch_max(depth, Ordering::SeqCst);
    COUNT.fetch_add(1, Ordering::SeqCst);
    if MODE.load(Ordering::Acquire) == 1 && depth == 1 {
        unsafe { upcall::enable() }.unwrap();
        poke();
        assert_eq!(DEEPEST.load(Ordering::Acquire), 2);
        upcall::mask().unwrap();
    }
    if MODE.load(Ordering::Acquire) == 3 {
        let base = rt::abi::UPCALL_CONTEXT_OFFSET;
        let pc = dispatch as *const () as u64;
        let buffer = rt::msgbuf::address() as u64;
        for (sp, pc, flags, buffer) in [
            (0x2000u64, pc, 5u64, buffer),
            (0x2000, pc, 0x80, buffer),
            (0x2000, pc, 0, buffer + 4096),
            (0x2008, pc, 0, buffer),
            (0x2000, pc + 2, 0, buffer),
        ] {
            for (index, value) in [(31, sp), (32, pc), (33, flags), (35, buffer)] {
                rt::msgbuf::write(base + index * 8, &value.to_le_bytes());
            }
            let result =
                unsafe { sys::raw::<{ rt::abi::Call::ThreadUpcallReturn.number() }>([0; 10]) };
            assert_eq!(result[0], rt::abi::Error::InvalidArgs.code());
        }
    }
    rt::msgbuf::write(0, &[0xee; rt::abi::msgbuf::RESERVED]);
    ACTIVE.fetch_sub(1, Ordering::SeqCst);
    if depth == 1 {
        STATE.done.store(1, Ordering::Release);
        sys::notify(&channel(&DONE), 1).unwrap();
    }
    // Clobber caller-saved FP state and TLS after all Rust operations.
    unsafe {
        core::arch::asm!("movi v0.16b, #238", "movi v31.16b, #238",
        "mov x9, #0x400000", "msr fpcr, x9", "mov x9, #0", "msr fpsr, x9",
        "msr tpidr_el0, xzr", out("x9") _, out("v0") _, out("v31") _);
    }
}
unsafe extern "C" fn worker(_: *mut c_void) -> *mut c_void {
    unsafe { upcall::bind(entry) }.unwrap();
    let self_native = unsafe { threads::probe_native(ffi::pthread_self()) }.unwrap();
    NATIVE.store(self_native.raw().0, Ordering::Release);
    sys::thread_set_priority(&self_native, 10, rt::abi::Policy::Fifo).unwrap();
    // The launch notification leaves a boost until the next receive. End it
    // before running a CPU-bound FIFO loop so the parent's owner can reply.
    let drain = sys::channel_create(10).unwrap();
    assert_eq!(sys::try_receive(&drain), Err(rt::abi::Error::WouldBlock));
    drop(drain);
    let mode = MODE.load(Ordering::Acquire);
    if mode != 2 {
        unsafe { upcall::enable() }.unwrap();
    }
    rt::msgbuf::write(0, &[0x55; rt::abi::msgbuf::RESERVED]);
    sys::notify(&channel(&READY), 1).unwrap();
    let mut valid = true;
    if mode == 2 {
        while GO.load(Ordering::Acquire) == 0 {
            core::hint::spin_loop();
        }
        unsafe { upcall::enable() }.unwrap();
        valid &= STATE.done.load(Ordering::Acquire) == 1;
    } else if mode == 4 {
        valid &= sys::receive(&channel(&GATE)) == Err(rt::abi::Error::Interrupted);
        valid &= STATE.done.load(Ordering::Acquire) == 1;
    } else {
        // SAFETY: the probe retains OUTPUT and state; delivery preserves its registers.
        unsafe { native_upcall_register_probe((*OUTPUT.0.get()).as_mut_ptr(), &STATE.seeded) };
    }
    let mut bytes = [0; rt::abi::msgbuf::RESERVED];
    rt::msgbuf::read(0, &mut bytes);
    let output = unsafe { &*OUTPUT.0.get() };
    valid &= bytes.iter().all(|&v| v == 0x55);
    if mode != 2 && mode != 4 {
        for (index, &actual) in output[..31].iter().enumerate() {
            let expected = match index {
                9 => ptr::from_ref(&STATE.seeded) as u64,
                10 => 1,
                _ => 1000 + index as u64,
            };
            valid &= actual == expected;
        }
        valid &= output[31] == output[102]
            && output[32] == 0xa000_0000
            && output[33] == output[103]
            && output[34] == output[104];
        for index in 0..32 {
            let expected = u64::from_ne_bytes([index as u8 + 1; 8]);
            valid &= output[36 + index * 2] == expected && output[37 + index * 2] == expected;
        }
        valid &= output[100] == 0x800000 && output[101] == 1;
    }
    upcall::unbind().unwrap();
    RESULT.store(if valid { 1 } else { 2 }, Ordering::Release);
    sys::notify(&channel(&DONE), 1).unwrap();
    ptr::null_mut()
}
fn wait_flag(channel: &Handle<Channel>, waiter: &Waiter, flag: &AtomicUsize) -> bool {
    let limit = now() + 500_000_000;
    loop {
        if flag.load(Ordering::Acquire) != 0 {
            return true;
        }
        if !matches!(waiter.receive_until(channel, limit), Ok(Waited::Got(_))) {
            return false;
        }
    }
}
pub(super) fn run() -> bool {
    let ready = sys::channel_create(30).unwrap();
    let done = sys::channel_create(30).unwrap();
    let gate = sys::channel_create(10).unwrap();
    let waiter = Waiter::new(&done, 0, 30).unwrap();
    let ready_waiter = Waiter::new(&ready, 0, 30).unwrap();
    READY.store(ready.raw().0, Ordering::Release);
    DONE.store(done.raw().0, Ordering::Release);
    GATE.store(gate.raw().0, Ordering::Release);
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let _ = settle();
    let before_handles = sys::process_handles(&process).unwrap().live;
    let before_used = sys::process_memory(&process).unwrap().used;
    let inactive = unsafe { sys::raw::<{ rt::abi::Call::ThreadUpcallReturn.number() }>([0; 10]) };
    assert_eq!(inactive[0], rt::abi::Error::BadState.code());
    for mode in [0, 1, 2, 3, 4] {
        MODE.store(mode, Ordering::Release);
        COUNT.store(0, Ordering::Release);
        ACTIVE.store(0, Ordering::Release);
        DEEPEST.store(0, Ordering::Release);
        RESULT.store(0, Ordering::Release);
        STATE.seeded.store(0, Ordering::Release);
        STATE.done.store(0, Ordering::Release);
        GO.store(0, Ordering::Release);
        let mut id = 0;
        assert_eq!(
            unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(worker), ptr::null_mut()) },
            0
        );
        if !matches!(
            ready_waiter.receive_until(&ready, now() + 500_000_000),
            Ok(Waited::Got(_))
        ) {
            return failed(230);
        }
        // Retrieve the handle published before the CPU-bound phase. Asking
        // the base-priority-1 pthread owner now would starve behind this worker.
        let native = Handle::<Thread>::borrowed(rt::abi::Handle(NATIVE.load(Ordering::Acquire)));
        // Give the lower-priority worker time to seed the actual assembly loop.
        if !matches!(
            waiter.receive_until(&done, now() + 20_000_000),
            Ok(Waited::Expired)
        ) || STATE.seeded.load(Ordering::Acquire) != u64::from(mode != 2 && mode != 4)
            || COUNT.load(Ordering::Acquire) != 0
        {
            return failed(231);
        }
        let restricted = sys::handle_duplicate(&native, rt::abi::Rights::NONE).unwrap();
        if sys::thread_upcall_request(&restricted) != Err(rt::abi::Error::AccessDenied) {
            return failed(232);
        }
        drop(restricted);
        if mode == 4 && sys::thread_info(&native).unwrap().state != ThreadState::Receiving {
            return failed(235);
        }
        poke();
        if mode == 2 {
            poke();
            if !matches!(
                waiter.receive_until(&done, now() + 20_000_000),
                Ok(Waited::Expired)
            ) || COUNT.load(Ordering::Acquire) != 0
            {
                return failed(236);
            }
            GO.store(1, Ordering::Release);
        }
        if !wait_flag(&done, &waiter, &RESULT)
            || RESULT.load(Ordering::Acquire) != 1
            || HANDLER_ID.load(Ordering::Acquire) != id
            || COUNT.load(Ordering::Acquire) != if mode == 1 { 2 } else { 1 }
            || DEEPEST.load(Ordering::Acquire) != if mode == 1 { 2 } else { 1 }
        {
            return failed(233);
        }
        let mut result = ptr::null_mut();
        let retained = sys::handle_duplicate(&native, rt::abi::Rights::MANAGE).unwrap();
        if unsafe { ffi::pthread_join(id, &mut result) } != 0 {
            return failed(234);
        }
        if sys::thread_upcall_request(&retained) != Err(rt::abi::Error::BadState) {
            return failed(237);
        }
    }
    let _ = settle();
    if sys::process_handles(&process).unwrap().live != before_handles
        || sys::process_memory(&process).unwrap().used != before_used
    {
        return failed(238);
    }
    rt::println!(
        "native-upcall-probe: CPU/IPC entry, GPR/SIMD/flags/TLS/IPC restore, nesting, pending and privilege validation ok"
    );
    true
}
