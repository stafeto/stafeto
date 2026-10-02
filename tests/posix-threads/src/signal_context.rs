// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Read and edit a real interrupted CPU loop, including nested signal contexts.
use super::*;
use crate::layer::signals::{self as api, LinuxContext, LinuxSigInfo, SigAction};
use core::cell::UnsafeCell;
use rt::wait::{Waited, Waiter};
unsafe extern "C" {
    fn native_upcall_register_probe(output: *mut u64, state: *const AtomicU64);
    static native_upcall_loop: u8;
    static native_upcall_resume: u8;
    static native_upcall_redirect: u8;
}
struct Output(UnsafeCell<[u64; 106]>);
// SAFETY: one worker writes OUTPUT, published before join using RESULT.
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
static ERRORS: AtomicUsize = AtomicUsize::new(0);
static DEPTH: AtomicUsize = AtomicUsize::new(0);
static OUTER_SP: AtomicU64 = AtomicU64::new(0);
static DONE: AtomicU64 = AtomicU64::new(0);
static RESULT: AtomicUsize = AtomicUsize::new(0);
fn bit(signal: i32) -> u64 {
    1 << (signal - 1)
}
fn now() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}
fn channel(raw: &AtomicU64) -> core::mem::ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(rt::abi::Handle(raw.load(Ordering::Acquire)))
}
unsafe extern "C" fn handler(signal: i32, info: *mut LinuxSigInfo, context: *mut c_void) {
    let depth = DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
    COUNT.fetch_add(1, Ordering::SeqCst);
    let mode = MODE.load(Ordering::Acquire);
    // SAFETY: the SA_SIGINFO dispatcher owns these live per-entry objects.
    let (info, context) = unsafe { (&*info, &mut *context.cast::<LinuxContext>()) };
    let mut effective = 0;
    let mut valid = signal == SIGUSR1
        && *info == LinuxSigInfo::thread(SIGUSR1)
        && context.link.is_null()
        && context.stack_pointer.is_null()
        && context.stack_size == 0
        && context.stack_flags == SS_DISABLE
        && unsafe { api::pthread_sigmask(-99, ptr::null(), &mut effective) } == 0
        && effective == bit(SIGPIPE) | bit(SIGUSR2) | if mode == 2 { 0 } else { bit(SIGUSR1) }
        && context.mask == bit(SIGPIPE) | if depth == 2 { bit(SIGUSR2) } else { 0 };
    if depth == 1 {
        OUTER_SP.store(context.sp, Ordering::Release);
        let expected_sp = unsafe { (*OUTPUT.0.get())[102] };
        valid &= context.sp == expected_sp
            && context.pc >= ptr::addr_of!(native_upcall_loop) as u64
            && context.pc < ptr::addr_of!(native_upcall_resume) as u64
            && context.pstate == 0xa000_0000
            && context.fpcr == 0x800000
            && context.fpsr == 1;
        for (index, &register) in context.registers.iter().enumerate() {
            valid &= if index == 9 {
                register == ptr::from_ref(&STATE.seeded) as u64
            } else if index == 10 {
                register <= 1
            } else {
                register == 1000 + index as u64
            };
        }
        for (index, &vector) in context.vectors.iter().enumerate() {
            valid &= vector == u128::from_ne_bytes([index as u8 + 1; 16]);
        }
        if mode == 1 {
            context.registers[0] = 0xfeed;
            context.registers[1] = 0xfeed;
            context.registers[10] = 1;
            context.pc = ptr::addr_of!(native_upcall_redirect) as u64;
            context.pstate = 0x6000_0000;
            context.vectors[31] = u128::from_ne_bytes([0x77; 16]);
            context.fpcr = 0;
            context.fpsr = 0;
            context.mask = bit(SIGTERM) | bit(SIGKILL);
        }
        if mode == 2 {
            let saved_pc = context.pc;
            valid &= api::raise(SIGUSR1) == 0
                && COUNT.load(Ordering::Acquire) == 2
                && context.pc == saved_pc
                && context.sp == OUTER_SP.load(Ordering::Acquire);
        }
        if mode == 3 {
            let mut old = posix_signals::INITIAL;
            valid &= unsafe { api::sigaction(SIGUSR1, ptr::null(), &mut old) } == 0
                && old.handler == api::DEFAULT
                && old.flags & SA_SIGINFO == 0;
        }
    } else {
        valid &= mode == 2 && depth == 2 && context.sp < OUTER_SP.load(Ordering::Acquire);
    }
    // A real asynchronous handler also performs required signal-safe file I/O.
    let fd = unsafe { ffi::open(c"/etc/motd".as_ptr(), O_RDONLY) };
    let mut byte = 0;
    valid &= fd >= 0
        && unsafe { ffi::read(fd, &mut byte, 1) } == 1
        && byte == b's'
        && unsafe { ffi::close(fd) } == 0;
    if !valid {
        ERRORS.fetch_add(1, Ordering::Release);
    }
    unsafe { *ffi::__errno_location() = 901 };
    DEPTH.fetch_sub(1, Ordering::SeqCst);
    if depth == 1 {
        STATE.done.store(1, Ordering::Release);
    }
}
unsafe extern "C" fn worker(_: *mut c_void) -> *mut c_void {
    let native = unsafe { threads::probe_native(ffi::pthread_self()) }.unwrap();
    sys::thread_set_priority(&native, 10, rt::abi::Policy::Fifo).unwrap();
    let drain = sys::channel_create(10).unwrap();
    assert_eq!(sys::try_receive(&drain), Err(rt::abi::Error::WouldBlock));
    drop(drain);
    unsafe { *ffi::__errno_location() = 777 };
    // SAFETY: one worker owns this retained output during the assembly call.
    unsafe { native_upcall_register_probe((*OUTPUT.0.get()).as_mut_ptr(), &STATE.seeded) };
    let mode = MODE.load(Ordering::Acquire);
    let output = unsafe { &*OUTPUT.0.get() };
    let mut mask = 0;
    let mut valid = unsafe { api::pthread_sigmask(-99, ptr::null(), &mut mask) } == 0
        && mask
            == if mode == 1 {
                bit(SIGTERM)
            } else {
                bit(SIGPIPE)
            }
        && COUNT.load(Ordering::Acquire) == if mode == 2 { 2 } else { 1 }
        && ERRORS.load(Ordering::Acquire) == 0
        && DEPTH.load(Ordering::Acquire) == 0
        && unsafe { *ffi::__errno_location() } == 777;
    for (index, &actual) in output[..31].iter().enumerate() {
        let expected = match index {
            0 if mode == 1 => 0xf00d,
            1 if mode == 1 => 0xfeed,
            9 => ptr::from_ref(&STATE.seeded) as u64,
            10 => 1,
            _ => 1000 + index as u64,
        };
        valid &= actual == expected;
    }
    valid &= output[31] == output[102]
        && output[32] == if mode == 1 { 0x6000_0000 } else { 0xa000_0000 }
        && output[33] == output[103]
        && output[34] == output[104]
        && output[100] == if mode == 1 { 0 } else { 0x800000 }
        && output[101] == u64::from(mode != 1);
    for index in 0..32 {
        let value = if mode == 1 && index == 31 {
            0x77
        } else {
            index as u8 + 1
        };
        let expected = u64::from_ne_bytes([value; 8]);
        valid &= output[36 + index * 2] == expected && output[37 + index * 2] == expected;
    }
    RESULT.store(if valid { 1 } else { 2 }, Ordering::Release);
    sys::notify(&channel(&DONE), 1).unwrap();
    ptr::null_mut()
}
pub(super) fn run() -> bool {
    let done = sys::channel_create(30).unwrap();
    DONE.store(done.raw().0, Ordering::Release);
    let waiter = Waiter::new(&done, 0, 30).unwrap();
    let process =
        Handle::<rt::handle::Process>::borrowed(rt::abi::Handle(PROCESS.load(Ordering::Acquire)));
    let _ = settle();
    let handles = sys::process_handles(&process).unwrap().live;
    let memory = sys::process_memory(&process).unwrap().used;
    let mut original = posix_signals::INITIAL;
    let mut inherited = 0;
    if unsafe { api::pthread_sigmask(SIG_SETMASK, &bit(SIGPIPE), &mut inherited) } != 0 {
        return failed(451);
    }
    for mode in 0..4 {
        MODE.store(mode, Ordering::Release);
        COUNT.store(0, Ordering::Release);
        ERRORS.store(0, Ordering::Release);
        DEPTH.store(0, Ordering::Release);
        RESULT.store(0, Ordering::Release);
        STATE.seeded.store(0, Ordering::Release);
        STATE.done.store(0, Ordering::Release);
        let action = SigAction {
            handler: handler as *const () as u64,
            mask: bit(SIGUSR2),
            flags: SA_SIGINFO
                | if mode == 2 {
                    SA_NODEFER
                } else if mode == 3 {
                    SA_RESETHAND
                } else {
                    0
                },
        };
        let mut old = posix_signals::INITIAL;
        if unsafe { api::sigaction(SIGUSR1, &action, &mut old) } != 0 {
            return failed(452);
        }
        if mode == 0 {
            original = old;
        }
        let mut id = 0;
        if unsafe { ffi::pthread_create(&mut id, ptr::null(), Some(worker), ptr::null_mut()) } != 0
        {
            return failed(453);
        }
        // Let the lower-priority worker seed the CPU loop while main sleeps.
        if !matches!(
            waiter.receive_until(&done, now() + 20_000_000),
            Ok(Waited::Expired)
        ) || STATE.seeded.load(Ordering::Acquire) != 1
        {
            return failed(454);
        }
        if ffi::pthread_kill(id, SIGUSR1) != 0 {
            return failed(455);
        }
        if !matches!(
            waiter.receive_until(&done, now() + 500_000_000),
            Ok(Waited::Got(_))
        ) || RESULT.load(Ordering::Acquire) != 1
        {
            return failed(456 + mode);
        }
        if unsafe { ffi::pthread_join(id, ptr::null_mut()) } != 0 {
            return failed(460);
        }
    }
    if unsafe { api::sigaction(SIGUSR1, &original, ptr::null_mut()) } != 0
        || unsafe { api::pthread_sigmask(SIG_SETMASK, &inherited, ptr::null_mut()) } != 0
        || !settle()
        || sys::process_handles(&process).unwrap().live != handles
        || sys::process_memory(&process).unwrap().used != memory
    {
        return failed(461);
    }
    rt::println!(
        "signal-context-probe: siginfo, interrupted GPR/PC/SP/SIMD/flags, context edits, nesting and reset ok"
    );
    true
}
