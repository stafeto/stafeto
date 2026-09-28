// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Process dispositions and ordinary thread-directed delivery through the owner.
//! Real-time queues, process routing, stop/continue, alternate stacks, siginfo
//! and automatic syscall restart still require implementation.
use crate::{constants::*, threads, tls};
pub use posix_signals::{DEFAULT, IGNORE};
pub use posix_types::{SigAction, SigSet};
use rt::upcall;
pub(crate) const ACTION: u64 = 40;
pub(crate) const MASK: u64 = 41;
pub(crate) const SEND: u64 = 42;
pub(crate) const PENDING: u64 = 43;
pub(crate) const TAKE: u64 = 44;
pub(crate) const READY: u64 = 45;
pub(crate) const WAIT: u64 = 46;
pub(crate) const WAIT_QUERY: u64 = 47;

// Only the bounded owner's bookkeeping transaction is masked. The owner never
// binds an entry or calls user code, so there is no interrupted-owner lock cycle.
pub(crate) struct NativeMask(bool);
impl NativeMask {
    pub(crate) fn new() -> Self {
        Self(upcall::mask().expect("signal transaction mask"))
    }
}
impl Drop for NativeMask {
    fn drop(&mut self) {
        if !self.0 {
            // SAFETY: the caller entered with delivery enabled; its bound entry
            // and resources already satisfy the native asynchronous contract.
            unsafe { upcall::enable() }.expect("restore signal transaction mask");
        }
    }
}
fn call(op: u64, args: [u64; 5]) -> Result<(u64, u64), i32> {
    threads::request_pair(op, args)
}
fn fail(code: i32) -> i32 {
    crate::fail(code) as i32
}

/// # Safety
/// set is writable for one signal set. No managed thread is required.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigemptyset(set: *mut SigSet) -> i32 {
    if set.is_null() {
        return fail(EFAULT);
    }
    unsafe { set.write(0) };
    0
}
/// # Safety
/// set is writable for one signal set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigfillset(set: *mut SigSet) -> i32 {
    if set.is_null() {
        return fail(EFAULT);
    }
    unsafe { set.write(posix_signals::VALID) };
    0
}
unsafe fn alter(set: *mut SigSet, signal: i32, add: bool) -> i32 {
    if set.is_null() {
        return fail(EFAULT);
    }
    let Ok(bit) = posix_signals::bit(signal) else {
        return fail(EINVAL);
    };
    let old = unsafe { set.read() };
    unsafe { set.write(if add { old | bit } else { old & !bit }) };
    0
}
/// # Safety
/// set is initialized and writable for one signal set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigaddset(set: *mut SigSet, signal: i32) -> i32 {
    unsafe { alter(set, signal, true) }
}
/// # Safety
/// set is initialized and writable for one signal set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigdelset(set: *mut SigSet, signal: i32) -> i32 {
    unsafe { alter(set, signal, false) }
}
/// # Safety
/// set is initialized and readable for one signal set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigismember(set: *const SigSet, signal: i32) -> i32 {
    if set.is_null() {
        return fail(EFAULT);
    }
    let Ok(bit) = posix_signals::bit(signal) else {
        return fail(EINVAL);
    };
    i32::from(unsafe { set.read() } & bit != 0)
}
/// # Safety
/// act is null or readable; old is null or writable. Their storage does not
/// overlap. A catching handler remains live and obeys async-signal safety.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigaction(signal: i32, act: *const SigAction, old: *mut SigAction) -> i32 {
    let _mask = NativeMask::new();
    let (present, action) = if act.is_null() {
        (0, posix_signals::INITIAL)
    } else {
        (1, unsafe { act.read() })
    };
    let args = [
        signal as u64,
        present,
        action.handler,
        action.mask,
        action.flags as u64,
    ];
    match call(ACTION, args) {
        Ok((handler, packed)) => {
            if !old.is_null() {
                unsafe { old.write(posix_signals::unpacked(handler, packed)) };
            }
            0
        }
        Err(code) => fail(code),
    }
}
/// # Safety
/// A non-special handler is a live void(int) C function, safe during asynchronous
/// entry. Stable BSD semantics are used: no reset, signal deferred during handler.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal(signal: i32, handler: u64) -> u64 {
    let action = SigAction {
        handler,
        mask: 0,
        flags: 0,
    };
    let mut old = posix_signals::INITIAL;
    if unsafe { sigaction(signal, &action, &mut old) } == 0 {
        old.handler
    } else {
        u64::MAX
    }
}
/// # Safety
/// set is null or readable, old is null or writable; storage does not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_sigmask(how: i32, set: *const SigSet, old: *mut SigSet) -> i32 {
    let _mask = NativeMask::new();
    let args = if set.is_null() {
        [0, 0, 0, 0, 0]
    } else {
        [how as u64, 1, unsafe { set.read() }, 0, 0]
    };
    match call(MASK, args) {
        Ok((mask, _)) => {
            if !old.is_null() {
                unsafe { old.write(mask) };
            }
            0
        }
        Err(code) => code,
    }
}
/// # Safety
/// Same pointers as pthread_sigmask; this implementation also supports threads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigprocmask(how: i32, set: *const SigSet, old: *mut SigSet) -> i32 {
    let code = unsafe { pthread_sigmask(how, set, old) };
    if code == 0 { 0 } else { fail(code) }
}
/// # Safety
/// set is writable for one signal set, in a managed thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigpending(set: *mut SigSet) -> i32 {
    if set.is_null() {
        return fail(EFAULT);
    }
    let _mask = NativeMask::new();
    match call(PENDING, [0; 5]) {
        Ok((pending, _)) => {
            unsafe { set.write(pending) };
            0
        }
        Err(code) => fail(code),
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn pthread_kill(thread: u64, signal: i32) -> i32 {
    let _mask = NativeMask::new();
    call(SEND, [thread, signal as u64, 0, 0, 0]).map_or_else(|code| code, |_| 0)
}
#[unsafe(no_mangle)]
pub extern "C" fn raise(signal: i32) -> i32 {
    let status = pthread_kill(threads::pthread_self(), signal);
    if status == 0 { 0 } else { fail(status) }
}

/// # Safety
/// The caller is managed. set is readable and sig is writable; their storage
/// does not overlap. All selected signals are blocked before this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigwait(set: *const SigSet, sig: *mut i32) -> i32 {
    let point = threads::cancel::Point::begin();
    let result = if set.is_null() || sig.is_null() {
        Err(EFAULT)
    } else {
        let set = unsafe { set.read() };
        call(WAIT, [set, 0, 0, 0, 0]).map(|(signal, _)| {
            unsafe { sig.write(signal as i32) };
        })
    };
    // Interrupted cancellation removes the registration and acknowledges its
    // retained record before user cleanup can inspect or reuse signal state.
    point.finish();
    result.map_or_else(|code| code, |()| 0)
}

#[cfg(feature = "transport-probe")]
pub fn probe_waiting(thread: u64) -> Result<bool, i32> {
    call(WAIT_QUERY, [thread, 0, 0, 0, 0]).map(|(value, _)| value != 0)
}

rt::upcall_entry!(entry, dispatch);
pub(crate) fn attach() -> Result<(), i32> {
    // SAFETY: this dispatcher owns no interrupted Rust references or locks. It
    // communicates with the sole owner and enters only caller-supplied C code.
    unsafe { upcall::bind(entry) }.map_err(|_| EIO)?;
    call(READY, [0; 5])?;
    unsafe { upcall::enable() }.map_err(|_| EIO)?;
    Ok(())
}
unsafe extern "C" fn dispatch() {
    let errno = tls::errno();
    let saved_errno = unsafe { *errno };
    loop {
        let (old_mask, _) = call(MASK, [0; 5]).expect("signal mask snapshot");
        let (delivery, handler) = call(TAKE, [0; 5]).expect("signal delivery snapshot");
        let signal = delivery as u32 as i32;
        if signal == 0 {
            break;
        }
        if handler == DEFAULT {
            // Process wait-status encoding and stop/continue need process routing.
            sys_exit_signal(signal);
        }
        // SAFETY: sigaction/signal callers supply this live void(int) C address.
        let callback: unsafe extern "C" fn(i32) = unsafe { core::mem::transmute(handler as usize) };
        // Effective signal masks are installed before allowing nested entries.
        unsafe { upcall::enable() }.expect("nested signal entry");
        unsafe { callback(signal) };
        upcall::mask().expect("signal handler mask restoration");
        call(MASK, [SIG_SETMASK as u64, 1, old_mask, 0, 0]).expect("signal mask restoration");
    }
    unsafe { *errno = saved_errno };
}
fn sys_exit_signal(signal: i32) -> ! {
    rt::sys::process_exit((128 + signal) as u64)
}
