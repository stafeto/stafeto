// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! System calls (spec 11): `svc #number` at EL0 with the number from
//! abi::Call, arguments in x0-x9. On success x0 is 0 and the call's values
//! follow in x1 and up; on an error x0 holds the code and no other register
//! changes. Every call checks in one order, so that a call with several
//! bad arguments fails the same way each time: values that need no lookup
//! (INVALID_ARGS); handles in the order of the arguments (BAD_HANDLE, then
//! WRONG_TYPE, then ACCESS_DENIED for missing rights); priority ceilings
//! (ACCESS_DENIED); the state of objects (BAD_STATE); resources
//! (NO_MEMORY, LIMIT_REACHED). The kernel never reads or writes memory of
//! a program through an address it is given: addresses are only numbers
//! to check. Test builds also know numbers of their own, in
//! abi::TEST_CALLS.

use crate::object::Object;
use crate::process::{self, Process};
use crate::sched;
use crate::thread::Thread;
use abi::{Call, Error, Handle, Rights};
use core::ptr::NonNull;
use kcore::sched::{policy_arg, priority_arg, under_ceilings};

/// A call's arguments: x0-x9 of the thread that made it.
type Args = [u64; 10];

/// Values a call returns in x1 and up on success.
pub struct Values {
    x: [u64; abi::RESULT_VALUES],
    len: usize,
}

impl Values {
    pub const NONE: Values = Values {
        x: [0; abi::RESULT_VALUES],
        len: 0,
    };

    /// At most abi::RESULT_VALUES values, for x1 and up.
    pub fn new(values: &[u64]) -> Values {
        let mut x = [0; abi::RESULT_VALUES];
        x[..values.len()].copy_from_slice(values);
        Values {
            x,
            len: values.len(),
        }
    }
}

/// Carries out system call `number` for `thread`, the running thread that
/// made it, and writes the result into its registers. The scheduler then
/// decides who runs (sched::resume): a call that lets another thread run
/// has written the caller's result first.
pub fn dispatch(thread: NonNull<Thread>, number: u16) {
    #[cfg(feature = "ktest")]
    if abi::TEST_CALLS.contains(&number) && crate::ktest::el0::syscall(thread, number) {
        return;
    }
    let mut args: Args = [0; 10];
    // SAFETY: the thread that made the call is alive.
    args.copy_from_slice(&unsafe { thread.as_ref() }.regs.x[..10]);
    let result = match Call::from_number(number) {
        Some(Call::HandleClose) => handle_close(thread, &args),
        Some(Call::ThreadSetPriority) => thread_set_priority(thread, &args),
        Some(Call::Yield) => yield_now(),
        Some(Call::ObjectInfo) => object_info(thread, &args),
        Some(Call::DebugWrite) => debug_write(thread, &args),
        // Numbers no call has, and those of calls that come later.
        _ => Err(Error::InvalidArgs),
    };
    set_result(thread, result);
}

/// Writes a call's result into the thread's registers: 0 and the values
/// from x1 up, or the error code in x0 alone.
pub fn set_result(mut thread: NonNull<Thread>, result: Result<Values, Error>) {
    // SAFETY: the running thread is alive, and nothing else refers to it now.
    let x = &mut unsafe { thread.as_mut() }.regs.x;
    match result {
        Ok(v) => {
            x[0] = 0;
            x[1..=v.len].copy_from_slice(&v.x[..v.len]);
        }
        Err(e) => x[0] = e as u64,
    }
}

/// The process of the thread that made the call.
fn caller(thread: NonNull<Thread>) -> NonNull<Process> {
    // SAFETY: the thread that made the call is alive.
    unsafe { thread.as_ref() }.process()
}

/// Looks `h` up in the caller's table (Process::lookup).
fn lookup<U>(
    thread: NonNull<Thread>,
    h: u64,
    rights: Rights,
    kind: impl FnOnce(&Object) -> Option<U>,
) -> Result<U, Error> {
    // SAFETY: the calling thread holds its process.
    unsafe { caller(thread).as_ref() }.lookup(Handle(h), rights, kind)
}

/// handle_close(x0 handle), no right needed: the handle's reference goes,
/// and the object goes with its last reference. Closing a handle to a
/// thread or a process does not end it.
fn handle_close(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    process::close_handle(caller(thread), Handle(a[0]))?;
    Ok(Values::NONE)
}

/// thread_set_priority(x0 thread with MANAGE, x1 priority 1-63, x2
/// policy): the thread's base priority and policy change. The priority is
/// no higher than the ceiling of the thread's process nor than the
/// caller's (ACCESS_DENIED): a handle to another process's thread does not
/// lift the thread above the caller's own ceiling. BAD_STATE for a thread
/// that ended. The thread moves by the rules of `pthread_setschedprio`; a
/// thread raised above the caller runs before the call returns, and so
/// does a thread the caller lowered itself below.
fn thread_set_priority(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let priority = priority_arg(a[1])?;
    let policy = policy_arg(a[2])?;
    let target = lookup(thread, a[0], Rights::MANAGE, Object::thread)?;
    // SAFETY: the handle holds the target thread, which holds its process;
    // the calling thread holds its own.
    let ceilings = unsafe {
        [
            target.as_ref().process().as_ref().ceiling(),
            caller(thread).as_ref().ceiling(),
        ]
    };
    under_ceilings(priority, &ceilings)?;
    sched::set_priority(target, priority, policy)?;
    Ok(Values::NONE)
}

/// yield(): the caller goes to the tail of its level with a new quantum,
/// and the next thread of that level runs; alone there, the caller goes on
/// at once. Lower levels never run through yield.
fn yield_now() -> Result<Values, Error> {
    sched::yield_running();
    Ok(Values::NONE)
}

/// object_info(x0 handle, x1 kind, x2 reserved and 0). One kind so far:
/// PROCESS_STATE, for a process handle with any rights, returns
/// abi::ProcessState::to_words in x1-x4.
fn object_info(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    if a[1] != abi::INFO_PROCESS_STATE || a[2] != 0 {
        return Err(Error::InvalidArgs);
    }
    let p = lookup(thread, a[0], Rights::NONE, Object::process)?;
    // SAFETY: the handle holds the process.
    let state = unsafe { p.as_ref() }.state();
    Ok(Values::new(&state.to_words()))
}

/// debug_write(x0 system resource with DEBUG, x1 length up to 64, x2-x9
/// the bytes as abi::inline_words packs them): writes the bytes to the
/// console at once, interrupts masked, and returns their count in x1.
fn debug_write(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    if a[1] > abi::INLINE_MAX as u64 {
        return Err(Error::InvalidArgs);
    }
    let len = a[1] as usize;
    lookup(thread, a[0], Rights::DEBUG, Object::resource)?;
    let words: &[u64; 8] = a[2..].try_into().expect("x2-x9");
    crate::console::write_bytes(&abi::inline_bytes(words)[..len]);
    Ok(Values::new(&[a[1]]))
}
