// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! System calls (spec 11): `svc #number` at EL0 with the number from
//! abi::Call, arguments in x0-x9. On success x0 is 0 and the call's values
//! follow in x1 and up; on an error x0 holds the code and no other register
//! changes. Every call checks in one order, so that a call with several
//! bad arguments fails the same way each time: values that need no lookup
//! (INVALID_ARGS); handles in the order of the arguments (BAD_HANDLE, then
//! WRONG_TYPE, then ACCESS_DENIED for missing rights); priority ceilings
//! (ACCESS_DENIED); the state of objects (BAD_STATE); values checked
//! against an object, such as a page that is mapped already
//! (INVALID_ARGS); resources (NO_MEMORY, LIMIT_REACHED), in the order the
//! call occupies them and a limit that needs no allocation first. The
//! kernel never reads or writes memory of a program through an address it
//! is given: addresses are only numbers to check. A call that ends its
//! caller (thread_exit, process_exit, process_kill of its own process)
//! never returns: it leaves through sched::resume, and the caller's
//! registers keep the arguments. `receive` writes x10 and x11 as well when
//! it takes something, and a thread that waits in it or in `send` gets its
//! result when the wait ends: `send` waits for the reply, whose message
//! comes in x0-x9 (spec 11). A long call, mem_create, mem_map, mem_unmap
//! or mem_protect, goes in portions with interrupts polled between them:
//! it starts over at its `svc` when one is pending, with how far it came
//! kept in the calling thread (thread::Long), and the next entry goes on
//! from there (spec 7.7). Test builds also know numbers of their own, in
//! abi::TEST_CALLS.

use crate::arch::timer as clock;
use crate::channel::{self, Via};
use crate::memory::{self, Memory};
use crate::mm::{pages, phys};
use crate::object::Object;
use crate::process::{self, Change, Op, Process};
use crate::thread::{self, Long, Thread};
use crate::{arch, cleanup, irq, sched, session, timer};
use abi::{
    CHANNEL_RIGHTS, Call, DMA_MEMORY_RIGHTS, Error, Handle, KernelStats, MEMORY_RIGHTS,
    Notification, OWNER_RIGHTS, ProcessHandles, ProcessMemory, ProcessState, Rights, WINDOW_RIGHTS,
};
#[cfg(feature = "measure")]
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use kcore::PAGE_SIZE;
use kcore::args::{
    Desc, MemoryKind, access_arg, bits_arg, check_buffer, check_start, handle_limit_arg,
    handle_values_arg, inline_len_arg, line_arg, memory_kind_arg, memory_size_arg,
    notify_priority_arg, policy_arg, priority_arg, quota_arg, range_arg, reserved_arg, rights_arg,
    trigger_arg, under_ceilings, wait_arg,
};
use kcore::maps::Mapping;

mod devices;
mod handles;
mod info;
mod mem;
mod messages;
mod proc;
mod time;
mod upcall;

use devices::{device_window_create, irq_ack, irq_bind};
use handles::{handle_close, handle_duplicate};
use info::{debug_write, object_info};
use mem::{change, go_on, mem_create, mem_map, mem_protect, mem_unmap};
use messages::{channel_create, notify, receive, reply, send};
use proc::{
    process_create, process_exit, process_kill, thread_create, thread_exit, thread_interrupt,
    thread_set_priority, thread_start, yield_now,
};
use time::{clock_now, timer_cancel, timer_create, timer_set};
use upcall::{
    thread_upcall_bind, thread_upcall_control, thread_upcall_request, thread_upcall_return,
};

/// A call's arguments: x0-x9 of the thread that made it.
type Args = [u64; 10];

/// Call times on the single core. EL0 entries keep interrupts masked until
/// the scheduler polls them; kernel tests call dispatch serially too.
#[cfg(feature = "measure")]
struct CallTiming(UnsafeCell<(u64, [u64; abi::KERNEL_CALL_SLOTS])>);

// SAFETY: dispatch and its exit paths run serially on the single core.
#[cfg(feature = "measure")]
unsafe impl Sync for CallTiming {}

#[cfg(feature = "measure")]
static CALL_TIMING: CallTiming = CallTiming(UnsafeCell::new((0, [0; abi::KERNEL_CALL_SLOTS])));

#[cfg(feature = "measure")]
fn record_call(number: u16) {
    if (1..abi::KERNEL_CALL_SLOTS as u16).contains(&number) {
        // SAFETY: the single-core dispatch owns this state until it exits.
        let timing = unsafe { &mut *CALL_TIMING.0.get() };
        let elapsed = clock::now().wrapping_sub(timing.0);
        timing.1[number as usize] = timing.1[number as usize].max(elapsed);
    }
}

#[cfg(not(feature = "measure"))]
#[inline(always)]
fn record_call(_: u16) {}

#[cfg(feature = "measure")]
pub(crate) fn call_maxima() -> [u64; abi::KERNEL_CALL_SLOTS] {
    // SAFETY: the call is running with interrupts masked on the single core.
    unsafe { (*CALL_TIMING.0.get()).1 }
}

#[cfg(feature = "icount")]
pub(crate) fn clear_call_maximum(number: u16) {
    // SAFETY: the single-core test runs with interrupts masked and no
    // other dispatch reads this entry while it resets the measurement.
    unsafe { (*CALL_TIMING.0.get()).1[number as usize] = 0 };
}

#[cfg(not(feature = "measure"))]
fn call_maxima() -> [u64; abi::KERNEL_CALL_SLOTS] {
    [0; abi::KERNEL_CALL_SLOTS]
}

/// Values a call returns in x1 and up on success: the first `len` of `x`
/// are written, the rest never read. The words past `len` stay unwritten,
/// and every copy of a result is written word by word, so that no result
/// on the path of a call becomes a call of `memset` or `memcpy` (spec
/// 15.3).
pub struct Values {
    x: [MaybeUninit<u64>; abi::RESULT_VALUES],
    len: usize,
}

impl Values {
    /// No values: `len` alone is written. A constant would be written
    /// whole, its unwritten words as zeros, by a call of `memset`.
    #[inline(always)]
    pub fn none() -> Values {
        let mut v = MaybeUninit::<Values>::uninit();
        // SAFETY: `x` may hold anything; `len` is written.
        unsafe {
            (&raw mut (*v.as_mut_ptr()).len).write(0);
            v.assume_init()
        }
    }

    /// At most abi::RESULT_VALUES values, for x1 and up. Every call site
    /// passes an array of known length, so a longer slice is a bug there,
    /// not a case to handle; it stops the kernel instead of silently
    /// dropping values while `len` still claims the full count.
    pub fn new(values: &[u64]) -> Values {
        assert!(values.len() <= abi::RESULT_VALUES);
        let mut x = [MaybeUninit::uninit(); abi::RESULT_VALUES];
        for (to, &value) in x.iter_mut().zip(values) {
            to.write(value);
        }
        Values {
            x,
            len: values.len(),
        }
    }
}

/// Carries out system call `number` for `thread`, the running thread that
/// made it, and writes the result into its registers. The scheduler then
/// decides who runs (sched::resume): a call that lets another thread run
/// has written the caller's result first. A thread in a long call goes on
/// with it (`go_on`).
pub fn dispatch(thread: NonNull<Thread>, number: u16) {
    #[cfg(feature = "trace")]
    crate::log::syscall(number, crate::thread::index(thread));
    #[cfg(feature = "measure")]
    {
        // SAFETY: the single-core dispatch owns this state until it exits.
        unsafe { (*CALL_TIMING.0.get()).0 = clock::now() };
    }
    dispatch_inner(thread, number);
    record_call(number);
}

fn dispatch_inner(thread: NonNull<Thread>, number: u16) {
    if crate::testpoint::test_call(thread, number) {
        return;
    }
    if let Some(long) = thread::long(thread) {
        return go_on(thread, long, number);
    }
    // SAFETY: the thread that made the call is alive.
    let r = &unsafe { thread.as_ref() }.regs.x;
    // Word by word: a copy of the slice would be a call of `memcpy`.
    let args: Args = [r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]];
    let result = match Call::from_number(number) {
        Some(Call::HandleClose) => handle_close(thread, &args),
        Some(Call::HandleDuplicate) => handle_duplicate(thread, &args),
        Some(Call::CreateChannel) => channel_create(thread, &args),
        Some(Call::Send) => return send(thread, &args),
        Some(Call::Receive) => return receive(thread, &args),
        Some(Call::Reply) => reply(thread, &args),
        Some(Call::Notify) => notify(thread, &args),
        Some(Call::MemCreate) => return mem_create(thread, &args),
        Some(Call::MemMap) => return change(thread, &args, mem_map),
        Some(Call::MemUnmap) => return change(thread, &args, mem_unmap),
        Some(Call::MemProtect) => return change(thread, &args, mem_protect),
        Some(Call::ProcessCreate) => process_create(thread, &args),
        Some(Call::ProcessKill) => process_kill(thread, &args),
        Some(Call::ProcessExit) => process_exit(thread, &args),
        Some(Call::ThreadCreate) => thread_create(thread, &args),
        Some(Call::ThreadStart) => thread_start(thread, &args),
        Some(Call::ThreadExit) => thread_exit(thread),
        Some(Call::ThreadSetPriority) => thread_set_priority(thread, &args),
        Some(Call::ThreadInterrupt) => thread_interrupt(thread, &args),
        Some(Call::ThreadUpcallBind) => thread_upcall_bind(thread, &args),
        Some(Call::ThreadUpcallControl) => thread_upcall_control(thread, &args),
        Some(Call::ThreadUpcallRequest) => thread_upcall_request(thread, &args),
        Some(Call::ThreadUpcallReturn) => return thread_upcall_return(thread),
        Some(Call::Yield) => yield_now(),
        Some(Call::DeviceWindowCreate) => device_window_create(thread, &args),
        Some(Call::IrqBind) => irq_bind(thread, &args),
        Some(Call::IrqAck) => irq_ack(thread, &args),
        Some(Call::ClockNow) => clock_now(),
        Some(Call::TimerCreate) => timer_create(thread, &args),
        Some(Call::TimerSet) => timer_set(thread, &args),
        Some(Call::TimerCancel) => timer_cancel(thread, &args),
        Some(Call::ObjectInfo) => object_info(thread, &args),
        Some(Call::DebugWrite) => debug_write(thread, &args),
        // Numbers no call has, and those of calls that come later.
        _ => Err(Error::InvalidArgs),
    };
    set_result(thread, result);
}

/// Writes a call's result into the thread's registers: 0 and the values
/// from x1 up, or the error code in x0 alone (spec 11). Inlined into each
/// caller, where the number of values is often known.
#[inline(always)]
pub fn set_result(mut thread: NonNull<Thread>, result: Result<Values, Error>) {
    // SAFETY: the running thread is alive, and nothing else refers to it now.
    let x = &mut unsafe { thread.as_mut() }.regs.x;
    match result {
        Ok(v) => {
            x[0] = 0;
            for i in 0..abi::RESULT_VALUES {
                if i < v.len {
                    // SAFETY: Values::new wrote the first `len` words.
                    x[1 + i] = unsafe { v.x[i].assume_init() };
                }
            }
        }
        Err(e) => x[0] = e.code(),
    }
}

/// Writes what `receive` took into the thread's registers: 0 in x0 and the
/// notification in x1-x11, in place (abi::Notification::write_words). x10
/// and x11 lie past the values of `Values`: only `receive` writes them
/// (spec 11).
pub fn set_notification(mut thread: NonNull<Thread>, n: Notification) {
    // SAFETY: the thread is alive, and nothing else refers to its
    // registers now.
    let x = &mut unsafe { thread.as_mut() }.regs.x;
    x[0] = 0;
    n.write_words((&mut x[1..12]).try_into().expect("x1-x11"));
}

/// Makes the call of `thread` start over (spec 6.1, 7.7): its program
/// counter goes back to its `svc`, and its registers stay as they were, so
/// it makes the call again when it next runs.
pub fn restart(mut thread: NonNull<Thread>) {
    // SAFETY: the thread is alive, and nothing else refers to its
    // registers now.
    unsafe { thread.as_mut() }.regs.elr -= 4;
}

/// The process of the thread that made the call.
fn caller(thread: NonNull<Thread>) -> NonNull<Process> {
    // SAFETY: the thread that made the call is alive.
    unsafe { thread.as_ref() }.process()
}

/// The level of the cleanup the caller's call causes: its effective
/// priority (spec 7.7).
fn cause(thread: NonNull<Thread>) -> u8 {
    // SAFETY: the thread that made the call is alive.
    unsafe { thread.as_ref() }.priority()
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

/// The priority ceiling of the caller's process.
fn caller_ceiling(thread: NonNull<Thread>) -> u8 {
    // SAFETY: the calling thread holds its process.
    unsafe { caller(thread).as_ref() }.ceiling()
}

/// The portions of a long call of `thread` from `entry`, the counter when
/// the kernel took the call (spec 7.7): `step` does one and says whether
/// the call is done. Each stretch between two polls for interrupts counts
/// toward the longest portion (KERNEL_STATS x5), the first with the checks
/// of its entry. After a portion that leaves work, with an interrupt
/// pending the call starts over at its `svc` (`restart`) and this returns
/// None; otherwise the next portion follows. Returns the result of the last
/// portion and when its stretch began, which the caller counts once the
/// call ended.
fn run_portions(
    thread: NonNull<Thread>,
    entry: u64,
    mut step: impl FnMut() -> Result<bool, Error>,
) -> Option<(Result<(), Error>, u64)> {
    let mut start = entry;
    loop {
        match step() {
            Ok(false) => {}
            done => return Some((done.map(|_| ()), start)),
        }
        cleanup::count_portion(start);
        sched::entry_polled();
        if arch::irq_pending() {
            restart(thread);
            return None;
        }
        start = clock::now();
        // The next portion, up to the next poll, is an interval of its own.
        sched::entry_started();
    }
}
