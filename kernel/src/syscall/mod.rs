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
//! comes in x0-x9 (spec 11). A long call, mem_create, mem_map, mem_unmap,
//! mem_protect or process_create, goes in portions with interrupts polled between them:
//! it starts over at its `svc` when one is pending, with how far it came
//! kept in the calling thread (thread::Long), and the next entry goes on
//! from there (spec 7.7). Test builds also know numbers of their own, in
//! abi::TEST_CALLS.

use crate::arch::timer as clock;
use crate::object::Object;
use crate::process::Process;
use crate::thread::{self, Thread};
use crate::{arch, cleanup, sched};
use abi::{Call, Error, Handle, Notification, Rights};
#[cfg(feature = "measure")]
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;

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
use mem::{change, change_map, go_on, mem_create, mem_protect, mem_unmap};
use messages::{channel_create, notify, receive, reply, send};
use proc::{
    process_control, process_create, process_exit, process_kill, thread_create, thread_exit,
    thread_interrupt, thread_set_priority, thread_start, yield_now,
};
use time::{clock_now, timer_cancel, timer_create, timer_set};
use upcall::{
    thread_upcall_bind, thread_upcall_control, thread_upcall_request, thread_upcall_return,
};

/// process_control, and for a suspension the wait for every CPU: it is
/// complete when no thread of the process is at EL0 on another CPU, which
/// holds once every CPU has been in the kernel since the gate went up. The
/// wait is a long call (`Long::Quiet`): this CPU takes its interrupts and
/// runs its scheduler between the looks, and holds no lock. The call writes
/// its own result, when the wait is over.
#[inline(never)]
fn process_control_waited(thread: NonNull<Thread>, args: &Args) {
    let r = objects(|| process_control(thread, args));
    if r.is_ok() && args[1] == 0 && crate::smp::cpus() > 1 {
        #[cfg(feature = "window-probe")]
        crate::cmd::window::arm_lag(thread);
        let epoch = crate::qsbr::begin_wait();
        thread::begin_long(
            thread,
            thread::Long::Quiet {
                epoch,
                limit: crate::qsbr::wait_limit(),
            },
        );
        return restart(thread);
    }
    set_result(thread, r);
}

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

    /// Five words of which the first `len` count: the copy is the same five
    /// words whatever `len` is, so it needs no loop (`len` is at most 5).
    #[inline(always)]
    pub fn of_five(words: [u64; 5], len: usize) -> Values {
        assert!(len <= 5);
        let mut x = [MaybeUninit::uninit(); abi::RESULT_VALUES];
        for (to, word) in x.iter_mut().zip(words) {
            to.write(word);
        }
        Values { x, len }
    }

    /// At most abi::RESULT_VALUES values, for x1 and up. Every call site
    /// passes an array of known length, so a longer slice is a bug there;
    /// it stops the kernel and never drops values silently while `len` still claims the full count.
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
    let _production = crate::obj::production();
    // An entry from EL0 holds no section (`obj::lock` takes none inside one).
    crate::obj::assert_not_held();
    #[cfg(feature = "trace")]
    crate::log::syscall(number, crate::thread::index(thread));
    #[cfg(feature = "measure")]
    {
        // SAFETY: the single-core dispatch owns this state until it exits.
        unsafe { (*CALL_TIMING.0.get()).0 = clock::now() };
    }
    crate::obj::serving(u64::from(number));
    dispatch_inner(thread, number);
    // The section of the call ended: the bytes of a message it delivered go
    // between the buffers outside OBJ, before anything runs, which
    // `sched::resume` sees to for a call that comes from EL0; the kernel
    // tests, which call this and look at the buffers, see to it here
    // (thread.rs).
    #[cfg(feature = "ktest")]
    thread::flush_copy();
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
        Some(Call::HandleClose) => objects(|| handle_close(thread, &args)),
        Some(Call::HandleDuplicate) => objects(|| handle_duplicate(thread, &args)),
        Some(Call::CreateChannel) => objects(|| channel_create(thread, &args)),
        Some(Call::Send) => {
            // The probe holds the thread here, with no section, until a
            // request for its entry came: the look under OBJ before the
            // wait has to find it.
            #[cfg(feature = "window-probe")]
            crate::cmd::window::after_check(thread);
            return send(thread, &args, crate::obj::lock());
        }
        Some(Call::Receive) => {
            #[cfg(feature = "window-probe")]
            if matches!(kcore::args::wait_arg(args[1]), Ok(true)) {
                crate::cmd::window::after_check(thread);
            }
            return objects(|| receive(thread, &args));
        }
        Some(Call::Reply) => objects(|| reply(thread, &args)),
        Some(Call::Notify) => objects(|| notify(thread, &args)),
        Some(Call::MemCreate) => return mem_create(thread, &args),
        Some(Call::MemMap) => return change_map(thread, &args),
        Some(Call::MemUnmap) => return change(thread, &args, mem_unmap),
        Some(Call::MemProtect) => return change(thread, &args, mem_protect),
        Some(Call::ProcessCreate) => return process_create(thread, &args),
        Some(Call::ProcessKill) => process_kill(thread, &args, crate::obj::lock()),
        Some(Call::ProcessControl) => return process_control_waited(thread, &args),
        Some(Call::ProcessExit) => process_exit(thread, &args, crate::obj::lock()),
        Some(Call::ThreadCreate) => objects(|| thread_create(thread, &args)),
        Some(Call::ThreadStart) => objects(|| thread_start(thread, &args)),
        Some(Call::ThreadExit) => thread_exit(thread, crate::obj::lock()),
        Some(Call::ThreadSetPriority) => objects(|| thread_set_priority(thread, &args)),
        Some(Call::ThreadInterrupt) => objects(|| thread_interrupt(thread, &args)),
        Some(Call::ThreadUpcallBind) => thread_upcall_bind(thread, &args),
        Some(Call::ThreadUpcallControl) => thread_upcall_control(thread, &args),
        Some(Call::ThreadUpcallRequest) => objects(|| thread_upcall_request(thread, &args)),
        Some(Call::ThreadUpcallReturn) => return thread_upcall_return(thread),
        Some(Call::Yield) => yield_now(),
        Some(Call::DeviceWindowCreate) => objects(|| device_window_create(thread, &args)),
        Some(Call::IrqBind) => objects(|| irq_bind(thread, &args)),
        Some(Call::IrqAck) => objects(|| irq_ack(thread, &args)),
        Some(Call::ClockNow) => clock_now(),
        Some(Call::TimerCreate) => {
            // The probe holds the thread here, with no section, until its
            // process ended: the call takes its section after the end.
            #[cfg(feature = "window-probe")]
            crate::cmd::window::entry_gap(thread);
            objects(|| timer_create(thread, &args))
        }
        Some(Call::TimerSet) => objects(|| timer_set(thread, &args)),
        Some(Call::TimerCancel) => objects(|| timer_cancel(thread, &args)),
        Some(Call::ObjectInfo) => objects(|| object_info(thread, &args)),
        Some(Call::DebugWrite) => objects(|| debug_write(thread, &args)),
        // Numbers no call has, and those of calls that come later.
        _ => return set_result(thread, Err(Error::InvalidArgs)),
    };
    set_result(thread, result);
}

/// Runs a call that reaches objects in a section under OBJ (obj.rs): the
/// handle tables, channels, processes and memory its checks and changes
/// read and link. A call that leaves for another thread or the way out
/// takes its section itself and hands it to `sched::resume_from` or
/// `thread::run_from`.
#[inline(always)]
fn objects<R>(call: impl FnOnce() -> R) -> R {
    let _section = crate::obj::lock();
    call()
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
