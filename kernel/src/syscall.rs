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
//! it takes something, and a thread that waits in it gets its result when
//! the wait ends (spec 11). Test builds also know numbers of their own, in
//! abi::TEST_CALLS.

use crate::mm::{pages, phys};
use crate::object::Object;
use crate::process::{self, Process};
use crate::thread::{self, Thread};
use crate::{channel, cleanup, sched};
use abi::{
    CHANNEL_RIGHTS, Call, Error, Handle, KernelStats, Notification, OWNER_RIGHTS, ProcessHandles,
    ProcessMemory, ProcessState, Rights,
};
use core::ptr::NonNull;
use kcore::notify::{bits_arg, wait_arg};
use kcore::process::{handle_limit_arg, quota_arg};
use kcore::sched::{notify_priority_arg, policy_arg, priority_arg, under_ceilings};
use kcore::thread::{check_buffer, check_start};

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
        Some(Call::CreateChannel) => channel_create(thread, &args),
        Some(Call::Receive) => return receive(thread, &args),
        Some(Call::Notify) => notify(thread, &args),
        Some(Call::ProcessCreate) => process_create(thread, &args),
        Some(Call::ProcessKill) => process_kill(thread, &args),
        Some(Call::ProcessExit) => process_exit(thread, &args),
        Some(Call::ThreadCreate) => thread_create(thread, &args),
        Some(Call::ThreadStart) => thread_start(thread, &args),
        Some(Call::ThreadExit) => thread_exit(thread),
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
        Err(e) => x[0] = e.code(),
    }
}

/// Writes what `receive` took into the thread's registers: 0 in x0 and the
/// notification in x1-x11 (abi::Notification::to_words). x10 and x11 lie
/// past the values of `Values`: only `receive` writes them (spec 11).
pub fn set_notification(mut thread: NonNull<Thread>, n: Notification) {
    // SAFETY: the thread is alive, and nothing else refers to its
    // registers now.
    let x = &mut unsafe { thread.as_mut() }.regs.x;
    x[0] = 0;
    x[1..=11].copy_from_slice(&n.to_words());
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

/// handle_close(x0 handle), no right needed: the handle's reference goes,
/// and the last reference queues the object for cleanup at the caller's
/// priority. Closing a handle to a thread or a process does not end it.
fn handle_close(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    process::close_handle(caller(thread), Handle(a[0]), cause(thread))?;
    Ok(Values::NONE)
}

/// The priority ceiling of the caller's process.
fn caller_ceiling(thread: NonNull<Thread>) -> u8 {
    // SAFETY: the calling thread holds its process.
    unsafe { caller(thread).as_ref() }.ceiling()
}

/// channel_create(x0 priority): a channel whose slot of label 0 has the
/// priority (spec 6.5); x1 returns a handle to it with SEND, NOTIFY,
/// RECEIVE, DUPLICATE and TRANSFER (abi::CHANNEL_RIGHTS). The priority is
/// 1-63 (INVALID_ARGS) and no higher than the caller's ceiling
/// (ACCESS_DENIED). Resources come last, in the order the call occupies
/// them (spec 11): the caller's table has room for the handle
/// (LIMIT_REACHED), then the caller's quota pays for a page of its pool of
/// channels when the pool grows and for a block of its table (NO_MEMORY).
/// A channel whose handle did not go in goes again.
fn channel_create(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let priority = priority_arg(a[0])?;
    under_ceilings(priority, &[caller_ceiling(thread)])?;
    process::handle_room(caller(thread))?;
    let c = channel::create(caller(thread), priority)?;
    let h = process::insert_handle(caller(thread), Object::Channel(c), CHANNEL_RIGHTS);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the channel.
    unsafe { channel::release(c, Rights::NONE, cause(thread)) };
    Ok(Values::new(&[h?.0]))
}

/// notify(x0 channel with NOTIFY, x1 bits): the bits first, since bit 63,
/// CLIENT_GONE, is the kernel's (INVALID_ARGS); then the handle, and
/// PEER_CLOSED once no handle with RECEIVE is left (spec 6.5, 6.8). The
/// bits go into the channel's slot of label 0, ORed with those not yet
/// received, and the slot to the top receiver that waits or into the
/// queue of slots. A receiver woken above the caller runs before the call
/// returns. No memory is taken, and nothing waits.
fn notify(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let bits = bits_arg(a[1])?;
    let c = lookup(thread, a[0], Rights::NOTIFY, Object::channel)?;
    channel::notify(c, bits, cause(thread))?;
    Ok(Values::NONE)
}

/// receive(x0 channel with RECEIVE, x1 flags): the flags first, bit 16
/// NO_WAIT and no other (INVALID_ARGS), then the handle. A call that passed
/// its checks ends the caller's boost by its last notification (spec
/// 6.6). What the queue of slots has comes at once: x1-x11 as
/// abi::Notification::to_words puts them, and the caller works at the
/// slot's priority, under its ceiling, until its next receive. With
/// nothing queued, WOULD_BLOCK under NO_WAIT; otherwise the caller waits
/// in the channel (spec 6.1), and the end of the wait writes its result:
/// a notification, or PEER_CLOSED in x0 alone once the last handle with
/// RECEIVE went. The call writes its own result: x0-x11 are its.
fn receive(thread: NonNull<Thread>, a: &Args) {
    let taken = wait_arg(a[1]).and_then(|wait| {
        let c = lookup(thread, a[0], Rights::RECEIVE, Object::channel)?;
        channel::receive(thread, c, wait)
    });
    match taken {
        Ok(Some(n)) => set_notification(thread, n),
        // The thread waits: the end of the wait writes its registers.
        Ok(None) => {}
        Err(e) => set_result(thread, Err(e)),
    }
}

/// process_create(x0 memory quota, x1 handle limit, x2 priority ceiling,
/// x3 exit channel, x4 notification priority, x5 start channel): a new
/// process with an empty address space and handle table; x1 returns a
/// handle to it with DUPLICATE, TRANSFER and MANAGE (abi::OWNER_RIGHTS),
/// the first two for milestone 1.3, so that the set never changes. The
/// quota is whole pages, at least one; the limit 1-16384; the ceiling 1-63
/// and no higher than the caller's (ACCESS_DENIED). Exit channels come
/// later in milestone 1.3b: x3 is 0, and x4 with it; any other x3 is looked
/// up and fails (BAD_HANDLE, WRONG_TYPE, a channel too until then). The
/// start channel, a channel with TRANSFER, moves into entry 0 of the
/// child's table (spec 13.3) from then on as well: x5 is 0, and any other
/// value is looked up after x3 and fails the same way. Entry 0 then holds a stub that goes at
/// once (process::reserve_start). The child is the caller's process's
/// (spec 4): it ends when its parent does. Resources come last and in the
/// order the call occupies them, a limit that needs no allocation first
/// (spec 11): the caller's own table has room for the new handle
/// (LIMIT_REACHED), then the quota comes off the caller's (spec 7.5), the
/// child pays from it for its root table, the caller for a page of its
/// pool of shells when the pool grows (spec 7.8), and the child for the
/// page of its pool of blocks with the chunk of entry 0 (NO_MEMORY when
/// either quota falls short): the least quota is 8 KiB. A full caller
/// table fails before the child is built, so nothing is made and torn
/// down for it. The quota comes back to the caller in full once the child
/// and whatever holds its shell went; the page of shells stays the
/// caller's.
fn process_create(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let quota = quota_arg(a[0])?;
    let limit = handle_limit_arg(a[1])?;
    let ceiling = priority_arg(a[2])?;
    let channel = a[3] != 0;
    let notify = notify_priority_arg(a[4], channel)?;
    // No object is taken as an exit channel or a start channel yet.
    if channel {
        lookup(thread, a[3], Rights::NOTIFY, |_| None::<()>)?;
    }
    if a[5] != 0 {
        lookup(thread, a[5], Rights::TRANSFER, |_| None::<()>)?;
    }
    let own = caller_ceiling(thread);
    under_ceilings(ceiling, &[own])?;
    under_ceilings(notify, &[own])?;
    // The caller's table first: it needs no allocation, and the call would
    // insert the child's handle there last (spec 11).
    process::handle_room(caller(thread))?;
    let child = process::create_child(caller(thread), quota, limit, ceiling)?;
    let h = process::reserve_start(child).and_then(|()| {
        process::insert_handle(caller(thread), Object::Process(child), OWNER_RIGHTS)
    });
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the child.
    unsafe { process::release(child, cause(thread)) };
    Ok(Values::new(&[h?.0]))
}

/// process_kill(x0 process with MANAGE): the process ends, reason
/// «killed» (spec 11): its threads stop in whatever state they are, its
/// descendants stop in a wave at its ceiling, and the cleanup queue takes
/// what it holds apart at the caller's priority, before the caller runs
/// again. A process that ended already: 0, and its teardown is raised to
/// the caller's priority (process::hasten), so that the call returns after
/// it as well. Killing the caller's own process never returns.
fn process_kill(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let target = lookup(thread, a[0], Rights::MANAGE, Object::process)?;
    let own = target == caller(thread);
    // SAFETY: the handle holds the process; the end takes its own
    // reference before the table that holds the handle may go.
    let ended = unsafe { process::end(target, ProcessState::Killed, cause(thread)) };
    if own {
        // The caller ended with its process and may be gone.
        sched::resume()
    }
    if !ended {
        // SAFETY: the handle holds the process, which ended before; no
        // portion runs during a call.
        unsafe { process::hasten(target, cause(thread)) };
    }
    Ok(Values::NONE)
}

/// process_exit(x0 code): the caller's process ends with `code`. Never
/// returns.
fn process_exit(thread: NonNull<Thread>, a: &Args) -> ! {
    let exited = ProcessState::Exited { code: a[0] };
    // SAFETY: the calling thread holds its process until the end takes
    // its own reference.
    unsafe { process::end(caller(thread), exited, cause(thread)) };
    sched::resume()
}

/// thread_create(x0 process with MANAGE, x1 entry, x2 stack, x3 argument,
/// x4 priority, x5 policy, x6 message buffer address): a stopped thread in
/// the process with its message buffer mapped at x6; x1 returns a handle
/// to it with DUPLICATE, TRANSFER and MANAGE. The entry is in the lower
/// half and 4-byte aligned, the stack no higher than its top and 16-byte
/// aligned, the buffer a whole page there (INVALID_ARGS); the priority no
/// higher than the ceiling of the process nor than the caller's
/// (ACCESS_DENIED); the process has not ended (BAD_STATE); the buffer's
/// page is free there (INVALID_ARGS). Resources come last and in the order
/// the call occupies them, a limit that needs no allocation first (spec 11):
/// the caller's own table has room for the new handle (LIMIT_REACHED),
/// then the target has fewer than abi::MAX_THREADS threads that have not
/// ended (LIMIT_REACHED, checked inside thread::create before it charges
/// anything), then the target's quota (NO_MEMORY).
fn thread_create(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let priority = priority_arg(a[4])?;
    let policy = policy_arg(a[5])?;
    check_start(a[1], a[2], priority)?;
    check_buffer(a[6])?;
    let target = lookup(thread, a[0], Rights::MANAGE, Object::process)?;
    // SAFETY: the handle holds the target process.
    let target_ceiling = unsafe { target.as_ref() }.ceiling();
    under_ceilings(priority, &[target_ceiling, caller_ceiling(thread)])?;
    process::check_alive(target)?;
    let buffer = a[6] as usize;
    if process::translate(target, buffer).is_some() {
        return Err(Error::InvalidArgs);
    }
    // The caller's table first: it needs no allocation, and the call would
    // insert the new thread's handle there last (spec 11).
    process::handle_room(caller(thread))?;
    let t = thread::create(target, a[1] as usize, a[2] as usize, a[3], priority, policy)?;
    let h = thread::give_buffer(t, buffer)
        .and_then(|()| process::insert_handle(caller(thread), Object::Thread(t), OWNER_RIGHTS));
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the thread, and without it the thread is queued for
    // cleanup and goes with its buffer.
    unsafe { thread::release(t, cause(thread)) };
    Ok(Values::new(&[h?.0]))
}

/// thread_start(x0 thread with MANAGE): the stopped thread becomes ready
/// at the tail of its level; above the caller, it runs before the call
/// returns. BAD_STATE for a thread that started before or whose process
/// has ended.
fn thread_start(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let t = lookup(thread, a[0], Rights::MANAGE, Object::thread)?;
    thread::start(t)?;
    Ok(Values::NONE)
}

/// thread_exit(): the caller ends; the last started thread of a process
/// ends the process with code 0. Never returns.
fn thread_exit(thread: NonNull<Thread>) -> ! {
    // SAFETY: the running thread made the call and is not used afterwards.
    unsafe { thread::exit(thread) };
    sched::resume()
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
    // SAFETY: the handle holds the target thread, which holds its process.
    let target_ceiling = unsafe { target.as_ref().process().as_ref() }.ceiling();
    under_ceilings(priority, &[target_ceiling, caller_ceiling(thread)])?;
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

/// object_info(x0 handle, x1 kind, x2 reserved and 0): the kind and x2
/// first (INVALID_ARGS), then the handle. For a process handle with any
/// rights: PROCESS_STATE returns abi::ProcessState::to_words in x1-x4,
/// PROCESS_MEMORY the quota (abi::ProcessMemory) and PROCESS_HANDLES the
/// table (abi::ProcessHandles) in x1-x3. KERNEL_STATS takes the system
/// resource with KSTATS and returns abi::KernelStats in x1-x7 (spec 16).
fn object_info(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    if a[2] != 0 {
        return Err(Error::InvalidArgs);
    }
    let target = || lookup(thread, a[0], Rights::NONE, Object::process);
    match a[1] {
        abi::INFO_PROCESS_STATE => {
            let p = target()?;
            // SAFETY: the handle holds the process.
            let state = unsafe { p.as_ref() }.state();
            Ok(Values::new(&state.to_words()))
        }
        abi::INFO_PROCESS_MEMORY => {
            let q = process::quota(target()?);
            let memory = ProcessMemory {
                quota: q.limit(),
                used: q.used(),
                returned: q.returned(),
            };
            Ok(Values::new(&memory.to_words()))
        }
        abi::INFO_PROCESS_HANDLES => {
            let (live, retired, limit) = process::handle_counts(target()?);
            let handles = ProcessHandles {
                live: live.into(),
                retired: retired.into(),
                limit: limit.into(),
            };
            Ok(Values::new(&handles.to_words()))
        }
        abi::INFO_KERNEL_STATS => {
            lookup(thread, a[0], Rights::KSTATS, Object::resource)?;
            Ok(Values::new(&kernel_stats().to_words()))
        }
        _ => Err(Error::InvalidArgs),
    }
}

/// What the kernel counts about itself, for KERNEL_STATS: the scheduler's
/// idle time and latencies, the cleanup queue, the frames and the pages of
/// the pools and of the page logs of their payers.
fn kernel_stats() -> KernelStats {
    let s = sched::stats();
    KernelStats {
        idle: s.idle,
        idle_latency: s.idle_latency,
        irq_latency: s.irq_latency,
        cleanup_queue: cleanup::len(),
        longest_portion: cleanup::longest(),
        free_frames: phys::free_frames(),
        pool_pages: pages::taken() as u64,
    }
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
