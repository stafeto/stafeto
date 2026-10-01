// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calls of processes and threads (spec 4, 8, 11).

use super::*;

/// process_create(x0 memory quota, x1 handle limit, x2 priority ceiling,
/// x3 exit channel, x4 notification priority, x5 start channel): a new
/// process with an empty address space and handle table; x1 returns a
/// handle to it with DUPLICATE, TRANSFER and MANAGE (abi::OWNER_RIGHTS),
/// the first two for milestone 1.3, so that the set never changes. The
/// quota is whole pages, at least one; the limit 1-16384; the ceiling 1-63
/// and no higher than the caller's (ACCESS_DENIED). x3, a channel handle
/// with NOTIFY, with a label or none, or 0, hears of the child's end once
/// the child gave its quota back (spec 7.9): a notification of priority
/// x4, 1-63 and no higher than the caller's ceiling, exactly 0 without x3,
/// bit 0, with the label of the handle; the child's teardown runs at x4 at
/// least (spec 7.7). x5, a channel handle with TRANSFER or 0, moves into
/// entry 0 of the child's table with its rights (spec 13.3): the child
/// takes it first, and the caller's handle goes once the child is made;
/// without x5 entry 0 holds a stub that goes at once
/// (process::reserve_start). x3 and x5 may be one handle: the label is
/// read before the move. The child is the caller's process's (spec 4): it
/// ends when its parent does. The checks in the order of spec 11: the
/// values; x3, then x5 (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED); the
/// ceilings; x3 on a channel that closed (PEER_CLOSED); then the resources
/// in the order the call occupies them, a limit that needs no allocation
/// first: the caller's own table has room for the new handle
/// (LIMIT_REACHED), the channel of x3 a slot for the exit notification
/// (LIMIT_REACHED, spec 6.5), then the quota comes off the caller's
/// (spec 7.5), the child pays from it for its root table, the caller for a
/// page of its pool of shells when the pool grows (spec 7.8), and the
/// child for the page of its pool of blocks with the chunk of entry 0
/// (NO_MEMORY when either quota falls short): the least quota is 8 KiB. A
/// full caller table fails before the child is built, so nothing is made
/// and torn down for it; a child that fails later goes again, hears of
/// nothing and leaves x5 with the caller. The quota comes back to the
/// caller in full once the child and whatever holds its shell went; the
/// page of shells stays the caller's.
pub(super) fn process_create(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let quota = quota_arg(a[0])?;
    let limit = handle_limit_arg(a[1])?;
    let ceiling = priority_arg(a[2])?;
    let notify = notify_priority_arg(a[4], a[3] != 0)?;
    let exit = match a[3] {
        0 => None,
        h => Some(lookup(thread, h, Rights::NOTIFY, |o| {
            Some((o.channel()?, o.session().map_or(0, session::label)))
        })?),
    };
    let start = match a[5] {
        0 => None,
        h => {
            // SAFETY: the calling thread holds its process.
            let table = unsafe { caller(thread).as_ref() };
            let (object, rights) = table
                .lookup_with_rights(Handle(h), Rights::TRANSFER, |o| o.channel().map(|_| *o))?;
            Some((Handle(h), object, rights))
        }
    };
    let own = caller_ceiling(thread);
    under_ceilings(ceiling, &[own])?;
    under_ceilings(notify, &[own])?;
    if let Some((c, _)) = exit
        && channel::is_closed(c)
    {
        return Err(Error::PeerClosed);
    }
    // The caller's table first: it needs no allocation, and the call would
    // insert the child's handle there last (spec 11).
    process::handle_room(caller(thread))?;
    if let Some((c, _)) = exit {
        channel::reserve_source(c)?;
    }
    let made = new_child(thread, quota, limit, ceiling, start.map(|(_, o, r)| (o, r)));
    match made {
        Ok((child, _)) => {
            if let Some((c, label)) = exit {
                process::set_exit(child, c, label, notify);
            }
            if let Some((moved, _, _)) = start {
                // The child holds the channel now; the caller's handle goes.
                let closed = process::close_handle(caller(thread), moved, cause(thread));
                assert!(closed.is_ok(), "the start channel's handle went on the way");
            }
            // SAFETY: the reference `create` handed out goes; the handle
            // holds the child.
            unsafe { process::release(child, cause(thread)) };
        }
        Err(_) => {
            if let Some((c, _)) = exit {
                channel::remove_source(c);
            }
        }
    }
    Ok(Values::new(&[made?.1.0]))
}

/// A child of the caller's process for process_create, with entry 0 of its
/// table, the start channel `start` or a stub, and a handle to it in the
/// caller's table; the reference `create` handed out comes along. A child
/// that fails on the way goes again, and the caller keeps its handles.
fn new_child(
    thread: NonNull<Thread>,
    quota: u64,
    limit: u32,
    ceiling: u8,
    start: Option<(Object, Rights)>,
) -> Result<(NonNull<Process>, Handle), Error> {
    let child = process::create_child(caller(thread), quota, limit, ceiling)?;
    match start {
        Some((object, rights)) => process::move_start(child, object, rights),
        None => process::reserve_start(child),
    }
    .and_then(|()| process::insert_handle(caller(thread), Object::Process(child), OWNER_RIGHTS))
    .map(|h| (child, h))
    .inspect_err(|_| {
        // SAFETY: the reference `create` handed out goes, and nothing else
        // holds the child, which goes again.
        unsafe { process::release(child, cause(thread)) }
    })
}

/// process_kill(x0 process with MANAGE, x1 level): the process ends, reason
/// «killed» (spec 11): its threads stop in whatever state they are and its
/// descendants in a wave, both at S, and the cleanup queue takes what it
/// holds apart at R, the higher of the level and the priority of its exit
/// notification (spec 7.7). Until the stage Threads took them, object_info
/// shows its threads as they were, and thread_interrupt and
/// thread_set_priority still act on them, though none runs. Level 0 is the
/// caller's effective priority: the teardown runs before the caller runs
/// again, and the call returns after it. A level of 1-63 no higher than the
/// caller's effective priority returns once the part in the call is done
/// when it is lower; the exit notification tells of the end. A process that
/// ended already: 0, and its teardown is raised to the level
/// (process::hasten). Killing the caller's own process never returns. The
/// checks in the order of spec 11: a level above 63 (INVALID_ARGS), the
/// handle, then a level above the caller's effective priority
/// (ACCESS_DENIED). O(1).
pub(super) fn process_kill(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let level = match a[1] {
        0 => None,
        l => Some(kcore::args::priority_arg(l)?),
    };
    let target = lookup(thread, a[0], Rights::MANAGE, Object::process)?;
    let cause = match level {
        None => cause(thread),
        Some(l) => {
            under_ceilings(l, &[cause(thread)])?;
            l
        }
    };
    let own = target == caller(thread);
    // SAFETY: the handle holds the process; the end takes its own
    // reference before the table that holds the handle may go.
    let ended = unsafe { process::end(target, ProcessState::Killed, cause) };
    if own {
        // The caller ended with its process and may be gone.
        record_call(Call::ProcessKill.number());
        sched::resume()
    }
    if !ended {
        // SAFETY: the handle holds the process, which ended before; no
        // portion runs during a call.
        unsafe { process::hasten(target, cause) };
    }
    Ok(Values::none())
}

/// process_exit(x0 code): the caller's process ends with `code`. Never
/// returns.
pub(super) fn process_exit(thread: NonNull<Thread>, a: &Args) -> ! {
    let exited = ProcessState::Exited { code: a[0] };
    // SAFETY: the calling thread holds its process until the end takes
    // its own reference.
    unsafe { process::end(caller(thread), exited, cause(thread)) };
    record_call(Call::ProcessExit.number());
    sched::resume()
}

/// thread_create(x0 process with MANAGE, x1 entry, x2 stack, x3 argument,
/// x4 priority, x5 policy, x6 message buffer address, x7 exit channel, x8
/// its priority): a stopped thread in the process with its message buffer
/// mapped at x6, whose address its TPIDRRO_EL0 holds (spec 6.2); x1
/// returns a handle to it with DUPLICATE, TRANSFER and MANAGE. The entry is
/// in the lower half and 4-byte aligned, the stack no higher than its top
/// and 16-byte aligned, the buffer a whole page there, x8 1-63 with x7 and
/// exactly 0 without (INVALID_ARGS); x7, a channel handle with NOTIFY, with
/// a label or none, or 0 (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED); the
/// priority no higher than the ceiling of the process nor than the
/// caller's, x8 no higher than the caller's (ACCESS_DENIED); the process
/// has not ended (BAD_STATE); x7 on a channel that closed (PEER_CLOSED);
/// the buffer's page is free there and outside its mappings, mapped or not
/// yet (INVALID_ARGS, spec 6.2). Resources come last and in the order the
/// call occupies them, a limit that needs no allocation first (spec 11):
/// the caller's own table has room for the new handle (LIMIT_REACHED),
/// then the target has fewer than abi::MAX_THREADS threads that have not
/// ended and the system a free thread number, then the channel of x7 a slot
/// (LIMIT_REACHED, checked inside thread::create before it charges
/// anything), then the target's quota (NO_MEMORY). With x7 the thread's
/// end through thread_exit posts bit 0 at x8 with the label of the handle
/// (source Exit), unless that exit ended the process (thread::exit).
pub(super) fn thread_create(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let priority = priority_arg(a[4])?;
    let policy = policy_arg(a[5])?;
    check_start(a[1], a[2], priority)?;
    check_buffer(a[6])?;
    let notice = notify_priority_arg(a[8], a[7] != 0)?;
    let target = lookup(thread, a[0], Rights::MANAGE, Object::process)?;
    let exit = match a[7] {
        0 => None,
        h => Some(lookup(thread, h, Rights::NOTIFY, |o| {
            Some((o.channel()?, o.session().map_or(0, session::label)))
        })?),
    };
    // SAFETY: the handle holds the target process.
    let target_ceiling = unsafe { target.as_ref() }.ceiling();
    under_ceilings(priority, &[target_ceiling, caller_ceiling(thread)])?;
    under_ceilings(notice, &[caller_ceiling(thread)])?;
    process::check_alive(target)?;
    if let Some((c, _)) = exit
        && channel::is_closed(c)
    {
        return Err(Error::PeerClosed);
    }
    let buffer = a[6] as usize;
    if process::translate(target, buffer).is_some() || process::in_mapping(target, buffer) {
        return Err(Error::InvalidArgs);
    }
    // The caller's table first: it needs no allocation, and the call would
    // insert the new thread's handle there last (spec 11).
    process::handle_room(caller(thread))?;
    let exit = exit.map(|(c, label)| (c, label, notice));
    let (entry, stack) = (a[1] as usize, a[2] as usize);
    let t = thread::create_with_exit(target, entry, stack, a[3], priority, policy, exit)?;
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
pub(super) fn thread_start(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let t = lookup(thread, a[0], Rights::MANAGE, Object::thread)?;
    thread::start(t)?;
    Ok(Values::none())
}

/// thread_exit(): the caller ends; the last started thread of a process
/// ends the process with code 0. Never returns.
pub(super) fn thread_exit(thread: NonNull<Thread>) -> ! {
    // SAFETY: the running thread made the call and is not used afterwards.
    unsafe { thread::exit(thread) };
    record_call(Call::ThreadExit.number());
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
pub(super) fn thread_set_priority(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let priority = priority_arg(a[1])?;
    let policy = policy_arg(a[2])?;
    let target = lookup(thread, a[0], Rights::MANAGE, Object::thread)?;
    // SAFETY: the handle holds the target thread, which holds its process.
    let target_ceiling = unsafe { target.as_ref().process().as_ref() }.ceiling();
    under_ceilings(priority, &[target_ceiling, caller_ceiling(thread)])?;
    sched::set_priority(target, priority, policy)?;
    Ok(Values::none())
}

/// thread_interrupt(x0 thread with MANAGE): abandon its current IPC wait
/// and wake it with INTERRUPTED. BAD_STATE for any thread without such a
/// wait. Stopped, runnable, ended and long-call threads are unaffected.
pub(super) fn thread_interrupt(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let target = lookup(thread, a[0], Rights::MANAGE, Object::thread)?;
    // SAFETY: the caller's handle holds the target through interruption.
    unsafe { sched::interrupt(target, cause(thread)) }?;
    Ok(Values::none())
}

/// yield(): the caller goes to the tail of its level with a new quantum,
/// and the next thread of that level runs; alone there, the caller goes on
/// at once. Lower levels never run through yield.
pub(super) fn yield_now() -> Result<Values, Error> {
    sched::yield_running();
    Ok(Values::none())
}
