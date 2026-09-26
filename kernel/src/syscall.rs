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
use crate::process::{self, Process};
use crate::thread::{self, Long, Thread};
use crate::{arch, cleanup, irq, sched, session, timer};
use abi::{
    CHANNEL_RIGHTS, Call, Error, Handle, KernelStats, MEMORY_RIGHTS, Notification, OWNER_RIGHTS,
    ProcessHandles, ProcessMemory, ProcessState, Rights, WINDOW_RIGHTS,
};
use core::ptr::NonNull;
use kcore::PAGE_SIZE;
use kcore::args::{
    Desc, access_arg, bits_arg, check_buffer, check_start, handle_limit_arg, handle_values_arg,
    inline_len_arg, line_arg, memory_size_arg, notify_priority_arg, policy_arg, priority_arg,
    quota_arg, range_arg, reserved_arg, rights_arg, trigger_arg, under_ceilings, wait_arg,
};
use kcore::maps::Mapping;

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
/// has written the caller's result first. A thread in a long call goes on
/// with it (`go_on`).
pub fn dispatch(thread: NonNull<Thread>, number: u16) {
    if crate::testpoint::test_call(thread, number) {
        return;
    }
    if let Some(long) = thread::long(thread) {
        return go_on(thread, long, number);
    }
    let mut args: Args = [0; 10];
    // SAFETY: the thread that made the call is alive.
    args.copy_from_slice(&unsafe { thread.as_ref() }.regs.x[..10]);
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

/// handle_close(x0 handle), no right needed: the handle's reference goes,
/// and the last reference queues the object for cleanup at the caller's
/// priority. Closing a handle to a thread or a process does not end it.
fn handle_close(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    process::close_handle(caller(thread), Handle(a[0]), cause(thread))?;
    Ok(Values::NONE)
}

/// handle_duplicate(x0 handle with DUPLICATE, x1 rights, x2 label, x3
/// priority): a copy of the handle with the rights, a subset of the
/// handle's own, in x1 (spec 5.2, 5.3). With label 0 and priority 0 the
/// copy names the same object, whatever its kind; a copy of a handle with
/// a label carries that label and counts as one more copy of its session.
/// A label that is not 0 goes on a copy of a channel handle that has none:
/// the copy names a new session of the channel with the label and a slot
/// of the priority, 1-63, which the caller's pool of sessions holds and its
/// quota pays for. The checks in the order of spec 11: bits no right has, a
/// priority without a label or a label without a priority 1-63
/// (INVALID_ARGS); the handle (BAD_HANDLE), a label on what is no channel
/// (WRONG_TYPE), no DUPLICATE or a right the handle lacks (ACCESS_DENIED);
/// the priority above the caller's ceiling (ACCESS_DENIED); a label on a
/// handle with one (BAD_STATE) or on a closed channel (PEER_CLOSED); then
/// the resources in the order the call takes them: room in the caller's
/// table (LIMIT_REACHED), a slot of the channel (LIMIT_REACHED, spec 6.5),
/// a page of the caller's pool of sessions and a block of its table
/// (NO_MEMORY). A session whose handle did not go in goes again.
fn handle_duplicate(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let rights = rights_arg(a[1])?;
    let label = a[2];
    let priority = notify_priority_arg(a[3], label != 0)?;
    let needed = Rights::DUPLICATE | rights;
    if label == 0 {
        let object = lookup(thread, a[0], needed, |o| Some(*o))?;
        let h = process::insert_handle(caller(thread), object, rights)?;
        return Ok(Values::new(&[h.0]));
    }
    let (c, labelled) = lookup(thread, a[0], needed, |o| {
        Some((o.channel()?, o.session().is_some()))
    })?;
    under_ceilings(priority, &[caller_ceiling(thread)])?;
    if labelled {
        return Err(Error::BadState);
    }
    if channel::is_closed(c) {
        return Err(Error::PeerClosed);
    }
    process::handle_room(caller(thread))?;
    let s = session::create(caller(thread), c, label, priority)?;
    let h = process::insert_handle(caller(thread), Object::Session(s), rights);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the session, and without it the session goes.
    unsafe { session::unref(s, cause(thread)) };
    Ok(Values::new(&[h?.0]))
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
/// bits go into the channel's slot of label 0, or through a handle with a
/// label into its session's slot (spec 5.3), ORed with those not yet
/// received, and the slot to the top receiver that waits or into the
/// queue of slots. A receiver woken above the caller runs before the call
/// returns. No memory is taken, and nothing waits.
fn notify(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let bits = bits_arg(a[1])?;
    let (c, s) = lookup(thread, a[0], Rights::NOTIFY, |o| {
        Some((o.channel()?, o.session()))
    })?;
    match s {
        Some(s) => session::notify(s, bits, cause(thread))?,
        None => channel::notify(c, bits, cause(thread))?,
    }
    Ok(Values::NONE)
}

/// receive(x0 channel with RECEIVE, x1 flags): the flags first, bit 16
/// NO_WAIT and no other (INVALID_ARGS), then the handle. A call that passed
/// its checks ends the caller's boost by its last notification or request
/// (spec 6.6). What the queue has comes at once: a notification in x1-x11
/// as abi::Notification::to_words puts them, after which the caller works
/// at the slot's priority, under its ceiling, until its next receive; or a
/// request in x1-x11 as abi::Message::to_words puts them, the label of the
/// handle it came through in x10 and the token of its reply in x11, after
/// which the caller works at the client's priority, under its ceiling,
/// until its reply with the token or its next receive. With nothing
/// queued, WOULD_BLOCK under NO_WAIT; otherwise the caller waits in the
/// channel (spec 6.1), and the end of the wait writes its result: a
/// notification, a request, or PEER_CLOSED in x0 alone once the last
/// handle with RECEIVE went. The call writes its own result: x0-x11 are
/// its (channel::receive).
fn receive(thread: NonNull<Thread>, a: &Args) {
    let taken = wait_arg(a[1]).and_then(|wait| {
        let c = lookup(thread, a[0], Rights::RECEIVE, Object::channel)?;
        channel::receive(thread, c, wait)
    });
    if let Err(e) = taken {
        set_result(thread, Err(e));
    }
}

/// The values of the handles of the message the caller sends or answers
/// with (spec 6.1, 6.2), read once from its message buffer before any
/// check: INVALID_ARGS for a value listed twice or equal to `channel`, x0
/// of send.
fn message_handles(
    thread: NonNull<Thread>,
    desc: Desc,
    channel: Option<u64>,
) -> Result<[u64; abi::MESSAGE_HANDLES], Error> {
    if desc.handles == 0 {
        return Ok([0; abi::MESSAGE_HANDLES]);
    }
    let values = thread::handle_values(thread, desc.handles);
    handle_values_arg(&values[..desc.handles], channel)?;
    Ok(values)
}

/// The handles of a message in the order it lists them (spec 6.1, 11):
/// BAD_HANDLE, then ACCESS_DENIED without TRANSFER; a handle to an object
/// of any kind travels.
fn check_handles(thread: NonNull<Thread>, values: &[u64]) -> Result<(), Error> {
    values
        .iter()
        .try_for_each(|&h| lookup(thread, h, Rights::TRANSFER, |_| Some(())))
}

/// send(x0 channel with SEND, x1 description, x2-x9 bytes 0-63 of the
/// request): a request and the wait for its reply (spec 6.1). The checks in
/// the order of spec 11: the description (abi::MESSAGE_MAX bytes and
/// abi::MESSAGE_HANDLES handles at most, NO_WAIT, no other bit) and the
/// values of its handles, which the message buffer holds
/// (`message_handles`); then x0, a channel or a labelled one (BAD_HANDLE,
/// WRONG_TYPE, ACCESS_DENIED without SEND), and the handles
/// (`check_handles`); then the state (BAD_STATE when the caller's count of
/// requests ran out, PEER_CLOSED once the channel closed, WOULD_BLOCK
/// under NO_WAIT when no receiver waits); then the room for the handles in
/// the table of a receiver that waits (LIMIT_REACHED, NO_MEMORY). x0 alone
/// changes on an error; the handles stay with the caller, but for
/// PEER_CLOSED, LIMIT_REACHED and NO_MEMORY, when they go. Otherwise the
/// handles leave the caller's table and the caller waits, its request
/// queued by its effective priority or taken by the top receiver that
/// waits at once, until the reply writes x0-x9: 0, the description and the
/// data, or an error of the reply's handles in x0 alone. Bytes 64 up to
/// the length of the request and of the reply go between the message
/// buffers, and the values and info words of the handles into them (spec
/// 6.2; channel::send). A receiver that takes the request on the fast path
/// runs at once (spec 6.4).
fn send(thread: NonNull<Thread>, a: &Args) {
    let sent = Desc::from_send(a[1]).and_then(|desc| {
        let values = message_handles(thread, desc, Some(a[0]))?;
        let via = lookup(thread, a[0], Rights::SEND, |o| match *o {
            Object::Channel(c) => Some(Via::Channel(c)),
            Object::Session(s) => Some(Via::Session(s)),
            _ => None,
        })?;
        let values = &values[..desc.handles];
        check_handles(thread, values)?;
        channel::send(thread, via, desc, values)
    });
    match sent {
        Ok(Some(receiver)) => thread::run(receiver),
        Ok(None) => {}
        Err(e) => set_result(thread, Err(e)),
    }
}

/// reply(x0 token, x1 description, x2-x9 bytes 0-63 of the reply): the
/// reply to the request the token names, which a thread of the caller's
/// process accepted (spec 6.1). The description first (NO_WAIT is
/// INVALID_ARGS: reply never waits) and the values of its handles
/// (`message_handles`), then the handles (`check_handles`); a reply with the
/// token of the caller's boost ends the boost, whatever comes of it (spec
/// 6.6); then the token: BAD_STATE for one that names no request waiting
/// for this process's reply, a used one among them, and PEER_CLOSED for one
/// whose client ended while it waited (spec 6.8); then the room for the
/// handles in the client's table (LIMIT_REACHED, NO_MEMORY), which fails
/// the client's send too and uses the token up. x0 alone changes on an
/// error; the handles stay with the caller, but for PEER_CLOSED,
/// LIMIT_REACHED and NO_MEMORY, when they go. Otherwise x0 is 0, and the
/// client gets the reply, bytes 64 up to its length through the message
/// buffers and the handles in its table (spec 6.2; channel::reply).
fn reply(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let desc = Desc::from_reply(a[1])?;
    let values = message_handles(thread, desc, None)?;
    let values = &values[..desc.handles];
    check_handles(thread, values)?;
    channel::reply(thread, a[0], desc, values)?;
    Ok(Values::NONE)
}

/// The next entry of the long call `long` of `thread` (spec 7.7), which
/// started over after an interrupt. An entry with the call's number goes
/// on where the call stopped, wherever its `svc` stands, with no check made
/// again, and its portions count from this entry. An entry with another
/// number gives the long call up as the caller's leaving does, what the
/// call held going at the thread's priority (thread::drop_long): a stretch
/// of its own, which counts toward the longest portion (KERNEL_STATS x5).
/// With an interrupt pending the entry then starts over at its `svc`
/// (`restart`), and call `number` runs the usual way on the next entry;
/// otherwise it runs at once.
fn go_on(thread: NonNull<Thread>, long: Long, number: u16) {
    let entry = clock::now();
    if number != long.call().number() {
        // SAFETY: the running thread is alive, and nothing uses what its
        // call held afterwards.
        unsafe { thread::drop_long(thread, cause(thread)) };
        cleanup::count_portion(entry);
        if arch::irq_pending() {
            return restart(thread);
        }
        return dispatch(thread, number);
    }
    match long {
        Long::Create(m) => make(thread, m, entry),
        _ => portions(thread, long, entry),
    }
}

/// mem_create(x0 size, x1 flags): a memory object of `size` bytes, whole
/// pages from one page to abi::MAX_MEMORY, whose frames the kernel takes
/// and zeroes at once, in portions (spec 7.3, 7.7); x1 returns a handle to
/// it with abi::MEMORY_RIGHTS once it is whole. The checks in the order of
/// spec 11: the size, then the flags, of which none is known
/// (INVALID_ARGS); then the resources in the order the call takes them:
/// room in the caller's table (LIMIT_REACHED) and a chunk for it
/// (NO_MEMORY; process::reserve_handles), a place in the caller's pool of
/// memory objects, whose page the caller's quota pays for when the pool
/// grows, and the object's budget, its pages and the nodes of their list,
/// from the caller's quota at once (NO_MEMORY; memory::create). A call
/// that fails there changes nothing but a chunk of the table or a page of
/// the pool, which stay the caller's. Then the portions (`make`); the call
/// writes its own result.
fn mem_create(thread: NonNull<Thread>, a: &Args) {
    let entry = clock::now();
    let made = memory_size_arg(a[0]).and_then(|pages| {
        reserved_arg(a[1])?;
        process::reserve_handles(caller(thread), 1)?;
        memory::create(caller(thread), pages)
    });
    match made {
        Ok(m) => {
            thread::begin_long(thread, Long::Create(m));
            make(thread, m, entry)
        }
        Err(e) => set_result(thread, Err(e)),
    }
}

/// The portions of the mem_create of `thread` for `m`, which the thread's
/// long call holds (spec 7.7), from `entry`, the counter when the kernel
/// took the call: each takes up to memory::CREATE_PORTION pages. Each
/// stretch between two polls for interrupts counts toward the longest
/// portion (KERNEL_STATS x5): the first with the checks of its entry, the
/// last with the handle and the end of the call. After a portion that
/// leaves pages, with an interrupt pending the call starts over at its
/// `svc` (`restart`), and its next entry comes back here; otherwise the
/// next portion follows. Once the object is whole its handle goes into the
/// caller's table, where the first entry made room; when other threads of
/// the process took the room meanwhile, the call fails with LIMIT_REACHED
/// or NO_MEMORY, the only error that comes late, and the object goes at
/// the caller's priority.
fn make(thread: NonNull<Thread>, m: NonNull<Memory>, entry: u64) {
    let mut start = entry;
    while !memory::fill(m) {
        cleanup::count_portion(start);
        if arch::irq_pending() {
            return restart(thread);
        }
        start = clock::now();
    }
    thread::end_long(thread);
    let h = process::insert_handle(caller(thread), Object::Memory(m), MEMORY_RIGHTS);
    // SAFETY: the reference `create` handed out, which the long call held,
    // goes; the handle, if it went in, holds the object, and without it
    // the object goes.
    unsafe { memory::release(m, cause(thread)) };
    set_result(thread, h.map(|h| Values::new(&[h.0])));
    cleanup::count_portion(start);
}

/// mem_map(x0 process with MANAGE, x1 memory object, x2 offset, x3 length,
/// x4 address, x5 access): shows `length` bytes of the object from byte
/// `offset` at `address` of the process, with access R, RW or RX
/// (abi::Access, spec 7.4); only x0 returns. The checks in the order of
/// spec 11: the values, the offset, the length and the address whole
/// pages, the length not 0, the range in the lower half, and the access
/// (INVALID_ARGS); x0 (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without
/// MANAGE), x1 (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without MAP_READ, or
/// MAP_WRITE for W, or MAP_EXEC for X); the process lives (BAD_STATE); the
/// range lies in the object and touches no mapping of the process and no
/// message buffer of its threads (INVALID_ARGS, process::check_free); then
/// the resources, which the process pays for whoever calls: a place in its
/// table of mappings (LIMIT_REACHED), the block of the table and the most
/// tables the range may take (NO_MEMORY, process::add_mapping). A call
/// that fails changes nothing but the block. Then the portions
/// (`portions`), which never fail but for a process that ends meanwhile;
/// the entry records the rights of x1 to map, which bound its mem_protect.
fn mem_map(thread: NonNull<Thread>, a: &Args) -> Result<Long, Error> {
    let pages = range_arg(a[4], a[3])?;
    if !a[2].is_multiple_of(PAGE_SIZE) {
        return Err(Error::InvalidArgs);
    }
    let access = access_arg(a[5])?;
    let target = lookup(thread, a[0], Rights::MANAGE, Object::process)?;
    // SAFETY: the calling thread holds its process.
    let (m, rights) = unsafe { caller(thread).as_ref() }.lookup_with_rights(
        Handle(a[1]),
        access.rights(),
        Object::memory,
    )?;
    process::check_alive(target)?;
    let size = memory::pages(m) as u64 * PAGE_SIZE;
    if a[2].checked_add(a[3]).is_none_or(|end| end > size) {
        return Err(Error::InvalidArgs);
    }
    process::check_free(target, a[4], pages)?;
    let map = Rights::MAP_READ | Rights::MAP_WRITE | Rights::MAP_EXEC;
    let offset = (a[2] / PAGE_SIZE) as u32;
    let mapping = Mapping::new(a[4], pages as u32, offset, m, Rights(rights.0 & map.0));
    let (on, prepaid) = process::add_mapping(target, mapping)?;
    process::retain(target);
    Ok(Long::Map {
        on,
        access,
        prepaid,
    })
}

/// mem_unmap(x0 process with MANAGE, x1 address, x2 length): the mapping
/// of the process that is exactly that range goes, its pages and their TLB
/// entries (spec 7.4); only x0 returns. The checks in the order of spec
/// 11: the values, the address and the length whole pages, the length not
/// 0, the range in the lower half (INVALID_ARGS); x0 (BAD_HANDLE,
/// WRONG_TYPE, ACCESS_DENIED without MANAGE); the process lives
/// (BAD_STATE); one mapping is exactly that range, and the page of a
/// message buffer is no mapping (INVALID_ARGS); no long call works on it
/// (BAD_STATE). Then the portions; the mapping's reference to its object
/// goes at the end.
fn mem_unmap(thread: NonNull<Thread>, a: &Args) -> Result<Long, Error> {
    let pages = range_arg(a[1], a[2])?;
    let target = lookup(thread, a[0], Rights::MANAGE, Object::process)?;
    process::check_alive(target)?;
    let (index, _) = process::find_mapping(target, a[1], pages)?;
    process::retain(target);
    Ok(Long::Unmap {
        on: process::begin_change(target, index),
    })
}

/// mem_protect(x0 process with MANAGE, x1 address, x2 length, x3 access):
/// the pages of the mapping of the process that is exactly that range get
/// access R, RW or RX (spec 7.4); only x0 returns. The checks in the order
/// of spec 11: the range as mem_unmap takes it and the access
/// (INVALID_ARGS); x0 (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without
/// MANAGE); the process lives (BAD_STATE); a mapping is that range
/// (INVALID_ARGS), no long call works on it (BAD_STATE), and the access
/// needs no right the mapping was not made with (ACCESS_DENIED). Then the
/// portions.
fn mem_protect(thread: NonNull<Thread>, a: &Args) -> Result<Long, Error> {
    let pages = range_arg(a[1], a[2])?;
    let access = access_arg(a[3])?;
    let target = lookup(thread, a[0], Rights::MANAGE, Object::process)?;
    process::check_alive(target)?;
    let (index, rights) = process::find_mapping(target, a[1], pages)?;
    if !rights.contains(access.rights()) {
        return Err(Error::AccessDenied);
    }
    process::retain(target);
    Ok(Long::Protect {
        on: process::begin_change(target, index),
        access,
    })
}

/// The first entry of mem_map, mem_unmap or mem_protect, whose checks and
/// resources are `first`'s: a call that passed them begins its long call
/// and its portions; one that failed writes the error.
fn change(
    thread: NonNull<Thread>,
    a: &Args,
    first: fn(NonNull<Thread>, &Args) -> Result<Long, Error>,
) {
    let entry = clock::now();
    match first(thread, a) {
        Ok(long) => {
            thread::begin_long(thread, long);
            portions(thread, long, entry)
        }
        Err(e) => set_result(thread, Err(e)),
    }
}

/// The portions of the change of a mapping `long` of `thread` (spec 7.7),
/// each up to process::PORTION pages or process::EXEC_PORTION with
/// execution, from `entry`, the counter when the kernel took the call.
/// Each stretch between two polls for interrupts counts toward the longest
/// portion (KERNEL_STATS x5): the first with the checks of its entry, the
/// last with the end of the call. After a portion that leaves pages, with
/// an interrupt pending the call starts over at its `svc` (`restart`), and
/// its next entry comes back here; otherwise the next portion follows. The
/// last one ends the call with 0 (process::finish_change); a process that
/// ended meanwhile ends it with BAD_STATE (process::abandon_change). Either
/// way the call's reference to the process goes, at the caller's priority.
fn portions(thread: NonNull<Thread>, mut long: Long, entry: u64) {
    let mut start = entry;
    let result = loop {
        match process::step_change(&mut long) {
            Ok(false) => {
                thread::update_long(thread, long);
                cleanup::count_portion(start);
                if arch::irq_pending() {
                    return restart(thread);
                }
                start = clock::now();
            }
            Ok(true) => break Ok(Values::NONE),
            Err(e) => break Err(e),
        }
    };
    thread::end_long(thread);
    let (Long::Map { on, .. } | Long::Unmap { on } | Long::Protect { on, .. }) = long else {
        unreachable!("mem_create changes no mapping");
    };
    // SAFETY: the call is over, and its reference to the process goes
    // last.
    unsafe {
        match result {
            Ok(_) => process::finish_change(long, cause(thread)),
            Err(_) => process::abandon_change(long, cause(thread)),
        }
        process::release(on.target, cause(thread));
    }
    set_result(thread, result);
    cleanup::count_portion(start);
}

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
fn process_create(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
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
/// the process with its message buffer mapped at x6, whose address its
/// TPIDRRO_EL0 holds (spec 6.2); x1 returns a handle to it with DUPLICATE,
/// TRANSFER and MANAGE. The entry is in the lower half and 4-byte aligned,
/// the stack no higher than its top and 16-byte aligned, the buffer a whole
/// page there (INVALID_ARGS); the priority no higher than the ceiling of
/// the process nor than the caller's (ACCESS_DENIED); the process has not
/// ended (BAD_STATE); the buffer's page is free there and outside its
/// mappings, mapped or not yet (INVALID_ARGS, spec 6.2).
/// Resources come last and in the order the call occupies them, a limit
/// that needs no allocation first (spec 11): the caller's own table has
/// room for the new handle (LIMIT_REACHED), then the target has fewer than
/// abi::MAX_THREADS threads that have not ended and the system a free
/// thread number (LIMIT_REACHED, checked inside thread::create before it
/// charges anything), then the target's quota (NO_MEMORY).
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
    if process::translate(target, buffer).is_some() || process::in_mapping(target, buffer) {
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

/// clock_now(): x1 returns the counter in nanoseconds, rounded down
/// (spec 10): the scale of the deadlines of timer_set.
fn clock_now() -> Result<Values, Error> {
    Ok(Values::new(&[clock::clock().ticks_to_ns(clock::now())]))
}

/// timer_create(x0 channel with RECEIVE, x1 priority): a timer on the
/// channel, not armed, whose notifications have the priority and the
/// label of the handle (spec 10); x1 returns a handle to it with
/// DUPLICATE, TRANSFER and MANAGE (abi::OWNER_RIGHTS). The channel is the
/// caller's own to receive from: its slots and the priorities that lift
/// its receivers are the receiver's. The checks in the order of spec 11:
/// the priority, 1-63 (INVALID_ARGS); the handle (BAD_HANDLE, WRONG_TYPE,
/// ACCESS_DENIED without RECEIVE); the priority above the caller's ceiling
/// (ACCESS_DENIED); then the resources in the order the call takes them:
/// room in the caller's table (LIMIT_REACHED), abi::MAX_TIMERS timers the
/// caller pays for (LIMIT_REACHED), a slot of the channel (LIMIT_REACHED,
/// spec 6.5), a page of the caller's pool of timers and a block of its
/// table (NO_MEMORY). A channel with a handle with RECEIVE is open. A
/// timer whose handle did not go in goes again.
fn timer_create(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let priority = priority_arg(a[1])?;
    let (c, label) = lookup(thread, a[0], Rights::RECEIVE, |o| {
        Some((o.channel()?, o.session().map_or(0, session::label)))
    })?;
    under_ceilings(priority, &[caller_ceiling(thread)])?;
    process::handle_room(caller(thread))?;
    let t = timer::create(caller(thread), c, label, priority)?;
    let h = process::insert_handle(caller(thread), Object::Timer(t), OWNER_RIGHTS);
    // SAFETY: the reference `create` handed out goes; the handle, if it
    // went in, holds the timer, and without it the timer goes.
    unsafe { timer::release(t, cause(thread)) };
    Ok(Values::new(&[h?.0]))
}

/// timer_set(x0 timer with MANAGE, x1 deadline): the timer fires at the
/// deadline, nanoseconds on the scale of clock_now, rounded up to counter
/// ticks so that it never fires early (spec 10). A deadline the counter
/// reached fires in the call: bit 0 into the timer's slot, which goes to
/// the top receiver that waits or into the channel's queue, as notify
/// puts it; any other arms the timer, and an armed one moves. PEER_CLOSED
/// once the channel closed, and the timer stays as it was. No memory is
/// taken.
fn timer_set(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let t = lookup(thread, a[0], Rights::MANAGE, Object::timer)?;
    let deadline = clock::clock().ns_to_ticks(a[1]);
    timer::set(t, deadline, cause(thread))?;
    Ok(Values::NONE)
}

/// timer_cancel(x0 timer with MANAGE): the timer is armed no more; bits it
/// posted stay in its slot until receive takes them (spec 10). A timer
/// that is not armed is left as it is: 0.
fn timer_cancel(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let t = lookup(thread, a[0], Rights::MANAGE, Object::timer)?;
    timer::cancel(t);
    Ok(Values::NONE)
}

/// device_window_create(x0 system resource with DEVICE, x1 address, x2
/// length): a device window, a memory object over the physical range
/// rounded out to whole pages (spec 9); x1 returns a handle to it with
/// abi::WINDOW_RIGHTS, which mem_map shows as Device-nGnRE, never
/// executable (spec 7.4). The checks in the order of spec 11: a length of
/// 0, a range that wraps around, ends past 2^48 or holds more than
/// abi::MAX_MEMORY (INVALID_ARGS, kcore::window::round_out); x0
/// (BAD_HANDLE, WRONG_TYPE, ACCESS_DENIED without DEVICE); a page of the
/// range shared with RAM or a device of the kernel (INVALID_ARGS,
/// memory::check_window); then the resources in the order the call takes
/// them: room in the caller's table (LIMIT_REACHED), a page of the caller's
/// pool of memory objects and a block of its table (NO_MEMORY). A window
/// whose handle did not go in goes again.
fn device_window_create(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let (base, pages) = kcore::window::round_out(a[1], a[2])?;
    lookup(thread, a[0], Rights::DEVICE, Object::resource)?;
    memory::check_window(base, pages)?;
    process::handle_room(caller(thread))?;
    let m = memory::create_window(caller(thread), base, pages as usize)?;
    let h = process::insert_handle(caller(thread), Object::Memory(m), WINDOW_RIGHTS);
    // SAFETY: the reference `create_window` handed out goes; the handle, if
    // it went in, holds the window, and without it the window goes.
    unsafe { memory::release(m, cause(thread)) };
    Ok(Values::new(&[h?.0]))
}

/// irq_bind(x0 system resource with DEVICE, x1 line, x2 channel with
/// NOTIFY, x3 priority, x4 flags): the line's interrupts come as
/// notifications of the channel (spec 9), bit 0 into a slot of the
/// priority with the label of the handle; x1 returns a handle to the
/// binding with DUPLICATE, TRANSFER and MANAGE (abi::OWNER_RIGHTS). The
/// channel may be a registration handle a service gave init: NOTIFY is
/// the right to post into it. The line is edge-triggered with
/// abi::TRIGGER_EDGE in the flags, level-triggered without, and open at
/// once. The checks in the order of spec 11: a line outside the shared
/// ones or the kernel's console line, a priority outside 1-63 and a flag
/// other than TRIGGER_EDGE (INVALID_ARGS); x0 (BAD_HANDLE, WRONG_TYPE,
/// ACCESS_DENIED without DEVICE), x2 (BAD_HANDLE, WRONG_TYPE,
/// ACCESS_DENIED without NOTIFY); the priority above the caller's ceiling
/// (ACCESS_DENIED); a line with a binding (BAD_STATE), a closed channel
/// (PEER_CLOSED); then the resources in the order the call takes them:
/// room in the caller's table (LIMIT_REACHED), a slot of the channel
/// (LIMIT_REACHED, spec 6.5), a page of the caller's pool of bindings and
/// a block of its table (NO_MEMORY). A binding whose handle did not go in
/// goes again, and its line with it.
fn irq_bind(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let line = line_arg(a[1], arch::gic::lines())?;
    let priority = priority_arg(a[3])?;
    let edge = trigger_arg(a[4])?;
    lookup(thread, a[0], Rights::DEVICE, Object::resource)?;
    let (c, label) = lookup(thread, a[2], Rights::NOTIFY, |o| {
        Some((o.channel()?, o.session().map_or(0, session::label)))
    })?;
    under_ceilings(priority, &[caller_ceiling(thread)])?;
    if irq::is_bound(line) {
        return Err(Error::BadState);
    }
    if channel::is_closed(c) {
        return Err(Error::PeerClosed);
    }
    process::handle_room(caller(thread))?;
    let b = irq::bind(caller(thread), c, label, line, priority, edge)?;
    let h = process::insert_handle(caller(thread), Object::Irq(b), OWNER_RIGHTS);
    // SAFETY: the reference `bind` handed out goes; the handle, if it went
    // in, holds the binding, and without it the binding and its line go.
    unsafe { irq::release_handle(b, cause(thread)) };
    Ok(Values::new(&[h?.0]))
}

/// irq_ack(x0 binding with MANAGE): the line an interrupt masked opens
/// again (spec 9); an open line stays open, 0 all the same. PEER_CLOSED once
/// the binding's channel closed, and the line stays masked.
fn irq_ack(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let b = lookup(thread, a[0], Rights::MANAGE, Object::irq)?;
    irq::ack(b)?;
    Ok(Values::NONE)
}

/// object_info(x0 handle, x1 kind, x2 reserved and 0): the kind and x2
/// first (INVALID_ARGS), then the handle. For a process handle with any
/// rights: PROCESS_STATE returns abi::ProcessState::to_words in x1-x4,
/// PROCESS_MEMORY the quota (abi::ProcessMemory) and PROCESS_HANDLES the
/// table (abi::ProcessHandles) in x1-x3. KERNEL_STATS takes the system
/// resource with KSTATS and returns abi::KernelStats in x1-x8 (spec 16).
/// MEMORY takes a memory object's handle, a device window's too, with any
/// rights and returns abi::MemoryInfo in x1-x3; THREAD_STATE a thread's and
/// returns abi::ThreadInfo in x1-x4; CHANNEL a channel's, a labelled copy
/// too, and returns abi::ChannelInfo in x1-x4; IRQ an interrupt binding's
/// and returns abi::IrqInfo in x1-x3.
fn object_info(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    reserved_arg(a[2])?;
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
        abi::INFO_MEMORY => {
            let m = lookup(thread, a[0], Rights::NONE, Object::memory)?;
            Ok(Values::new(&memory::info(m).to_words()))
        }
        abi::INFO_THREAD_STATE => {
            let t = lookup(thread, a[0], Rights::NONE, Object::thread)?;
            Ok(Values::new(&thread::info(t).to_words()))
        }
        abi::INFO_CHANNEL => {
            let c = lookup(thread, a[0], Rights::NONE, Object::channel)?;
            Ok(Values::new(&channel::info(c).to_words()))
        }
        abi::INFO_IRQ => {
            let b = lookup(thread, a[0], Rights::NONE, Object::irq)?;
            Ok(Values::new(&irq::info(b).to_words()))
        }
        _ => Err(Error::InvalidArgs),
    }
}

/// What the kernel counts about itself, for KERNEL_STATS: the scheduler's
/// idle time and latencies, the cleanup queue, the frames, the pages of
/// the pools and of the page logs of their payers, and the longest portion
/// of firings of timers.
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
        longest_firing: timer::longest_firing(),
    }
}

/// debug_write(x0 system resource with DEBUG, x1 length up to 64, x2-x9
/// the bytes as abi::inline_words packs them): writes the bytes to the
/// console at once, interrupts masked, and returns their count in x1.
fn debug_write(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let len = inline_len_arg(a[1])?;
    lookup(thread, a[0], Rights::DEBUG, Object::resource)?;
    let words: &[u64; 8] = a[2..].try_into().expect("x2-x9");
    crate::console::write_bytes(&abi::inline_bytes(words)[..len]);
    Ok(Values::new(&[a[1]]))
}
