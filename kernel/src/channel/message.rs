// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Requests and their replies (spec 6.1, 6.3, 6.4, 6.6, 6.8): `Via`, `Wait`, receive, send with its fast path, reply, and the end of a wait.

use super::*;

/// What a request went through (spec 5.3, 6.1): a handle to the channel
/// with no label, or one with a label, which names a session of the
/// channel; the receiver gets the label with the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Channel(NonNull<Channel>),
    Session(NonNull<Session>),
}

impl Via {
    /// The channel the request goes into.
    pub fn channel(self) -> NonNull<Channel> {
        match self {
            Via::Channel(c) => c,
            Via::Session(s) => session::channel(s),
        }
    }

    /// The label the receiver gets: the session's, or 0.
    fn label(self) -> u64 {
        match self {
            Via::Channel(_) => 0,
            Via::Session(s) => session::label(s),
        }
    }

    /// A request that waits in the queue holds what it went through from
    /// now on (spec 6.1): the channel, or one more copy of the session, so
    /// that CLIENT_GONE comes after the request (spec 5.3). Only counts, so
    /// it runs under the scheduler's lock.
    fn hold(self) {
        match self {
            Via::Channel(c) => retain(c, Rights::NONE),
            Via::Session(s) => session::retain(s, Rights::NONE),
        }
    }

    /// The reference a wait held goes at `cause`, which may queue what it
    /// held (spec 7.7); the last copy of a session posts CLIENT_GONE
    /// (session::release), so it runs after the scheduler's lock.
    ///
    /// # Safety
    /// The reference is the caller's: `hold` took it, or a wait in receive
    /// holds the channel.
    pub unsafe fn let_go(self, cause: u8) {
        match self {
            // SAFETY: the caller's promise.
            Via::Channel(c) => unsafe { release(c, Rights::NONE, cause) },
            // SAFETY: as above.
            Via::Session(s) => unsafe { session::release(s, Rights::NONE, cause) },
        }
    }
}

/// What a thread waits for, and where its own slot stands meanwhile (spec
/// 6.1, 8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    /// In receive on the channel, its slot in the channel's queue; the wait
    /// holds a reference to the channel.
    Receive(NonNull<Channel>),
    /// In send, its slot, its request, in the queue of the channel it went
    /// through; the wait holds that (`Via::hold`).
    Send(Via),
    /// Its request accepted by a thread of the process, its slot in the
    /// process's queue of accepted requests: it waits for the reply and
    /// holds nothing; the stage Replies of the process wakes it if the
    /// process ends first (spec 6.8).
    Reply(NonNull<Process>),
}

/// What the first look of receive at a channel's queue came to.
enum Looked {
    /// What it took under the scheduler's lock, if anything.
    Done(Option<Taken>),
    /// The request at the head, of this client, whose handles need room in
    /// the receiver's table first.
    Handles(NonNull<Thread>),
}

/// The description of the request of `client`, which waits in `send`: its
/// own x1, which the call checked.
///
/// # Safety
/// `client` is alive.
unsafe fn sent(client: NonNull<Thread>) -> Desc {
    // SAFETY: the caller's promise; only the register is read.
    Desc::from_send(unsafe { (*client.as_ptr()).regs.x[1] })
        .expect("a request's description was checked")
}

/// The handles `values` of a message of `t`, the running thread, go where
/// no table takes them (spec 6.1): out of its process's table, each
/// released at `t`'s priority.
fn drop_handles(t: NonNull<Thread>, values: &[u64]) {
    // SAFETY: the running thread is alive and holds its process.
    let (p, cause) = unsafe { (t.as_ref().process(), t.as_ref().priority()) };
    let moving = process::take_handles(p, values);
    // SAFETY: the references were the handles', which left the table.
    unsafe { object::release_moving(moving, cause) };
}

/// receive (spec 6.1, 6.5, 6.6) for `t`, the running thread, on `c`, to
/// which it holds a handle with RECEIVE, so the channel is open; it writes
/// `t`'s result itself. First the boost of `t`'s last notification or
/// request ends. Then the head of the top level of the queue leaves it: a
/// slot, emptied into x0-x11, after which `t` works at the slot's priority
/// under its ceiling until its next receive, and the slot lets its owner
/// go at that priority after the scheduler's lock; or a request, which `t`
/// takes (`accept`) once its handles have room in the table of `t`'s
/// process (process::reserve_handles), the reference of its sender's wait
/// going after the lock. A request whose handles find no room fails its
/// sender with that error, LIMIT_REACHED or NO_MEMORY, and its handles go at
/// `t`'s priority; the call then starts over at its `svc` with its
/// registers as they were (syscall::restart), and takes the next head
/// (spec 6.1). With nothing queued, WOULD_BLOCK when `wait` is false;
/// otherwise `t` waits through its own slot at the tail of its level,
/// holding a reference to `c`, and gets its result when the wait ends
/// (`post`, `send`, `clean`). O(1).
pub fn receive(t: NonNull<Thread>, c: NonNull<Channel>, wait: bool) -> Result<(), Error> {
    // SAFETY: the current thread is held; inspect its private delivery state.
    if wait && unsafe { t.as_ref() }.upcall.interrupt_wait() {
        return Err(Error::Interrupted);
    }
    let ceiling = ceiling(t);
    let looked = sched::locked(|k| {
        // SAFETY: the running thread and the channel, which its handle
        // holds, are alive; the sender of a queued request waits, so it is
        // alive, and its wait holds what it went through.
        unsafe {
            k.s.unboost(t);
            (*t.as_ptr()).boost_token = 0;
            let q = queue(c, k.s);
            if !q.has_receivers()
                && let Some(slot) = q.head()
            {
                let owner = (*slot.as_ptr()).owner();
                if let Owner::Thread(client) = owner {
                    if sent(client).handles > 0 {
                        // Its handles need room first, which may take a page.
                        return Ok(Looked::Handles(client));
                    }
                    return Ok(Looked::Done(Some(take_request(k, t, c, client, Ok(())))));
                }
                q.take_slot();
                let (n, priority) = notice(slot);
                syscall::set_notification(t, n);
                k.s.boost(t, priority, ceiling);
                return Ok(Looked::Done(Some(Taken::Slot(owner))));
            }
            if !wait {
                return Err(Error::WouldBlock);
            }
            let running = k.s.block();
            assert!(running == t, "a thread that does not run waits");
            let slot = thread::slot(t);
            (*slot.as_ptr()).set_priority(t.as_ref().priority());
            queue(c, k.s).wait(slot);
            (*t.as_ptr()).waits = Some(Wait::Receive(c));
        }
        retain(c, Rights::NONE);
        Ok(Looked::Done(None))
    })?;
    let taken = match looked {
        Looked::Done(taken) => taken,
        Looked::Handles(client) => {
            // SAFETY: the client waits, so it is alive.
            let n = unsafe { sent(client) }.handles;
            // SAFETY: the running thread is alive and holds its process.
            let fit = process::reserve_handles(unsafe { t.as_ref() }.process(), n);
            // SAFETY: nothing changed the queue meanwhile: one CPU, and
            // interrupts are masked in the kernel (spec 8.1).
            Some(sched::locked(|k| unsafe {
                take_request(k, t, c, client, fit)
            }))
        }
    };
    // SAFETY: the running thread is alive; the reference of the slot or of
    // the sender's wait goes, and so do the handles no table took; nothing
    // uses them afterwards.
    unsafe {
        let cause = t.as_ref().priority();
        match taken {
            Some(Taken::Slot(owner)) => owner.let_go(cause),
            Some(Taken::Request(via, sender)) => {
                if let Some(sender) = sender {
                    thread::drop_transit(sender, cause);
                }
                via.let_go(cause);
            }
            None => {}
        }
    }
    Ok(())
}

/// The request of `client`, the head of the queue of `c`, leaves it for
/// `t`'s receive (spec 6.1): with room for its handles (`fit`), `t` takes
/// it (`accept`); otherwise its sender wakes with that error in x0 alone,
/// at the tail of its level with a new quantum, and `t`'s call starts over
/// (syscall::restart). Returns what the request's wait held, and the
/// sender whose handles no table took, for after the lock. O(1).
///
/// # Safety
/// `t` runs; `c` is alive, and `client` waits in send at the head of its
/// queue; `k` is the locked scheduler.
unsafe fn take_request(
    k: &mut Locked<'_>,
    t: NonNull<Thread>,
    c: NonNull<Channel>,
    client: NonNull<Thread>,
    fit: Result<(), Error>,
) -> Taken {
    // SAFETY: the caller's promise; the client's wait holds what it went
    // through, and its handles lie in it.
    unsafe {
        let taken = queue(c, k.s).take_slot();
        assert!(
            taken == Some(thread::slot(client)),
            "the head of a channel's queue moved while its receiver made room"
        );
        let Some(Wait::Send(via)) = (*client.as_ptr()).waits else {
            unreachable!("a request whose thread does not send");
        };
        if let Err(e) = fit {
            (*client.as_ptr()).waits = None;
            syscall::set_result(client, Err(e));
            k.s.wake(client);
            syscall::restart(t);
            return Taken::Request(via, Some(client));
        }
        accept(k, t, client, via, sent(client));
        Taken::Request(via, None)
    }
}

/// send (spec 6.1, 6.3) for `t`, the running thread, through `via`, to
/// which it holds a handle with SEND, with the description `desc` and the
/// handles `values` of its process, all checked; the request is `t`'s own
/// x1-x9. The checks of state in the order of spec 11: BAD_STATE when `t`
/// has no count of requests left (spec 6.1); PEER_CLOSED once the channel
/// closed, and the handles go then, released at `t`'s priority;
/// WOULD_BLOCK with NO_WAIT when no receiver waits. Otherwise the top
/// receiver that waits takes the request at once (`accept`) once its
/// handles have room in the receiver's table (process::reserve_handles):
/// LIMIT_REACHED or NO_MEMORY otherwise, the handles go and the receiver
/// waits on. With the request taken or no receiver waiting, `t` waits for
/// the reply (Ok), its own slot at the level of its effective priority and
/// its handles out of its process's table (process::take_handles): the
/// receiver becomes ready at the tail of its level with a new quantum, the
/// reference of its wait going after the scheduler's lock; or else the
/// slot goes to the tail of its level in the channel's queue (spec 6.3),
/// holding `via` and the handles (Thread::transit) until a receive takes
/// it. A message of registers alone may take the fast path (`fast_send`),
/// and Ok names the receiver then, which the caller runs at once. O(1).
pub fn send(
    t: NonNull<Thread>,
    via: Via,
    desc: Desc,
    values: &[u64],
) -> Result<Option<NonNull<Thread>>, Error> {
    let c = via.channel();
    sched::locked(|k| k.tokens.check_count(thread::index(t)))?;
    if is_closed(c) {
        drop_handles(t, values);
        return Err(Error::PeerClosed);
    }
    // SAFETY: as above; a pending internal deferral cannot enter user code yet.
    // Match Interrupted's transfer contract even before the request is queued.
    if unsafe { t.as_ref() }.upcall.interrupt_wait() {
        drop_handles(t, values);
        return Err(Error::Interrupted);
    }
    if desc.len <= INLINE_MAX
        && values.is_empty()
        && let Some(r) = fast_send(t, via, desc)
    {
        return Ok(Some(r));
    }
    let receiver = sched::locked(|k| {
        // SAFETY: the channel, which the sender's handle holds, is alive; a
        // thread that waits in receive is alive, and its slot lies in it.
        unsafe {
            let q = queue(c, k.s);
            q.has_receivers()
                .then(|| thread_of(q.head().expect("a receiver")))
        }
    });
    if desc.no_wait && receiver.is_none() {
        return Err(Error::WouldBlock);
    }
    if let Some(r) = receiver
        && !values.is_empty()
        // SAFETY: a thread that waits is alive and holds its process.
        && let Err(e) = process::reserve_handles(unsafe { r.as_ref() }.process(), values.len())
    {
        drop_handles(t, values);
        return Err(e);
    }
    if !values.is_empty() {
        // SAFETY: the running thread holds its process, and its handles on
        // their way are its own.
        unsafe { thread::set_transit(t, process::take_handles(t.as_ref().process(), values)) };
    }
    let took = sched::locked(|k| {
        // SAFETY: the running thread and the channel, which its handle
        // holds, are alive; its handles are on their way, with room for
        // them in the table of the receiver's process; nothing changed the
        // queue since it was looked at: one CPU, and interrupts are masked
        // in the kernel (spec 8.1). The receiver it returns is alive.
        unsafe {
            let r = meet(k, t, via, desc);
            assert!(r == receiver, "the receiver of a request changed");
            if let Some(r) = r {
                k.s.wake(r);
            }
            r.is_some()
        }
    });
    if took {
        // SAFETY: the reference was the receiver's wait's; the sender's
        // handle keeps the channel, and the sender is alive.
        unsafe { release(c, Rights::NONE, t.as_ref().priority()) };
    }
    Ok(None)
}

/// The fast path of send (spec 6.4) for `t`, the running thread, through
/// `via`, with `desc`, a message of registers alone: the top receiver that
/// waits in the channel takes the request (`accept`) and runs at once in
/// place of `t` (sched::hand_off), when the top level of the cleanup queue
/// is below the receiver's effective priority after the boost the request
/// gives it, no interrupt is pending, and that priority is above every
/// ready thread's. The state is the one the slow path leaves. The
/// reference of the receiver's wait goes after the scheduler's lock.
/// Returns the receiver, which the caller runs; None, with nothing changed,
/// when a condition fails. O(1).
fn fast_send(t: NonNull<Thread>, via: Via, desc: Desc) -> Option<NonNull<Thread>> {
    let c = via.channel();
    // Read before the scheduler's lock: the locks do not nest.
    let cleanup = cleanup::top();
    let next_timer = timer::first();
    let r = sched::hand_off(next_timer, |k| {
        // SAFETY: the running thread and the channel, which its handle
        // holds, are alive; a thread that waits in receive is alive, and
        // its slot lies in it.
        unsafe {
            let q = queue(c, k.s);
            if !q.has_receivers() {
                return None;
            }
            let r = thread_of(q.head()?);
            let n = &r.as_ref().sched;
            let boost = n.boost().max(t.as_ref().priority().min(ceiling(r)));
            let level = n.base().max(boost);
            if !k.s.can_hand_off(level, cleanup) || arch::irq_pending() || !testpoint::fast_path() {
                return None;
            }
            let taken = meet(k, t, via, desc);
            assert!(taken == Some(r), "the receiver of a request changed");
            Some(r)
        }
    })?;
    // SAFETY: the reference was the receiver's wait's; the sender's handle
    // keeps the channel, and the sender is alive.
    unsafe { release(c, Rights::NONE, t.as_ref().priority()) };
    Some(r)
}

/// The meeting of a request with a receiver, on both paths of send (spec
/// 6.1, 6.3, 6.4): `t`, the running thread, stops running, and its slot
/// goes into the queue of `via`'s channel at `t`'s effective priority. The
/// top receiver that waits there takes the request (`accept`), its wait
/// ended, and is returned; the caller wakes it or runs it. With no
/// receiver waiting, `t` waits in the queue instead, and `via` holds the
/// channel for the wait: None. O(1).
///
/// # Safety
/// Under the scheduler's lock `k`: `t` runs and sends through `via`, whose
/// channel is alive, with `desc`; its handles are on their way, and a
/// receiver that waits has room for them in its process's table.
/// Inlined into both paths: a call of its own costs each of them about 30
/// instructions.
#[inline(always)]
unsafe fn meet(
    k: &mut Locked<'_>,
    t: NonNull<Thread>,
    via: Via,
    desc: Desc,
) -> Option<NonNull<Thread>> {
    // SAFETY: the caller's promise; a thread that waits in receive is
    // alive, and its slot lies in it.
    unsafe {
        let running = k.s.block();
        assert!(running == t, "a thread that does not run sends");
        let slot = thread::slot(t);
        (*slot.as_ptr()).set_priority(t.as_ref().priority());
        let Some(r) = queue(via.channel(), k.s).send(slot) else {
            (*t.as_ptr()).waits = Some(Wait::Send(via));
            via.hold();
            return None;
        };
        let r = thread_of(r);
        (*r.as_ptr()).waits = None;
        accept(k, r, t, via, desc);
        Some(r)
    }
}

/// Writes a message from `from`, its sender, into `to`, the thread it
/// comes to (spec 6.1, 6.2, 11): x0 0, x1 the description, x2-x9 bytes
/// 0-63 from the sender's registers, zero past the length; bytes 64 up to
/// the length go from the sender's message buffer into the receiver's, at
/// the same offsets (thread::copy_message); the handles on their way in
/// `from` (Thread::transit) go into the table of `to`'s process, which
/// made room for them, and their values and info words into `to`'s buffer
/// (process::put_handles, thread::write_handles). O(1): at most 960 bytes
/// and four handles.
///
/// # Safety
/// `to` and `from` are alive and differ; nothing else borrows their
/// registers or buffers; `from` carries `desc.handles` handles.
unsafe fn deliver(to: NonNull<Thread>, from: NonNull<Thread>, desc: Desc) {
    // SAFETY: the caller's promise; the two threads are two objects.
    unsafe {
        let x = &mut (*to.as_ptr()).regs.x;
        x[0] = 0;
        x[1] = desc.result();
        // Word by word: a copy of the slice would be a call of `memcpy`.
        let f = &from.as_ref().regs.x;
        [x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9]] =
            [f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9]];
        mask_tail(&mut x[2..10], desc.len);
        if desc.len > INLINE_MAX {
            thread::copy_message(to, from, INLINE_MAX..desc.len);
        }
        if desc.handles > 0 {
            let put = process::put_handles(to.as_ref().process(), thread::take_transit(from));
            thread::write_handles(to, &put[..desc.handles]);
        }
    }
}

/// The request of `client` goes to `r`, the receiver, in its receive (spec
/// 6.1, 6.6): the client's count grows by 1 and the token names the
/// request; the client's own slot goes to the tail of its level in the
/// queue of accepted requests of `r`'s process, where the client waits for
/// the reply; x0-x11 of `r` get the message (`deliver`) with its handles,
/// the label of `via` and the token; and `r` works at the client's level,
/// under its own ceiling, until its reply with this token or its next
/// receive. O(1).
///
/// # Safety
/// `r` and `client` are alive and differ; `client` waits in send through
/// `via` with the description `desc` and carries its handles, its slot in
/// no queue; the table of `r`'s process has room for them; `r` has no
/// boost.
unsafe fn accept(
    k: &mut Locked<'_>,
    r: NonNull<Thread>,
    client: NonNull<Thread>,
    via: Via,
    desc: Desc,
) {
    let token = k.tokens.accept(thread::index(client));
    // SAFETY: the caller's promise; the two threads' registers are two
    // objects.
    unsafe {
        let p = r.as_ref().process();
        let slot = thread::slot(client);
        process::accepted(p, k.s).push_tail(slot);
        (*client.as_ptr()).waits = Some(Wait::Reply(p));
        deliver(r, client, desc);
        let to = &mut (*r.as_ptr()).regs.x;
        to[10] = via.label();
        to[11] = token;
        k.s.boost(r, (*slot.as_ptr()).priority(), ceiling(r));
        (*r.as_ptr()).boost_token = token;
    }
}

/// reply (spec 6.1, 6.6) of `t`, the running thread, with its x1-x9, the
/// description `desc` and the handles `values` of its process, all
/// checked, to the request `token` names. A reply with the token of `t`'s
/// boost ends the boost first, whatever comes of it (spec 6.6). Then
/// BAD_STATE when the token names no request that waits for a reply from
/// `t`'s process: a number outside the table, a count other than the
/// number's last, or a client that waits for no reply or for one from
/// another process; nothing else happens then. PEER_CLOSED when its client
/// ended while it waited (Table::mark_dead, spec 6.8), each time it is
/// tried, and the handles go. Otherwise the token is used up: the client
/// leaves the queue of accepted requests and becomes ready at the tail of
/// its level with a new quantum, its registers holding the message with
/// its handles (`deliver`) once they have room in the client's table
/// (process::reserve_handles); with no room the reply and the client's
/// send both fail with LIMIT_REACHED or NO_MEMORY, in x0 alone, and the
/// handles go. Handles that go are released at `t`'s priority. Never
/// waits. O(1).
pub fn reply(t: NonNull<Thread>, token: u64, desc: Desc, values: &[u64]) -> Result<(), Error> {
    let client = sched::locked(|k| {
        // SAFETY: the running thread is alive; so is a thread whose number
        // is taken (it gives the number back as it ends); a client that
        // waits is not `t`.
        unsafe {
            if token != 0 && (*t.as_ptr()).boost_token == token {
                k.s.unboost(t);
                (*t.as_ptr()).boost_token = 0;
            }
            let client = k.tokens.check(token)?;
            if (*client.as_ptr()).waits != Some(Wait::Reply(t.as_ref().process())) {
                return Err(Error::BadState);
            }
            Ok(client)
        }
    });
    let client = match client {
        Err(Error::PeerClosed) => {
            drop_handles(t, values);
            return Err(Error::PeerClosed);
        }
        client => client?,
    };
    // SAFETY: the running thread and the client that waits for its reply
    // are alive and hold their processes; the running thread's handles on
    // their way are its own.
    let fit = unsafe {
        if values.is_empty() {
            Ok(())
        } else {
            let fit = process::reserve_handles(client.as_ref().process(), values.len());
            thread::set_transit(t, process::take_handles(t.as_ref().process(), values));
            fit
        }
    };
    sched::locked(|k| {
        // SAFETY: as above; the process that took the request holds the
        // client's slot, and nothing changed since the check: one CPU, and
        // interrupts are masked in the kernel (spec 8.1).
        unsafe {
            let p = t.as_ref().process();
            process::accepted(p, k.s).remove(thread::slot(client));
            (*client.as_ptr()).waits = None;
            match fit {
                Ok(()) => deliver(client, t, desc),
                Err(e) => syscall::set_result(client, Err(e)),
            }
            k.s.wake(client);
        }
    });
    if fit.is_err() {
        // SAFETY: the running thread is alive, and no table took its
        // handles.
        unsafe { thread::drop_transit(t, t.as_ref().priority()) };
    }
    fit
}

/// Withdraw the send or receive of `t` (interrupt): its slot leaves the
/// channel's queue it stands in, wherever it stands there. What the wait
/// held, a channel or a session, goes to the caller, which lets it go once
/// the scheduler has let the thread go (`Via::let_go`); the handles of a
/// request stay in the thread until interrupt drops its transit. A wait
/// for the reply to an accepted request is never withdrawn: it stays as it
/// is, and None comes back, as for a thread that waits for nothing; the
/// reply comes once (spec 6.1). O(1).
///
/// # Safety
/// `t` is alive; `k` is the locked scheduler.
pub unsafe fn withdraw(t: NonNull<Thread>, k: &mut Locked<'_>) -> Option<Via> {
    let slot = thread::slot(t);
    // SAFETY: the caller's promise; a wait holds its channel or session.
    unsafe {
        let waits = &mut (*t.as_ptr()).waits;
        match *waits {
            Some(Wait::Receive(c)) => {
                *waits = None;
                queue(c, k.s).cancel(slot);
                Some(Via::Channel(c))
            }
            Some(Wait::Send(via)) => {
                *waits = None;
                queue(via.channel(), k.s).cancel(slot);
                Some(via)
            }
            Some(Wait::Reply(_)) | None => None,
        }
    }
}

/// Abandon the current wait of `t` on exit: a send or receive is withdrawn
/// (`withdraw`); a slot in the queue of accepted requests of the process
/// that took its request leaves that queue, and its last accepted request
/// is marked dead (Table::mark_dead), so the reply finds PEER_CLOSED and a
/// new owner of the number never takes the old token. None for a thread
/// that waits for nothing, or for a reply. O(1).
///
/// # Safety
/// As for `withdraw`.
pub unsafe fn cancel(t: NonNull<Thread>, k: &mut Locked<'_>) -> Option<Via> {
    let slot = thread::slot(t);
    // SAFETY: the caller's promise; the process that accepted the request
    // holds the slot.
    unsafe {
        if let Some(Wait::Reply(p)) = (*t.as_ptr()).waits {
            (*t.as_ptr()).waits = None;
            process::accepted(p, k.s).remove(slot);
            k.tokens.mark_dead(thread::index(t));
            return None;
        }
        withdraw(t, k)
    }
}

/// thread_set_priority of `t` (sched::set_priority): the slot of a thread
/// that waits moves in its queue, a channel's or that of accepted
/// requests, to the level of the thread's new effective priority, by the
/// rules of the ready queue (spec 6.1, 6.3). Returns the wait, for `raise`
/// after the scheduler's lock. O(1).
///
/// # Safety
/// As for `withdraw`.
pub unsafe fn requeue(t: NonNull<Thread>, k: &mut Locked<'_>) -> Option<Wait> {
    let slot = thread::slot(t);
    // SAFETY: the caller's promise, as in `withdraw`.
    unsafe {
        let level = t.as_ref().priority();
        let waits = (*t.as_ptr()).waits;
        match waits {
            Some(Wait::Receive(c)) => queue(c, k.s).move_to(slot, level),
            Some(Wait::Send(via)) => queue(via.channel(), k.s).move_to(slot, level),
            Some(Wait::Reply(p)) => process::accepted(p, k.s).move_to(slot, level),
            None => {}
        }
        waits
    }
}

/// After `requeue` of a thread that waits in `w`, once the scheduler's lock
/// went (sched::set_priority, spec 7.7): a channel at its stage Close, or a
/// process at its stage Replies, goes up in the cleanup queue to the level
/// of its top waiter when that is higher. O(1).
///
/// # Safety
/// The thread still waits in `w`, which keeps the channel, or the process's
/// shell, alive.
pub unsafe fn raise(w: Wait) {
    let c = match w {
        Wait::Receive(c) => c,
        Wait::Send(via) => via.channel(),
        // SAFETY: the caller's promise.
        Wait::Reply(p) => return unsafe { process::raise_replies(p) },
    };
    if !is_closed(c) {
        return;
    }
    // SAFETY: as above; a closed channel with a thread in its queue stands
    // in the cleanup queue at its stage Close.
    unsafe {
        let p = c.as_ptr();
        let top = sched::locked(|k| queue(c, k.s).top()).expect("the thread's slot is queued");
        let item = NonNull::new_unchecked(&raw mut (*p).cleanup);
        cleanup::raise_above(item, top.max((*p).cause));
    }
}
