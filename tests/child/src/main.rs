// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The child program of the test init (spec 15.2): the second file of the
//! test boot image, which the test init loads with rt::loader. As it
//! starts, a child adds 1 to its mark STARTED, in the page its parent
//! mapped at child::MARKS, then asks for its start data through
//! abi::START_CHANNEL (spec 13.3): the reply names its role, with up to
//! seven arguments and four handles (lib.rs). The child ends with the code
//! its role returns, or by the fault its role exists for.

#![no_std]
#![no_main]

use abi::{Access, Call, Error, Policy, ProcessState, Rights};
use child::{
    ARGS, BIND, CEILING, Checked, FAILED, FAULT_AT, FULL, HELLO, HELPER, IMAGE, MADE, MARKS,
    MOST_USED, NO_FAULT, QUOTA, ROUNDS, Role, SCRATCH, SCRATCH_LAST, SCRATCH_PAGES, SEEN, SHARED,
    STARTED, WINDOW, marked, x0_alone,
};
use core::mem::ManuallyDrop;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use rt::handle::{Channel, Memory, Process, Resource, Thread};
use rt::sys::{self, Received};
use rt::{Handle, Stack, loader, msgbuf};

rt::entry!(main);

const PAGE: u64 = 4096;
/// The bytes of the scratch mapping (child::SCRATCH).
const SCRATCH_LEN: u64 = SCRATCH_PAGES as u64 * PAGE;
/// Copies of handles Role::Churn holds at a time: more than the table of
/// a child its parent made for it takes.
const HELD_MAX: usize = 1024;

/// `ret`, the word Role::RunData writes and branches to: a word of the
/// data segment.
static DATA: AtomicU32 = AtomicU32::new(0);
/// The copies Role::Churn holds.
static HELD: [AtomicU64; HELD_MAX] = [const { AtomicU64::new(0) }; HELD_MAX];
/// The stacks of the helper threads of a role.
static STACKS: [Stack<8192>; 2] = [const { Stack::new() }; 2];

/// The reply to the start request. The child holds its handles until it
/// ends; the roles view them (`Handle::borrowed`).
struct Start {
    role: Role,
    args: [u64; ARGS],
    handles: [abi::Handle; abi::MESSAGE_HANDLES],
}

/// A view of the start channel, entry 0 of the child's table (spec 13.3),
/// which the child holds until it ends.
fn parent() -> ManuallyDrop<Handle<Channel>> {
    Handle::borrowed(abi::START_CHANNEL)
}

fn main(_: u64) -> u64 {
    mark(STARTED).fetch_add(1, Relaxed);
    match ask() {
        Ok(start) => run(&start),
        Err(_) => FAILED,
    }
}

/// Mark `i` in the page at MARKS.
fn mark(i: usize) -> &'static AtomicU64 {
    // SAFETY: the parent mapped the page of marks, readable and writable,
    // before the child started; it stays while the child lives, and the
    // words are only reached as atomics.
    unsafe { &*(MARKS as *const AtomicU64).add(i) }
}

/// The start request (spec 13.3): HELLO through START_CHANNEL; the reply
/// holds the role's code, its arguments and its handles.
fn ask() -> Result<Start, Error> {
    let mut reply = sys::send(&parent(), &HELLO.to_le_bytes())?;
    let role = Role::from_code(reply.words[0]).ok_or(Error::InvalidArgs)?;
    let mut args = [0; ARGS];
    args.copy_from_slice(&reply.words[1..]);
    let handles = core::array::from_fn(|i| {
        reply
            .handles
            .take_any(i)
            .map_or(abi::Handle::INVALID, Handle::into_raw)
    });
    Ok(Start {
        role,
        args,
        handles,
    })
}

fn run(s: &Start) -> u64 {
    let a = &s.args;
    match s.role {
        Role::Exit => a[0],
        Role::Echo => echo(a),
        Role::Recurse => deeper(0),
        Role::Panic => {
            rt::console::set(Handle::<Resource>::from_raw(s.handles[0]));
            panic!("{}", child::PANIC)
        }
        Role::Load => {
            let at = mark(FAULT_AT).as_ptr();
            // SAFETY: the load is the fault the role exists for; its address
            // goes to mark FAULT_AT first.
            unsafe {
                core::arch::asm!(
                    "adr {t}, 2f",
                    "str {t}, [{at}]",
                    "2: ldr {t}, [{a}]",
                    t = out(reg) _,
                    at = in(reg) at,
                    a = in(reg) a[0],
                    options(nostack),
                )
            };
            NO_FAULT
        }
        Role::WriteCode => {
            let own = Handle::<Process>::borrowed(s.handles[0]);
            // SAFETY: the call must fail; had it passed, the code would
            // only have become writable.
            let protected =
                unsafe { sys::mem_protect(&own, a[0] as usize, a[1], Access::ReadWrite) };
            if protected != Err(Error::AccessDenied) {
                return FAILED;
            }
            let code = main as fn(u64) -> u64 as usize;
            // SAFETY: the store is the fault the role exists for.
            unsafe { (code as *mut u32).write_volatile(0) };
            NO_FAULT
        }
        Role::RunData => {
            let own = Handle::<Process>::borrowed(s.handles[0]);
            let parts = [(a[0], a[1]), (a[2], a[3]), (MARKS as u64, PAGE)];
            let denied = parts.iter().all(|&(at, len)| {
                // SAFETY: the call must fail; had it passed, the child
                // would only fault sooner.
                let made = unsafe { sys::mem_protect(&own, at as usize, len, Access::ReadExec) };
                made == Err(Error::AccessDenied)
            });
            if !denied {
                return FAILED;
            }
            DATA.store(0xD65F_03C0, Relaxed);
            let data = (&raw const DATA).cast::<()>();
            // SAFETY: the branch is the fault the role exists for.
            let f = unsafe { core::mem::transmute::<*const (), extern "C" fn()>(data) };
            f();
            NO_FAULT
        }
        Role::WriteProtected => with_scratch(s, |own, at| {
            let Some(access) = Access::from_raw(a[0]) else {
                return FAILED;
            };
            // SAFETY: the pages are the child's own, readable and writable
            // until mem_protect, which nothing but this role uses.
            let protected = unsafe {
                at.write_volatile(1);
                sys::mem_protect(own, SCRATCH, SCRATCH_LEN, access)
            };
            if protected.is_err() {
                return FAILED;
            }
            // SAFETY: the store is the fault the role exists for.
            unsafe { at.write_volatile(2) };
            NO_FAULT
        }),
        Role::ReadUnmapped => with_scratch(s, |own, at| {
            // SAFETY: the page is the child's own, readable and writable.
            let seen = unsafe {
                at.write_volatile(1);
                at.read_volatile()
            };
            // SAFETY: nothing but this role uses the pages.
            if seen != 1 || unsafe { sys::mem_unmap(own, SCRATCH, SCRATCH_LEN) }.is_err() {
                return FAILED;
            }
            // SAFETY: the load is the fault the role exists for.
            unsafe { at.read_volatile() };
            NO_FAULT
        }),
        Role::Grandparent => grandparent(s).unwrap_or(FAILED),
        Role::Spin => {
            let count = mark(a[0] as usize);
            loop {
                count.fetch_add(1, Relaxed);
            }
        }
        Role::Churn => churn(s, a[0]),
        Role::Wfi => {
            let at = mark(FAULT_AT).as_ptr();
            // SAFETY: the instruction is the fault the role exists for; its
            // address goes to mark FAULT_AT first.
            unsafe {
                core::arch::asm!(
                    "adr {t}, 2f",
                    "str {t}, [{at}]",
                    "2: wfi",
                    t = out(reg) _,
                    at = in(reg) at,
                    options(nostack),
                )
            };
            NO_FAULT
        }
        Role::LastThread => last_thread(s),
        Role::ExitProcess => match helper(s, 0, a[1] as u8, mark_helper) {
            Ok(_) => sys::process_exit(a[0]),
            Err(_) => FAILED,
        },
        Role::KillItself => {
            let own = Handle::<Process>::borrowed(s.handles[0]);
            match helper(s, 0, a[0] as u8, mark_helper) {
                // A kill of its own process does not return.
                Ok(_) => sys::process_kill(&own).map_or(FAILED, |()| FAILED),
                Err(_) => FAILED,
            }
        }
        Role::Notify => match sys::notify(&parent(), a[0]) {
            Ok(()) => 0,
            Err(e) => e.code(),
        },
        Role::Reply => {
            let mut x = marked();
            x[..3].copy_from_slice(&[a[0], 8, a[1]]);
            // SAFETY: reply reads its registers and the caller's buffer.
            let after = unsafe { sys::raw::<{ Call::Reply.number() }>(x) };
            after[0]
        }
        Role::TakeThenExit => {
            let c = Handle::<Channel>::borrowed(s.handles[0]);
            match sys::receive(&c) {
                Ok(Received::Message { .. }) => sys::process_exit(0),
                _ => FAILED,
            }
        }
        Role::Send => {
            let c = Handle::<Channel>::borrowed(s.handles[0]);
            match sys::send(&c, &a[0].to_le_bytes()) {
                Ok(reply) => reply.words[0],
                Err(e) => e.code(),
            }
        }
        Role::BufferBack => buffer_back(s),
        Role::Serve => serve(s, a[0]),
        Role::Ceiling => match Checked::from_code(a[0]) {
            Some(checked) => ceiling(s, checked),
            None => FAILED,
        },
        Role::Service => service(s).unwrap_or(FAILED),
        Role::Provider => provide(s).unwrap_or(FAILED),
        Role::Rtc => drive(s).unwrap_or(FAILED),
        Role::BadHandle | Role::DoubleClose => {
            rt::console::set(Handle::<Resource>::from_raw(s.handles[0]));
            let strict = match s.role {
                Role::BadHandle => bad_handle(),
                _ => double_close(),
            };
            strict.unwrap_or(FAILED)
        }
    }
}

/// Role::Echo.
fn echo(args: &[u64; ARGS]) -> u64 {
    let mut words = [0; 8];
    words[..ARGS].copy_from_slice(args);
    let bytes = abi::inline_bytes(&words);
    match sys::send(&parent(), &bytes[..8 * ARGS]) {
        Ok(reply) => reply.words[0],
        Err(_) => FAILED,
    }
}

/// Role::Recurse: each call keeps a frame the compiler cannot drop.
fn deeper(depth: u64) -> u64 {
    let frame = [depth; 32];
    if depth == u64::MAX {
        return NO_FAULT;
    }
    core::hint::black_box(&frame);
    deeper(depth + 1).wrapping_add(frame[1])
}

/// SCRATCH_PAGES pages of a new object mapped at SCRATCH, RW, through
/// handle 0, the child's own process; `then` gets that handle and the
/// first word of SCRATCH_LAST.
fn with_scratch(s: &Start, then: impl FnOnce(&Handle<Process>, *mut u64) -> u64) -> u64 {
    let own = Handle::<Process>::borrowed(s.handles[0]);
    let Ok(m) = sys::mem_create(SCRATCH_LEN) else {
        return FAILED;
    };
    if sys::mem_map(&own, &m, 0, SCRATCH_LEN, SCRATCH, Access::ReadWrite).is_err() {
        return FAILED;
    }
    then(&own, SCRATCH_LAST as *mut u64)
}

/// Role::Grandparent: the grandchild runs Spin below the child, which then
/// waits in a request to its parent until it is killed.
fn grandparent(s: &Start) -> Result<u64, Error> {
    let [own, image, exit, marks] = s.handles;
    let own = Handle::<Process>::borrowed(own);
    let image = Handle::<Memory>::borrowed(image);
    let exit = Handle::<Channel>::borrowed(exit);
    let marks = Handle::<Memory>::borrowed(marks);
    let size = sys::memory_info(&image)?.size;
    sys::mem_map(&own, &image, 0, size, IMAGE, Access::Read)?;
    // SAFETY: the mapping shows the boot image, read-only, and stays.
    let bytes = unsafe { core::slice::from_raw_parts(IMAGE as *const u8, size as usize) };
    let program = child::program_in(bytes).ok_or(Error::InvalidArgs)?;
    let requests = sys::channel_create(1)?;
    let start = sys::handle_label(&requests, Rights::SEND | Rights::TRANSFER, 1, 1)?;
    let level = s.args[1] as u8;
    let params = loader::Params {
        quota: s.args[0],
        handle_limit: 16,
        ceiling: level,
        exit: Some((&exit, 1)),
        start: Some(start),
        priority: level,
        policy: Policy::Fifo,
    };
    // SAFETY: only the loader uses WINDOW.
    let g = unsafe { loader::load(&own, &program, WINDOW, params) }.map_err(|(e, _)| e)?;
    sys::mem_map(&g.process, &marks, 0, PAGE, MARKS, Access::ReadWrite)?;
    sys::thread_start(&g.thread)?;
    let Received::Message { token, .. } = sys::receive(&requests)? else {
        return Ok(FAILED);
    };
    token.reply(&child::reply(Role::Spin, &[s.args[2]]))?;
    sys::send(&parent(), &[])?;
    Ok(FAILED)
}

/// Role::Churn.
fn churn(s: &Start, total: u64) -> u64 {
    let own = Handle::<Process>::borrowed(s.handles[0]);
    let (mut made, mut rounds, mut full, mut most) = (0, 0, 0, 0);
    while made < total {
        let mut n = 0;
        let error = loop {
            if n == HELD_MAX {
                break Error::LimitReached;
            }
            match sys::handle_duplicate(&own, Rights::NONE) {
                Ok(h) => {
                    HELD[n].store(h.into_raw().0, Relaxed);
                    n += 1;
                }
                Err(e) => break e,
            }
        };
        if let Ok(m) = sys::process_memory(&own) {
            most = most.max(m.used);
            mark(QUOTA).store(m.quota, Relaxed);
        }
        for h in &HELD[..n] {
            if Handle::<Process>::from_raw(abi::Handle(h.load(Relaxed)))
                .close()
                .is_err()
            {
                return FAILED;
            }
        }
        full += u64::from(error == Error::NoMemory);
        rounds += 1;
        made += n as u64;
        if n == 0 {
            break;
        }
    }
    mark(MADE).store(made, Relaxed);
    mark(ROUNDS).store(rounds, Relaxed);
    mark(FULL).store(full, Relaxed);
    mark(MOST_USED).store(most, Relaxed);
    0
}

/// The page of the message buffer of helper thread `i`, from 1, above the
/// first thread's (abi::INIT_MSGBUF).
fn buffer(i: usize) -> usize {
    abi::INIT_MSGBUF as usize + i * PAGE as usize
}

/// A helper thread of the child at `priority` on the stack of slot `slot`,
/// started, that runs `entry` with handle 0 of the start data, the child's
/// own process, as its argument.
fn helper(
    s: &Start,
    slot: usize,
    priority: u8,
    entry: extern "C" fn(u64) -> !,
) -> Result<Handle<Thread>, Error> {
    let own = Handle::<Process>::borrowed(s.handles[0]);
    let top = STACKS[slot].top();
    // SAFETY: each helper has a stack of its own, which nothing else uses.
    let t = unsafe {
        sys::thread_create(
            &own,
            entry,
            top,
            own.raw().0,
            priority,
            Policy::Fifo,
            buffer(slot + 1),
        )
    }?;
    sys::thread_start(&t)?;
    Ok(t)
}

/// A helper that marks HELPER and ends.
extern "C" fn mark_helper(_: u64) -> ! {
    mark(HELPER).fetch_add(1, Relaxed);
    sys::thread_exit()
}

/// A helper that marks SEEN when object_info of its process, `own`, says
/// it lives, marks HELPER and ends.
extern "C" fn alive_then_exit(own: u64) -> ! {
    let state = sys::process_state(&Handle::<Process>::borrowed(abi::Handle(own)));
    mark(SEEN).store(u64::from(state == Ok(ProcessState::Alive)), Relaxed);
    mark(HELPER).fetch_add(1, Relaxed);
    sys::thread_exit()
}

/// A helper that marks SEEN when its message buffer reads zero and takes
/// a write, marks HELPER and ends.
extern "C" fn buffer_then_exit(_: u64) -> ! {
    let word = msgbuf::address() as *mut u64;
    // SAFETY: the buffer is the thread's own page, readable and writable
    // while it lives (spec 6.2).
    let fresh = unsafe {
        let zero = word.read_volatile() == 0;
        word.write_volatile(0x5EED);
        zero && word.read_volatile() == 0x5EED
    };
    mark(SEEN).store(u64::from(fresh), Relaxed);
    mark(HELPER).fetch_add(1, Relaxed);
    sys::thread_exit()
}

/// Role::LastThread.
fn last_thread(s: &Start) -> u64 {
    let own = Handle::<Process>::borrowed(s.handles[0]);
    let level = s.args[0] as u8;
    // SAFETY: the stack of slot 1 is the stopped thread's, which never
    // runs.
    let stopped = unsafe {
        sys::thread_create(
            &own,
            mark_helper,
            STACKS[1].top(),
            0,
            level,
            Policy::Fifo,
            buffer(2),
        )
    };
    match (stopped, helper(s, 0, level, alive_then_exit)) {
        (Ok(_), Ok(_)) => sys::thread_exit(),
        _ => FAILED,
    }
}

/// Role::BufferBack.
fn buffer_back(s: &Start) -> u64 {
    let own = Handle::<Process>::borrowed(s.handles[0]);
    let me = Handle::<Thread>::borrowed(s.handles[1]);
    let level = s.args[0] as u8;
    let used = || sys::process_memory(&own).map_or(0, |m| m.used);
    let before = used();
    let Ok(t) = helper(s, 0, level, buffer_then_exit) else {
        return FAILED;
    };
    let charged = used();
    // The helper runs, and ends, before the child does again.
    if sys::thread_set_priority(&me, level - 1, Policy::Fifo).is_err() {
        return FAILED;
    }
    let after = used();
    let ended = sys::thread_set_priority(&t, level, Policy::Fifo);
    let closed = t.close();
    match () {
        () if mark(SEEN).load(Relaxed) != 1 => 1,
        () if before == 0 || charged <= before => 2,
        () if after != before => 3,
        () if ended != Err(Error::BadState) || closed.is_err() => 4,
        () => 0,
    }
}

/// Role::Serve.
fn serve(s: &Start, requests: u64) -> u64 {
    let c = Handle::<Channel>::borrowed(s.handles[0]);
    for _ in 0..requests {
        let Ok(Received::Message {
            len, token, words, ..
        }) = sys::receive(&c)
        else {
            return FAILED;
        };
        let bytes = abi::inline_bytes(&words);
        if token.reply(&bytes[..len.min(abi::INLINE_MAX)]).is_err() {
            return FAILED;
        }
    }
    0
}

/// Role::Ceiling: 0 when each case of `checked` did as it must, else the
/// number of the first that did not, from 1. Handles the child makes
/// itself: one it closed, a channel, and a copy with NOTIFY of a channel
/// that closed.
fn ceiling(s: &Start, checked: Checked) -> u64 {
    let [thread, process, ..] = s.handles.map(|h| h.0);
    let (above, at) = (u64::from(CEILING) + 1, u64::from(CEILING));
    let (rr, fifo) = (Policy::RoundRobin as u64, Policy::Fifo as u64);
    let denied = Error::AccessDenied.code();
    let (bad, closed_channel) = (Error::BadHandle.code(), Error::PeerClosed.code());
    let Ok((closed, channel, left)) = made() else {
        return FAILED;
    };
    let h = channel.raw().0;
    let notify = u64::from(Rights::NOTIFY.0);
    let first_wrong = |cases: &[bool]| cases.iter().position(|&ok| !ok).map_or(0, |i| i as u64 + 1);
    match checked {
        Checked::ThreadSetPriority => {
            const N: u16 = Call::ThreadSetPriority.number();
            first_wrong(&[
                x0_alone::<N>(&[thread, above, rr], denied),
                x0_alone::<N>(&[thread, at, rr], 0),
            ])
        }
        Checked::ThreadCreate => {
            const N: u16 = Call::ThreadCreate.number();
            let args = [process, 0x1000, 0x80_1000, 7, above, fifo, 0x3000];
            first_wrong(&[x0_alone::<N>(&args, denied)])
        }
        Checked::ProcessCreate => {
            const N: u16 = Call::ProcessCreate.number();
            let over = abi::MAX_MEMORY;
            first_wrong(&[
                x0_alone::<N>(&[PAGE, 16, above, closed, 5, 0], bad),
                x0_alone::<N>(&[PAGE, 16, above, 0, 0, closed], bad),
                x0_alone::<N>(&[PAGE, 16, above, 0, 0, 0], denied),
                x0_alone::<N>(&[over, 16, above, 0, 0, 0], denied),
                x0_alone::<N>(&[over, 16, at, 0, 0, 0], Error::NoMemory.code()),
            ])
        }
        Checked::ExitChannel => {
            const N: u16 = Call::ProcessCreate.number();
            let q = 2 * PAGE;
            first_wrong(&[
                x0_alone::<N>(&[q, 16, 20, closed, above, h], bad),
                x0_alone::<N>(&[q, 16, 20, h, above, closed], bad),
                x0_alone::<N>(&[q, 16, 20, h, above, 0], denied),
                x0_alone::<N>(&[q, 16, 20, left, above, 0], denied),
                x0_alone::<N>(&[q, 16, 20, left, at, 0], closed_channel),
            ])
        }
        Checked::CreateChannel => {
            const N: u16 = Call::CreateChannel.number();
            first_wrong(&[x0_alone::<N>(&[above], denied)])
        }
        Checked::Label => {
            const N: u16 = Call::HandleDuplicate.number();
            let refused = [
                x0_alone::<N>(&[closed, notify, 7, above], bad),
                x0_alone::<N>(&[h, notify, 7, above], denied),
            ];
            let Ok(first) =
                sys::handle_label(&channel, Rights::NOTIFY | Rights::DUPLICATE, 7, CEILING)
            else {
                return FAILED;
            };
            let f = first.raw().0;
            first_wrong(&[
                refused[0],
                refused[1],
                x0_alone::<N>(&[f, notify, 8, above], denied),
                x0_alone::<N>(&[f, notify, 8, at], Error::BadState.code()),
            ])
        }
        Checked::TimerCreate => {
            const N: u16 = Call::TimerCreate.number();
            first_wrong(&[x0_alone::<N>(&[h, above], denied)])
        }
    }
}

/// A handle the child closed, a channel, and a copy with NOTIFY of a
/// channel that closed with its last handle with RECEIVE.
fn made() -> Result<(u64, Handle<Channel>, u64), Error> {
    let gone = sys::channel_create(1)?;
    let closed = gone.raw().0;
    gone.close()?;
    let channel = sys::channel_create(10)?;
    let shut = sys::channel_create(10)?;
    let left = sys::handle_duplicate(&shut, Rights::NOTIFY)?;
    shut.close()?;
    Ok((closed, channel, left.into_raw().0))
}

/// x0 of a call that returns nothing else: 0, or the code of its error.
fn code(result: Result<(), Error>) -> u64 {
    result.map_or_else(Error::code, |()| 0)
}

/// Role::Service.
fn service(s: &Start) -> Result<u64, Error> {
    let requests = Handle::<Channel>::borrowed(s.handles[0]);
    let own = Handle::<Process>::borrowed(s.handles[1]);
    let Received::Message {
        mut handles,
        token,
        words,
        ..
    } = sys::receive(&requests)?
    else {
        return Ok(FAILED);
    };
    let (Some((kind, rights)), 1) = (handles.info(0), handles.len()) else {
        return Ok(FAILED);
    };
    let m = handles.take::<Memory>(0)?;
    let (len, word) = (words[0], words[1]);
    let mut answer = [0; 8];
    answer[0] = abi::msgbuf::info(kind, rights);
    let shared = sys::mem_map(&own, &m, 0, len, SHARED, Access::ReadWrite);
    answer[3] = code(shared);
    if shared.is_err() {
        answer[4] = code(sys::mem_map(&own, &m, 0, len, SHARED, Access::ReadExec));
        sys::mem_map(&own, &m, 0, len, SHARED, Access::Read)?;
        // SAFETY: the calls must fail; had they passed, the pages would
        // only have become writable or executable.
        unsafe {
            answer[5] = code(sys::mem_protect(&own, SHARED, len, Access::ReadWrite));
            answer[6] = code(sys::mem_protect(&own, SHARED, len, Access::ReadExec));
        }
    }
    let at = SHARED as *mut u64;
    // SAFETY: the mapping shows `len` bytes at SHARED, readable, and
    // writable when `shared` passed; nothing else uses them.
    unsafe {
        answer[2] = at.read_volatile();
        answer[1] =
            (0..len as usize / 8).fold(0u64, |sum, i| sum.wrapping_add(at.add(i).read_volatile()));
        if shared.is_ok() {
            at.add(1).write_volatile(word);
        }
        sys::mem_unmap(&own, SHARED, len)?;
    }
    m.close()?;
    token.reply(&abi::inline_bytes(&answer)[..7 * 8])?;
    Ok(0)
}

/// Role::Provider.
fn provide(s: &Start) -> Result<u64, Error> {
    let requests = Handle::<Channel>::borrowed(s.handles[0]);
    let own = Handle::<Process>::borrowed(s.handles[1]);
    let Received::Message { token, words, .. } = sys::receive(&requests)? else {
        return Ok(FAILED);
    };
    let (pages, seed) = (words[0], words[1]);
    let len = pages * PAGE;
    let m = sys::mem_create(len)?;
    sys::mem_map(&own, &m, 0, len, SHARED, Access::ReadWrite)?;
    let at = SHARED as *mut u64;
    // SAFETY: the mapping shows the object's `len` bytes at SHARED,
    // readable and writable, and nothing else uses them.
    unsafe {
        for i in 0..len as usize / 8 {
            at.add(i).write_volatile(seed + i as u64);
        }
        sys::mem_unmap(&own, SHARED, len)?;
    }
    let used = sys::process_memory(&own)?.used;
    let copy = sys::handle_duplicate(&m, Rights::MAP_READ | Rights::TRANSFER)?;
    m.close()?;
    token
        .reply_handles(&used.to_le_bytes(), [copy.erase()])
        .map_err(|r| r.error)?;
    Ok(0)
}

/// Role::Rtc: the binding comes in the reply to BIND and stays with the
/// child; the request after the interrupt, or with word 0 other than 0 the
/// one after the reply, waits until the child dies.
fn drive(s: &Start) -> Result<u64, Error> {
    let c = sys::channel_create(1)?;
    let notify = sys::handle_duplicate(&c, Rights::NOTIFY | Rights::TRANSFER)?;
    let hold = s.args[0] != 0;
    let mut reply = if hold {
        let seen = sys::handle_duplicate(&c, Rights::RECEIVE | Rights::TRANSFER)?;
        let handles = [notify.erase(), seen.erase()];
        sys::send_handles(&parent(), &BIND.to_le_bytes(), handles).map_err(|r| r.error)?
    } else {
        sys::send_handles(&parent(), &BIND.to_le_bytes(), [notify.erase()]).map_err(|r| r.error)?
    };
    let (Some((kind, rights)), 1) = (reply.handles.info(0), reply.handles.len()) else {
        return Ok(FAILED);
    };
    // The binding stays with the child until it ends.
    let _binding = reply.handles.take_any(0)?;
    if hold {
        sys::send(&parent(), &BIND.to_le_bytes())?;
        return Ok(FAILED);
    }
    let Received::Notification {
        source,
        label,
        bits,
        count,
    } = sys::receive(&c)?
    else {
        return Ok(FAILED);
    };
    let words = [
        abi::msgbuf::info(kind, rights),
        source.code(),
        label,
        bits,
        count.into(),
        0,
        0,
        0,
    ];
    sys::send(&parent(), &abi::inline_bytes(&words)[..5 * 8])?;
    Ok(FAILED)
}

/// Role::BadHandle.
fn bad_handle() -> Result<u64, Error> {
    let gone = sys::channel_create(1)?;
    let value = gone.raw();
    gone.close()?;
    match sys::notify(&Handle::<Channel>::borrowed(value), 1) {
        Ok(()) => Ok(FAILED),
        Err(e) => Ok(e.code()),
    }
}

/// Role::DoubleClose.
fn double_close() -> Result<u64, Error> {
    let c = sys::channel_create(1)?;
    let twin = Handle::<Channel>::from_raw(c.raw());
    c.close()?;
    drop(twin);
    Ok(0)
}
