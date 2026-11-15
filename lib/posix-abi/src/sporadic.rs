// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! SCHED_SPORADIC of the threads (XSH 2.8.4; plan 4b): the sporadic server
//! parameters each thread holds and the path to its kernel time budget.
//!
//! The thread's parameters are in a table of the layer (`SLOTS` threads at
//! most, as the process service has it), since the thread block is shared
//! with relibc and stays as it is. A thread's budget is made by init and
//! kept by the process service (proto_process `Method::Budget`); the layer
//! asks for one (`ask`), binds it to the thread with the one call of the
//! kernel that holds the thread's budget (`budget_call`) and tells the
//! service how the bind went (`done`). A thread that leaves the policy
//! (`leave`) or ends (`forget`) gives its share back through the service.
//!
//! The budget lives on a CPU, and its thread on the same one: the layer
//! keeps the CPU of each thread it made (`note_cpu`); the calling thread's
//! is the CPU it runs on.

use crate::budget_call;
use crate::constants::*;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use posix_sync::LayerLock;
use posix_types::sporadic::Ss;
use proto_process::Method;
use proto_process::sporadic as proto;
use rt::abi::Rights;
use rt::handle::{Budget, Handle, Thread};
use rt::sys;

/// The threads of a process that run under a sporadic server at once.
pub const SLOTS: usize = proto::THREADS_MAX;

/// A thread number in the key of the next thread's slot.
const NEXT: u32 = 1 << 31;

struct Slot {
    key: u32,
    ss: Ss,
}

struct Table(UnsafeCell<[Slot; SLOTS]>);
// SAFETY: every access is under LOCK.
unsafe impl Sync for Table {}

static LOCK: LayerLock = LayerLock::new();
static TABLE: Table = Table(UnsafeCell::new(
    [const {
        Slot {
            key: 0,
            ss: Ss {
                low: 0,
                c_ns: 0,
                t_ns: 0,
                max_repl: 0,
            },
        }
    }; SLOTS],
));

fn with<R>(f: impl FnOnce(&mut [Slot; SLOTS]) -> R) -> R {
    let _guard = LOCK.lock();
    // SAFETY: LOCK serializes the access.
    f(unsafe { &mut *TABLE.0.get() })
}

/// The parameters of thread `id`, if it runs under a sporadic server.
pub fn get(id: u64) -> Option<Ss> {
    let key = id as u32;
    with(|t| t.iter().find(|s| s.key == key).map(|s| s.ss))
}

/// The parameters of the thread `id`; false when the table is full.
fn put(key: u32, ss: Ss) -> bool {
    with(|t| {
        if let Some(slot) = t.iter_mut().find(|s| s.key == key) {
            slot.ss = ss;
            return true;
        }
        match t.iter_mut().find(|s| s.key == 0) {
            Some(slot) => {
                *slot = Slot { key, ss };
                true
            }
            None => false,
        }
    })
}

fn take(key: u32) -> Option<Ss> {
    with(|t| {
        let slot = t.iter_mut().find(|s| s.key == key)?;
        slot.key = 0;
        Some(slot.ss)
    })
}

/// The parameters the next thread the calling thread makes starts with
/// (PTHREAD_EXPLICIT_SCHED with SCHED_SPORADIC); `None` forgets them.
pub fn set_next(ss: Option<Ss>) -> Result<(), i32> {
    let key = NEXT | crate::threads::thread_number() as u32;
    match ss {
        Some(ss) if put(key, ss) => Ok(()),
        Some(_) => Err(EAGAIN),
        None => {
            take(key);
            Ok(())
        }
    }
}

/// The parameters the calling thread's next thread takes, once.
pub fn take_next() -> Option<Ss> {
    take(NEXT | crate::threads::thread_number() as u32)
}

/// Forgets everything of the parent: a child of a fork has no budget and
/// none of its threads' parameters.
pub fn after_fork() {
    with(|t| {
        for slot in t.iter_mut() {
            slot.key = 0;
        }
    });
}

/// The CPU each thread was made on, plus one (0: not known), by thread
/// number minus one.
static CPUS: [AtomicU8; crate::relibc::PLACES] =
    [const { AtomicU8::new(0) }; crate::relibc::PLACES];

/// Notes that thread `id` runs on `cpu`.
pub fn note_cpu(id: u64, cpu: usize) {
    if let Some(slot) = usize::try_from(id)
        .ok()
        .and_then(|i| i.checked_sub(1))
        .and_then(|i| CPUS.get(i))
    {
        slot.store(cpu as u8 + 1, Ordering::Relaxed);
    }
}

/// The CPU of thread `id`: the calling thread's own, or the one noted when
/// the layer made the thread, or the caller's for a thread it knows nothing
/// of (the kernel refuses a bind that names another CPU than the thread's).
fn cpu_of(id: u64) -> usize {
    if crate::threads::thread_number() == id {
        return crate::cpus::current();
    }
    usize::try_from(id)
        .ok()
        .and_then(|i| i.checked_sub(1))
        .and_then(|i| CPUS.get(i))
        .map(|c| c.load(Ordering::Relaxed))
        .filter(|&c| c != 0)
        .map_or_else(crate::cpus::current, |c| usize::from(c) - 1)
}

/// The CPU a thread the caller makes next runs on: the caller's, or the
/// first the process's mask allows (`cpus::new_thread_cpu`).
pub fn next_thread_cpu() -> usize {
    match crate::cpus::new_thread_cpu() {
        0 => crate::cpus::current(),
        cpu => usize::from(cpu) - 1,
    }
}

/// The errno of a status of the service for a request of a budget: the
/// refused share is EPERM (the caller of `pthread_create` and `fork` makes
/// it EAGAIN), numbers the service refuses EINVAL, a busy service EAGAIN.
fn errno_of(status: u32) -> i32 {
    match status {
        proto_process::FULL | proto_process::PERMISSION => EPERM,
        proto_process::INVALID => EINVAL,
        proto_process::AGAIN => EAGAIN,
        proto_process::NO_PROCESS => ESRCH,
        _ => EIO,
    }
}

fn request(op: u32, thread: u64, last: Option<u32>) -> Result<proto_wire::Writer, i32> {
    let mut w = crate::process::request(Method::Budget, &[op, thread as u32])?;
    if let Some(word) = last {
        w.u32(word).map_err(|_| EIO)?;
    }
    Ok(w)
}

/// What the service gave for a request: the budget made and the thread's
/// current one, if it has one.
pub struct Given {
    pub new: Handle<Budget>,
    pub old: Option<Handle<Budget>>,
}

/// Asks the process service for a budget for the thread `id` on `cpu`, from
/// `ss` and `low` (the level of `sched_ss_low_priority`). The reply waits
/// for init's admission. EPERM for a refused share, EINVAL for numbers the
/// kernel refuses, EAGAIN while the thread's request is on.
pub fn ask(id: u64, cpu: usize, ss: &Ss, low: u8) -> Result<Given, i32> {
    let mut w = crate::process::request(Method::Budget, &[proto::ASK])?;
    proto::Ask {
        thread: id as u32,
        cpu: cpu as u32,
        low: u32::from(low),
        max_repl: ss.max_repl,
        c_ns: ss.c_ns,
        t_ns: ss.t_ns,
    }
    .write(&mut w)
    .map_err(|_| EIO)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let mut reply = crate::process::send_again(&w).map_err(|_| EIO)?;
    let mut bytes = proto_wire::Reader::new(reply.bytes(&mut buffer));
    let status = bytes.u32().map_err(|_| EIO)?;
    if status != 0 {
        return Err(errno_of(status));
    }
    let new = reply.handles.take::<Budget>(0).map_err(|_| EIO)?;
    let old = reply.handles.take::<Budget>(1).ok();
    Ok(Given { new, old })
}

/// Tells the service how the bind of the thread `id` went: `bound`, or
/// not (the new share goes back and the old stays).
pub fn done(id: u64, bound: bool) {
    if let Ok(w) = request(proto::DONE, id, Some(u32::from(bound))) {
        let _ = crate::process::ask(&w);
    }
}

/// The thread `id` ended or never started: its budget and its share go back.
pub fn forget(id: u64) {
    take(id as u32);
    if let Ok(w) = request(proto::DROP, id, None) {
        let _ = crate::process::ask(&w);
    }
}

/// A copy of the handle of the thread `native` with MANAGE, for the calls
/// that wait for the service while the thread's place is not pinned.
pub fn manage_copy(native: &Handle<Thread>) -> Result<Handle<Thread>, i32> {
    sys::handle_duplicate(native, Rights::MANAGE).map_err(|_| EIO)
}

/// The errno of a refusal of the bind by the kernel: a thread on another CPU
/// than its budget's, or that runs on one that is not the caller's, is a
/// thread the caller has no say over.
fn bind_errno(e: rt::abi::Error) -> i32 {
    use rt::abi::Error;
    match e {
        Error::BadState | Error::InvalidArgs | Error::AccessDenied => EPERM,
        _ => EIO,
    }
}

/// Gives the thread `id` (handle `thread`, with MANAGE) the sporadic server
/// `ss` with its levels `low`, replacing what it has: a budget from the
/// service, the bind (or the rebind, when it has one) and the report. The
/// table keeps the parameters on success.
pub fn set(id: u64, thread: &Handle<Thread>, ss: Ss, low: u8) -> Result<(), i32> {
    let given = ask(id, cpu_of(id), &ss, low)?;
    let bound = match given.old.as_ref() {
        Some(old) => budget_call::rebind(thread, &given.new, old),
        None => budget_call::bind(thread, &given.new),
    };
    // The copy goes once the kernel holds the budget: the thread keeps it
    // for its life, and the service keeps the handle that can take it off.
    drop(given);
    match bound {
        Ok(()) => {
            done(id, true);
            if put(id as u32, ss) {
                Ok(())
            } else {
                // The table is as large as the service's: it cannot be full
                // when the service had room, but a full table undoes the bind.
                forget(id);
                Err(EAGAIN)
            }
        }
        Err(e) => {
            done(id, false);
            Err(bind_errno(e))
        }
    }
}

/// The thread `id` (handle `thread`) leaves the sporadic server: the
/// service gives the handle of its budget, the kernel takes the budget off
/// the thread, and the share goes back.
pub fn leave(id: u64, thread: &Handle<Thread>) -> Result<(), i32> {
    let w = request(proto::UNBIND, id, None)?;
    let mut reply = crate::process::send_again(&w).map_err(|_| EIO)?;
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let status = proto_wire::Reader::new(reply.bytes(&mut buffer))
        .u32()
        .map_err(|_| EIO)?;
    if status != 0 {
        return Err(errno_of(status));
    }
    let old = reply.handles.take::<Budget>(0).map_err(|_| EIO)?;
    match budget_call::unbind(thread, &old) {
        Ok(()) => {
            done(id, true);
            take(id as u32);
            Ok(())
        }
        Err(e) => {
            done(id, false);
            Err(bind_errno(e))
        }
    }
}

/// The calling thread's end: its budget goes back, if it has one.
pub fn release_own() {
    let id = crate::threads::thread_number();
    if get(id).is_some() {
        forget(id);
    }
}
