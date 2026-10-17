// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calls of upcalls (spec 11): thread_upcall_bind, thread_upcall_control, thread_upcall_request and thread_upcall_return.

use super::{Args, Values, cause, lookup, set_result};
use crate::object::Object;
use crate::sched;
use crate::thread::{self, Thread};
use abi::{Error, Rights, UpcallControl};
use core::ptr::NonNull;

#[inline(never)]
pub(super) fn thread_upcall_bind(mut thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    if thread::buffer_page(thread).is_none() {
        return Err(Error::BadState);
    }
    // SAFETY: only the current thread configures its own entry, under the
    // OBJ, which a request from another core takes too.
    let upcall = &mut unsafe { thread.as_mut() }.upcall;
    locked_bind(upcall, a[0])?;
    Ok(Values::none())
}
/// One parse of x0: the numbers 5 to 12 left in epoch 2 and are INVALID_ARGS
/// like any other unknown one (spec 11). The five that need no argument are
/// the path of every entry (S5 counts its instructions) and stay in this
/// function; the others (13 to 16, with x1 and x2) go to a call of their own.
#[inline(never)]
pub(super) fn thread_upcall_control(
    mut thread: NonNull<Thread>,
    a: &Args,
) -> Result<Values, Error> {
    if a[0] > UpcallControl::Resume.raw() {
        return thread_upcall_control_more(thread, a);
    }
    let operation = UpcallControl::from_raw(a[0]).ok_or(Error::InvalidArgs)?;
    // SAFETY: only current-thread state changes, under the scheduler's
    // lock; no user pointers are accessed.
    let upcall = &mut unsafe { thread.as_mut() }.upcall;
    if operation == UpcallControl::Take {
        return Ok(Values::new(&locked_take(upcall)?));
    }
    let reply = locked_basic(upcall, operation)?;
    Ok(Values::of_five(reply.words(), reply.len()))
}
#[inline(never)]
fn thread_upcall_control_more(mut thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let operation = UpcallControl::from_raw(a[0]).ok_or(Error::InvalidArgs)?;
    // SAFETY: as above.
    let upcall = &mut unsafe { thread.as_mut() }.upcall;
    let reply = locked_control(upcall, operation, a[1], a[2])?;
    Ok(Values::of_five(reply.words(), reply.len()))
}
pub(super) fn thread_upcall_request(thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    let target = lookup(thread, a[0], Rights::MANAGE, Object::thread)?;
    // SAFETY: the caller's handle holds the target through the request.
    unsafe { sched::request_upcall(target, cause(thread)) }?;
    Ok(Values::none())
}

/// Restore from a fixed area of the held buffer, never from an arbitrary user pointer.
/// Validate before changing any context; successful restore has no usual x0 result.
pub(super) fn thread_upcall_return(thread: NonNull<Thread>) {
    if let Err(error) = thread::restore_upcall(thread) {
        set_result(thread, Err(error));
    }
}

// The entry's state is the thread's own: only the CPU that runs the thread
// changes it, without a lock. A request from another CPU reaches the state
// by a command that the owner executes (SMP stage 4); `pending` is the one
// field another CPU reads. Each change is in a function of its own, which
// keeps its code off the path of the other calls.
#[inline(never)]
fn locked_bind(upcall: &mut kcore::upcall::State, entry: u64) -> Result<(), Error> {
    upcall.bind(entry)
}
#[inline(never)]
fn locked_take(upcall: &mut kcore::upcall::State) -> Result<[u64; 4], Error> {
    upcall.take()
}
#[inline(never)]
fn locked_basic(
    upcall: &mut kcore::upcall::State,
    operation: UpcallControl,
) -> Result<kcore::upcall::Reply, Error> {
    upcall.control_basic(operation)
}
#[inline(never)]
fn locked_control(
    upcall: &mut kcore::upcall::State,
    operation: UpcallControl,
    x1: u64,
    x2: u64,
) -> Result<kcore::upcall::Reply, Error> {
    upcall.control(operation, x1, x2)
}
