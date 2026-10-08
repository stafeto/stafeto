// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calls of upcalls (spec 11): thread_upcall_bind, thread_upcall_control, thread_upcall_request and thread_upcall_return.

use super::{Args, Values, cause, lookup, set_result};
use crate::object::Object;
use crate::sched;
use crate::thread::{self, Thread};
use abi::{Error, Rights, UpcallControl};
use core::ptr::NonNull;

pub(super) fn thread_upcall_bind(mut thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    if thread::buffer_page(thread).is_none() {
        return Err(Error::BadState);
    }
    // SAFETY: only the current thread configures its own entry under kernel serialization.
    unsafe { thread.as_mut() }.upcall.bind(a[0])?;
    Ok(Values::none())
}
/// One parse of x0: the numbers 5 to 12 left in epoch 2 and are INVALID_ARGS
/// like any other unknown one (spec 11).
pub(super) fn thread_upcall_control(
    mut thread: NonNull<Thread>,
    a: &Args,
) -> Result<Values, Error> {
    let operation = UpcallControl::from_raw(a[0]).ok_or(Error::InvalidArgs)?;
    // SAFETY: only current-thread state changes; no user pointers are accessed.
    let (was, pc, flags) = unsafe { thread.as_mut() }.upcall.control(operation)?;
    Ok(Values::new(&[was, pc, flags]))
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
