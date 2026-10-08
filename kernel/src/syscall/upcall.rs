// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The calls of upcalls (spec 11): thread_upcall_bind, thread_upcall_control, thread_upcall_request and thread_upcall_return.

use super::{Args, Values, cause, lookup, set_result};
use crate::object::Object;
use crate::sched;
use crate::thread::{self, Thread};
use abi::{Error, Rights};
use core::ptr::NonNull;

pub(super) fn thread_upcall_bind(mut thread: NonNull<Thread>, a: &Args) -> Result<Values, Error> {
    if thread::buffer_page(thread).is_none() {
        return Err(Error::BadState);
    }
    // SAFETY: only the current thread configures its own entry under kernel serialization.
    unsafe { thread.as_mut() }.upcall.bind(a[0])?;
    Ok(Values::none())
}
pub(super) fn thread_upcall_control(
    mut thread: NonNull<Thread>,
    a: &Args,
) -> Result<Values, Error> {
    // Resolve a target before mutably borrowing current-thread entry state.
    // The target may be the caller itself.
    if a[0] == abi::UpcallControl::LayerRequest.raw() {
        let target = lookup(thread, a[1], Rights::MANAGE, Object::thread)?;
        // SAFETY: the caller's capability retains this exact target.
        unsafe { sched::request_layer_upcall(target, cause(thread)) }?;
        return Ok(Values::none());
    }
    if a[0] == abi::UpcallControl::ObserverBind.raw() {
        if thread::buffer_page(thread).is_none() {
            return Err(Error::BadState);
        }
        // SAFETY: current-thread configuration is serialized by the kernel.
        unsafe { thread.as_mut() }
            .upcall
            .bind_observer(a[1], a[2])?;
        return Ok(Values::none());
    }
    // SAFETY: only current-thread state changes; no user pointers are accessed.
    let (was, pc, flags) = unsafe { thread.as_mut() }.upcall.control(a[0])?;
    if a[0] == abi::UpcallControl::ObserverTake.raw() {
        // SAFETY: the current entry has taken its snapshot before new delivery.
        let tls = unsafe { thread.as_ref() }.upcall.interrupted_tls();
        Ok(Values::new(&[was, pc, flags, tls]))
    } else {
        Ok(Values::new(&[was, pc, flags]))
    }
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
