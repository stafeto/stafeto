// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C probe of the package service's place in a process (slot.c) on relibc: posix-crt starts
//! the layer, relibc starts C. The functions below give C the layer's `packages` session and
//! the requests it sends through it.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};
use posix_abi::packages;
use proto_pkg::{self as pkg, Method};
use proto_wire::{Reader, Status, Writer};
use rt::abi::{MESSAGE_MAX, Rights};
use rt::handle::{Channel, Handle};
use rt::sys;

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

/// 1 when the process has a session with the package service.
#[unsafe(no_mangle)]
pub extern "C" fn ps_session() -> i32 {
    i32::from(packages::session().is_some())
}

/// The status of a request sent through the process's session: 0 for OK, the code of the
/// service's refusal (1201 and up), minus 1 for a channel that failed or no session.
fn ask(request: &[u8], identity: bool) -> i32 {
    let Some(session) = packages::session() else {
        return -1;
    };
    let session = Handle::<Channel>::borrowed(session);
    let copy = identity
        .then(posix_abi::process::identity)
        .flatten()
        .and_then(|i| sys::handle_duplicate(i, Rights::NOTIFY | Rights::TRANSFER).ok());
    let reply = match copy {
        None => sys::send(&session, request),
        Some(h) => sys::send_handles(&session, request, [h.erase()]).map_err(|r| r.error),
    };
    let Ok(reply) = reply else {
        return -1;
    };
    let mut out = [0; MESSAGE_MAX];
    let bytes = reply.bytes(&mut out);
    match Reader::new(bytes).u32().map(Status::from_code) {
        Ok(Status::Ok) => 0,
        Ok(Status::Unknown(code)) => code as i32,
        _ => -1,
    }
}

/// LIST from the first entry: 0 when the service answers it, else the code.
#[unsafe(no_mangle)]
pub extern "C" fn ps_list() -> i32 {
    let mut w = Writer::new();
    if pkg::write_word(Method::List, 0, &mut w).is_err() {
        return -1;
    }
    ask(w.as_bytes(), false)
}

/// INSTALL_BEGIN of a record nobody has, with the process's identity session: 0 when the
/// service took it (the long operation is begun), 1201 (NOT_ALLOWED) for a process that is not
/// the superuser, another code for another refusal.
#[unsafe(no_mangle)]
pub extern "C" fn ps_begin() -> i32 {
    let mut w = Writer::new();
    let record = pkg::Begin {
        name: b"slot-probe",
        version: b"1",
        size: 4096,
        sha256: [7; 32],
        repository: b"stafeto",
        flags: 0,
    };
    if record.write(&mut w).is_err() {
        return -1;
    }
    // The reply of a request the service takes is a long operation's WAIT: status 0.
    ask(w.as_bytes(), true)
}

/// 0 when the process's session answers a CLONE with a session of its own (which this closes),
/// -1 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn ps_clone_ok() -> i32 {
    let Some(session) = packages::session() else {
        return -1;
    };
    match rt::service::clone_session(
        &Handle::<Channel>::borrowed(session),
        &Method::Clone.header().bytes(),
    ) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

static HIDDEN: AtomicU64 = AtomicU64::new(0);

/// Hides the session (1) or shows it again (0), for the forks and spawns between: the price of
/// the CLONE the layer makes with it.
#[unsafe(no_mangle)]
pub extern "C" fn ps_hide(hide: i32) {
    if hide != 0 {
        let raw = packages::probe_swap_session(0);
        if raw != 0 {
            HIDDEN.store(raw, Ordering::Release);
        }
    } else {
        let raw = HIDDEN.swap(0, Ordering::AcqRel);
        if raw != 0 {
            packages::probe_swap_session(raw);
        }
    }
}

/// The clock in nanoseconds.
#[unsafe(no_mangle)]
pub extern "C" fn ps_ns() -> u64 {
    rt::time::ticks_to_ns(rt::time::now())
}
