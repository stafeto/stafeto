// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! A C main on relibc that sets threads and a child process under sporadic
//! servers and reads back what the layer, the process service and init
//! made of them (sporadic.c).

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

use proto_process::Method;
use proto_process::sporadic::{self as ss, Set};
use proto_wire::{Reader, Writer};
use rt::abi::Rights;

/// The reply of the process service to a request: its status, and for a
/// QUERY the mask.
fn ask(w: &Writer, handles: rt::handle::Outgoing, mask: Option<&mut u32>) -> u32 {
    let mut buffer = [0; rt::abi::MESSAGE_MAX];
    let session = posix_abi::process::client().session();
    let sent = if handles.is_empty() {
        rt::sys::send(session, w.as_bytes())
    } else {
        rt::sys::send_handles(session, w.as_bytes(), handles).map_err(|refused| refused.error)
    };
    match sent {
        Ok(reply) => read(reply, &mut buffer, mask),
        Err(_) => 9999,
    }
}

fn read(
    reply: rt::sys::Reply,
    buffer: &mut [u8; rt::abi::MESSAGE_MAX],
    mask: Option<&mut u32>,
) -> u32 {
    if !reply.handles.is_empty() {
        return 8888;
    }
    let mut r = Reader::new(reply.bytes(buffer));
    let Ok(status) = r.u32() else { return 9999 };
    if let (0, Some(mask)) = (status, mask) {
        let Ok(shares) = ss::Shares::read(&mut r) else {
            return 9999;
        };
        *mask = shares.mask;
    }
    status
}

/// SET with `flags`, naming the main thread with a handle (MANAGE): the
/// service's status.
#[unsafe(no_mangle)]
extern "C" fn sporadic_set(flags: u32) -> u32 {
    let Ok(thread) = rt::sys::handle_duplicate(&*posix_abi::threads::main_handle(), Rights::MANAGE)
    else {
        return 7777;
    };
    let mut w = Writer::new();
    let set = Set {
        thread: 1,
        cpu: 1,
        low: 3,
        max_repl: 4,
        flags,
        reserved: 0,
        c_ns: 1_000_000,
        t_ns: 10_000_000,
    };
    if Method::Budget.header().write(&mut w).is_err()
        || w.u32(ss::SET).is_err()
        || set.write(&mut w).is_err()
    {
        return 9999;
    }
    let mut handles = rt::handle::Outgoing::new();
    let _ = handles.push(thread.erase());
    ask(&w, handles, None)
}

/// QUERY: 0 and the mask of the CPUs with a share, or the status.
///
/// # Safety
/// `mask` is writable.
#[unsafe(no_mangle)]
unsafe extern "C" fn sporadic_query(mask: *mut u32) -> u32 {
    let mut w = Writer::new();
    if Method::Budget.header().write(&mut w).is_err() || w.u32(ss::QUERY).is_err() {
        return 9999;
    }
    let mut got = 99;
    let status = ask(&w, rt::handle::Outgoing::new(), Some(&mut got));
    // SAFETY: the caller's promise.
    unsafe { mask.write(got) };
    status
}

/// WORK, an operation of the service's own threads, through a session.
#[unsafe(no_mangle)]
extern "C" fn sporadic_work() -> u32 {
    let mut w = Writer::new();
    let work = ss::Work {
        seq: 0,
        status: 0,
        id: 0,
        flags: 0,
        reserved: 0,
    };
    if Method::Budget.header().write(&mut w).is_err()
        || w.u32(ss::WORK).is_err()
        || work.write(&mut w).is_err()
    {
        return 9999;
    }
    ask(&w, rt::handle::Outgoing::new(), None)
}
