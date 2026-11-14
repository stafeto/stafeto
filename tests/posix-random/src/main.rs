// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C probe of the source of entropy (random.c) on relibc: posix-crt
//! starts the layer, relibc starts C.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

/// Drops the process's session with the entropy service, as if the service
/// had gone: the generator of a program that started with AT_RANDOM has no
/// key yet, so it then has no source.
#[unsafe(no_mangle)]
pub extern "C" fn random_probe_drop_session() {
    // SAFETY: the C probe calls it on its only thread, before it asks the
    // generator for a byte.
    unsafe { posix_abi::random::init(None) };
}

/// The existing process counter, for bounded waits in the C probe.
#[unsafe(no_mangle)]
pub extern "C" fn random_probe_calls() -> u64 {
    rt::sys::calls()
}

/// Ends the entropy service's instance: CRASH through the process's session
/// (the service of this image is built with it), which has no reply. Init
/// starts the service again.
#[unsafe(no_mangle)]
pub extern "C" fn random_probe_crash() -> i32 {
    let Some(session) = posix_abi::random::session() else {
        return -1;
    };
    let _ = rt::sys::send(
        &rt::handle::Handle::<rt::handle::Channel>::borrowed(session),
        &proto_entropy::Method::Crash.header().bytes(),
    );
    0
}

/// 1 when the process's session with the entropy service is open (a session
/// of a live instance), 0 when it is closed or there is none.
#[unsafe(no_mangle)]
pub extern "C" fn random_probe_session_open() -> i32 {
    let Some(session) = posix_abi::random::session() else {
        return 0;
    };
    let open = rt::sys::channel_info(&rt::handle::Handle::<rt::handle::Channel>::borrowed(
        session,
    ))
    .is_ok_and(|info| !info.closed);
    i32::from(open)
}

/// One EntropyRejoin request of the process service, a call that bypasses the
/// layer (the layer asks for itself when it finds its session closed): 0 for
/// a new session (which closes at once), 501 PERMISSION, 506 AGAIN, 1000 the
/// limit of the generation's sessions, -1 for anything else.
#[unsafe(no_mangle)]
pub extern "C" fn random_probe_rejoin() -> i32 {
    let Some(client) = posix_abi::process::try_client() else {
        return -1;
    };
    match client.entropy_rejoin() {
        Ok(_session) => 0,
        Err(proto_wire::Status::Kernel(rt::abi::Error::LimitReached)) => 1000,
        Err(status) if status == proto_wire::Status::from_code(proto_process::PERMISSION) => {
            i32::try_from(proto_process::PERMISSION).unwrap_or(-1)
        }
        Err(status) if status == proto_wire::Status::from_code(proto_process::AGAIN) => {
            i32::try_from(proto_process::AGAIN).unwrap_or(-1)
        }
        Err(_) => -1,
    }
}
