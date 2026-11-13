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
