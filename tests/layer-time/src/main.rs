// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The measurement of the layered root on a machine (time.c) on relibc: posix-crt starts the layer
//! (with the layer service, feature `layer`), relibc starts C. The functions below give C the
//! counts of the calls that take the process's place with the layer service and of the answers
//! STARTING it has had.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

/// The calls of TakeRoot, SESSION and BIND this process has made, one function for each.
#[unsafe(no_mangle)]
pub extern "C" fn lt_take_roots() -> u32 {
    posix_abi::layer::taken().0
}

#[unsafe(no_mangle)]
pub extern "C" fn lt_sessions() -> u32 {
    posix_abi::layer::taken().1
}

#[unsafe(no_mangle)]
pub extern "C" fn lt_binds() -> u32 {
    posix_abi::layer::taken().2
}

/// The answers STARTING the layer service has given this process so far.
#[unsafe(no_mangle)]
pub extern "C" fn lt_starting() -> u32 {
    posix_abi::layer::starting_answers()
}
