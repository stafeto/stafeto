// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The measurement of the layered root on a machine (time.c) on relibc: posix-crt starts the layer
//! (with the layer service, feature `layer`), relibc starts C. The function below gives C the
//! count of the answers STARTING the process has had.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

/// The answers STARTING the layer service has given this process so far.
#[unsafe(no_mangle)]
pub extern "C" fn lt_starting() -> u32 {
    posix_abi::layer::starting_answers()
}
