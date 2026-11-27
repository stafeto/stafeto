// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C probe of the POSIX layer on the layered root (layer.c) on relibc: posix-crt starts the
//! layer (with the layer service, feature `layer`), relibc starts C. The functions below give C the
//! layer's session with the layer service.

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

/// 1 when the process has a session with the layer service (one taken, or one that came in the
/// slot), 0 when it has none yet.
#[unsafe(no_mangle)]
pub extern "C" fn lp_session() -> i32 {
    i32::from(posix_abi::layer::session().is_some())
}
